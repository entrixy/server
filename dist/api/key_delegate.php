<?php
/**
 * Passing a key on. The holder does NOT issue a key and does NOT learn anyone
 * else's secret: they hand out a link, and the secret is born on the
 * recipient's device when the link is opened.
 *
 * One link may carry objects from several keys the holder has on this server —
 * keys from different owners. A key row belongs to one owner (commands go
 * through their phone, they assemble the bundle, depth and revocation count
 * from the parent), so the link is a group of parts, one per parent key, tied
 * together by `grp`. The recipient sees one key; each owner sees their part.
 *
 *   a=create  (holder)  add a part to a link, or start a new link
 *   a=info    (any)     what a link offers
 *   a=redeem  (any)     accept: the recipient's device sends a key per part
 *   a=cancel  (holder)  withdraw a part nobody has accepted yet
 *   a=list    (holder)  one's parts and the keys issued through them
 *   a=edit    (holder)  change the objects of a key one passed on
 *   a=revoke  (holder)  revoke a key one passed on, with everything below it
 *   a=message (holder)  a message to the recipient, readable by them only
 *
 * A child key is an ordinary row on the OWNER's object: only the owner's device
 * can assemble its bundle, so after acceptance or an edit the key waits for the
 * owner to come online.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/guest_auth.php';
require_once __DIR__ . '/../lib/account.php';
require_once __DIR__ . '/../lib/key_tree.php';
require_once __DIR__ . '/../lib/fcm.php';

const DELEGATE_MAX_CHILDREN = 5;    // how many children one key may have
const DELEGATE_INVITE_HOURS = 72;   // how long a link lives

$action = (string)($_GET['a'] ?? '');
$j = jin();

/** The holder, by their key plus the device fingerprint bound to it. */
function guest_key_auth(array $j): array {
    $fp = (string)($j['device_fp'] ?? '');
    // The holder proves the right by signature; the server never sees the key.
    $who = guest_auth($j, 'key_delegate', file_get_contents('php://input'));
    if (!$who) jout(['error' => 'auth'], 401);
    $st = db()->prepare(
        'SELECT id, host_id, enabled, mode, delegate_depth, expires_at, bound_device_fp, org_id
         FROM user_keys WHERE id = ? LIMIT 1'
    );
    $st->execute([(int)$who['id']]);
    $k = $st->fetch(PDO::FETCH_ASSOC);
    if (!$k || !(int)$k['enabled']) jout(['error' => 'auth'], 401);
    if (($k['mode'] ?? 'auto') === 'off') jout(['error' => 'revoked'], 403);
    if ($k['expires_at'] && strtotime($k['expires_at']) < time()) jout(['error' => 'expired'], 403);
    if ($k['bound_device_fp'] && (!$fp || !hash_equals($k['bound_device_fp'], $fp))) {
        jout(['error' => 'already_bound'], 403);
    }
    $k['fp'] = $fp;
    return $k;
}

function key_numbers(int $keyId): array {
    $st = db()->prepare('SELECT number_id FROM key_numbers WHERE user_key_id = ?');
    $st->execute([$keyId]);
    return array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
}

/** A list of positive ids out of whatever arrived. */
function int_ids($v): array {
    $out = [];
    foreach ((array)$v as $x) { $x = (int)$x; if ($x > 0) $out[$x] = $x; }
    return array_values($out);
}

function csv_ids(?string $s): array {
    return $s === null || $s === '' ? [] : array_map('intval', explode(',', $s));
}

function new_code(): string {
    return substr(rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='), 0, 22);
}

/** A child of $parentId, or a refusal: a holder touches only what they passed on. */
function own_child(int $parentId, int $childId): array {
    $st = db()->prepare('SELECT * FROM user_keys WHERE id = ? AND parent_key_id = ?');
    $st->execute([$childId, $parentId]);
    $c = $st->fetch(PDO::FETCH_ASSOC);
    if (!$c) jout(['error' => 'not_found'], 404);
    return $c;
}

/** Ask the owner to assemble the child's bundle, and tell them about it. */
function ask_owner(int $hostId, int $childId, int $parentId, array $numbers, array $bles): void {
    db()->prepare(
        'INSERT INTO pending_host_msgs (host_id, payload, created_at, dedup_key) VALUES (?,?,NOW(),?)
         ON DUPLICATE KEY UPDATE payload = VALUES(payload), created_at = NOW()'
    )->execute([$hostId,
        json_encode(['type' => 'bundle_request', 'key_id' => $childId,
                     'parent_key_id' => $parentId,
                     'number_ids' => $numbers, 'ble_ids' => $bles]),
        'bundle_req_' . $childId]);
    db()->prepare('INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?,?,NOW())')
        ->execute(['key_delegated', $childId]);
}

// ── Add a part to a link ───────────────────────────────────────────────────────
if ($action === 'create') {
    $k = guest_key_auth($j);
    rate_limit_check('key_delegate', 30);
    if (!empty($k['org_id'])) jout(['error' => 'org_key'], 403);
    $depth = (int)$k['delegate_depth'];
    if ($depth < 1) jout(['error' => 'not_allowed'], 403);

    // Children count against the parent's own allowance: a guest must not eat up
    // the owner's whole supply of keys.
    $cnt = db()->prepare('SELECT COUNT(*) FROM user_keys WHERE parent_key_id = ?');
    $cnt->execute([(int)$k['id']]);
    if ((int)$cnt->fetchColumn() >= DELEGATE_MAX_CHILDREN) {
        jout(['error' => 'children_limit', 'limit' => DELEGATE_MAX_CHILDREN], 403);
    }
    // And against the owner's overall limit — the key is theirs after all.
    $max = account_limits((int)$k['host_id'])['max_keys'];
    $have = db()->prepare('SELECT COUNT(*) FROM user_keys WHERE host_id = ? AND enabled = 1');
    $have->execute([(int)$k['host_id']]);
    if ((int)$have->fetchColumn() >= $max) jout(['error' => 'owner_limit_reached'], 403);

    // Objects: only those the holder has. Bluetooth locks are not listed on
    // the server; the owner checks them when assembling the bundle.
    $ids  = array_values(array_intersect(int_ids($j['number_ids'] ?? []), key_numbers((int)$k['id'])));
    $bles = int_ids($j['ble_ids'] ?? []);
    if (!$ids && !$bles) jout(['error' => 'bad_numbers'], 400);

    $hours = (int)($j['ttl_hours'] ?? DELEGATE_INVITE_HOURS);
    if ($hours < 1 || $hours > 720) $hours = DELEGATE_INVITE_HOURS;
    $welcome = (string)($j['welcome_cipher'] ?? '');
    if ($welcome !== '' && (strlen($welcome) > 4096 || !is_valid_cipher($welcome))) {
        jout(['error' => 'invalid_cipher_format'], 400);
    }

    // A part joins an existing link only from the handset that started it.
    $grp = (string)($j['grp'] ?? '');
    $redeemed = false;
    if ($grp !== '') {
        $g = db()->prepare('SELECT creator_fp, status FROM key_invites WHERE grp = ?');
        $g->execute([$grp]);
        $rows = $g->fetchAll(PDO::FETCH_ASSOC);
        if (!$rows) jout(['error' => 'not_found'], 404);
        foreach ($rows as $r) {
            if (!$k['fp'] || !hash_equals((string)$r['creator_fp'], $k['fp'])) jout(['error' => 'not_yours'], 403);
            if ($r['status'] === 'redeemed') $redeemed = true;
        }
    } else {
        $grp = new_code();
    }

    // One part per parent key within a link: a second call replaces the objects.
    $ex = db()->prepare('SELECT id, code FROM key_invites WHERE grp = ? AND parent_key_id = ? AND status = "new"');
    $ex->execute([$grp, (int)$k['id']]);
    if ($row = $ex->fetch(PDO::FETCH_ASSOC)) {
        db()->prepare('UPDATE key_invites SET number_ids = ?, ble_ids = ?, depth = ?,
                              expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR) WHERE id = ?')
            ->execute([implode(',', $ids), implode(',', $bles), $depth - 1, $hours, (int)$row['id']]);
        $code = $row['code'];
    } else {
        $code = null;
        for ($try = 0; $try < 5 && $code === null; $try++) {
            $c = new_code();
            try {
                db()->prepare(
                    'INSERT INTO key_invites (host_id, parent_key_id, code, grp, creator_fp, number_ids, ble_ids,
                                              welcome_cipher, depth, expires_at, created_at)
                     VALUES (?,?,?,?,?,?,?,?,?, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())'
                )->execute([(int)$k['host_id'], (int)$k['id'], $c, $grp, $k['fp'] ?: null,
                            implode(',', $ids), implode(',', $bles), $welcome ?: null, $depth - 1, $hours]);
                $code = $c;
            } catch (\Throwable $e) { /* code collision */ }
        }
        if ($code === null) jout(['error' => 'try_later'], 503);
    }

    // The link was already accepted: the recipient's handset picks the new part
    // up by itself. A push saves the wait until its next start.
    if ($redeemed) {
        $h = db()->prepare('SELECT key_hash FROM user_keys WHERE share_grp = ?');
        $h->execute([$grp]);
        foreach ($h->fetchAll(PDO::FETCH_COLUMN) as $hash) {
            fcm_send_to_topic("k_{$hash}", ['type' => 'share_part', 'hash' => $hash, 'grp' => $grp]);
        }
    }

    jout(['code' => $code, 'grp' => $grp, 'url' => site_url('/i/' . $grp),
          'objects' => count($ids) + count($bles), 'depth' => $depth - 1, 'expires_in_hours' => $hours]);
}

// ── What a link offers ──────────────────────────────────────────────────────────
if ($action === 'info') {
    $grp = (string)($_GET['code'] ?? ($j['code'] ?? ($j['grp'] ?? '')));
    if ($grp === '') jout(['error' => 'bad_input'], 400);
    rate_limit_check('key_invite_info', 60);
    $st = db()->prepare('SELECT * FROM key_invites WHERE grp = ? ORDER BY id');
    $st->execute([$grp]);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    if (!$rows) jout(['error' => 'not_found'], 404);
    $parts = [];
    $welcome = null;
    $open = 0;
    foreach ($rows as $inv) {
        $state = $inv['status'];
        if ($state === 'new' && strtotime($inv['expires_at']) < time()) $state = 'expired';
        if ($state === 'new') $open++;
        if ($welcome === null && $inv['welcome_cipher']) $welcome = $inv['welcome_cipher'];
        $parts[] = ['code' => $inv['code'], 'state' => $state,
                    'objects' => count(csv_ids($inv['number_ids'])) + count(csv_ids($inv['ble_ids'])),
                    'depth' => (int)$inv['depth']];
    }
    jout(['grp' => $grp, 'state' => $open ? 'new' : $parts[0]['state'], 'parts' => $parts,
          'welcome_cipher' => $welcome]);
}

// ── Accept: the recipient's device generates a key per part ─────────────────────
if ($action === 'redeem') {
    $grp = (string)($j['grp'] ?? '');
    // One encryption pair for the whole key: every owner seals their bundle key
    // with its public half, so neither the server nor the holder can read them.
    $guest_pub = (string)($j['guest_pub'] ?? '');
    $parts_in = is_array($j['parts'] ?? null) ? $j['parts'] : [];
    if ($grp === '' || !$parts_in) jout(['error' => 'bad_input'], 400);
    if (!preg_match('/^[A-Za-z0-9_-]{40,120}$/', $guest_pub)) jout(['error' => 'bad_pubkey'], 400);
    require_once __DIR__ . '/../lib/suites.php';
    $suite = (string)($j['suite'] ?? ENTRIXY_SUITE_PREFERRED);
    if (!suite_known($suite)) jout(['error' => 'unsupported_suite', 'suites' => suite_list()], 400);
    rate_limit_check('key_invite_redeem', 20);

    $st  = db()->prepare('SELECT * FROM key_invites WHERE code = ? AND grp = ? FOR UPDATE');
    $par = db()->prepare('SELECT id, enabled, mode, expires_at, native_only FROM user_keys WHERE id = ?');
    $chk = db()->prepare('SELECT id FROM user_keys WHERE key_hash = ?');
    $out = [];
    db()->beginTransaction();
    foreach ($parts_in as $p) {
        $code = (string)($p['code'] ?? '');
        // The recipient creates each key on their own device and sends only its
        // fingerprint and the public half of its signing pair.
        $key_hash = strtolower(trim((string)($p['key_hash'] ?? '')));
        $sign_pub = base64_decode(strtr((string)($p['sign_pub'] ?? ''), '-_', '+/'), true);
        if (!preg_match('/^[a-f0-9]{64}$/', $key_hash) || $sign_pub === false || strlen($sign_pub) !== 32) {
            $out[] = ['code' => $code, 'error' => 'bad_input']; continue;
        }
        $st->execute([$code, $grp]);
        $inv = $st->fetch(PDO::FETCH_ASSOC);
        if (!$inv || $inv['status'] !== 'new') { $out[] = ['code' => $code, 'error' => 'not_found']; continue; }
        if (strtotime($inv['expires_at']) < time()) {
            db()->prepare('UPDATE key_invites SET status = "expired" WHERE id = ?')->execute([(int)$inv['id']]);
            $out[] = ['code' => $code, 'error' => 'expired']; continue;
        }
        // Is the parent still alive?
        $par->execute([(int)$inv['parent_key_id']]);
        $pk = $par->fetch(PDO::FETCH_ASSOC);
        if (!$pk || !(int)$pk['enabled'] || ($pk['mode'] ?? 'auto') === 'off'
            || ($pk['expires_at'] && strtotime($pk['expires_at']) < time())) {
            $out[] = ['code' => $code, 'error' => 'parent_revoked']; continue;
        }
        $chk->execute([$key_hash]);
        if ($chk->fetch()) { $out[] = ['code' => $code, 'error' => 'user_key_collision']; continue; }

        // The child key is enabled but carries NO bundle: until the owner
        // assembles one it opens nothing. Lifetime and the "app only" mode are
        // inherited from the parent: nobody can pass on more than they hold.
        db()->prepare(
            'INSERT INTO user_keys (host_id, parent_key_id, share_grp, ble_ids, delegate_depth, guest_pub, key_hash,
                                    sign_pub, sign_suite, enabled, mode, native_only, expires_at, created_at)
             VALUES (?,?,?,?,?,?,?,?,?,1,"auto",?,?,NOW())'
        )->execute([(int)$inv['host_id'], (int)$inv['parent_key_id'], $grp, $inv['ble_ids'] ?: null,
                    (int)$inv['depth'], $guest_pub, $key_hash, $sign_pub, $suite,
                    (int)$pk['native_only'], $pk['expires_at']]);
        $childId = (int)db()->lastInsertId();
        $ins = db()->prepare('INSERT INTO key_numbers (user_key_id, number_id) VALUES (?,?)');
        foreach (csv_ids($inv['number_ids']) as $nid) $ins->execute([$childId, $nid]);
        db()->prepare('UPDATE key_invites SET status="redeemed", child_key_id=?, redeemed_at=NOW() WHERE id=?')
            ->execute([$childId, (int)$inv['id']]);
        ask_owner((int)$inv['host_id'], $childId, (int)$inv['parent_key_id'],
                  csv_ids($inv['number_ids']), csv_ids($inv['ble_ids']));
        $out[] = ['code' => $code, 'id' => $childId, 'key_hash' => $key_hash];
    }
    db()->commit();

    $ok = array_filter($out, fn($o) => isset($o['id']));
    if (!$ok) {
        $err = $out[0]['error'] ?? 'not_found';
        jout(['error' => $err, 'parts' => $out], $err === 'expired' ? 410 : 404);
    }
    jout(['ok' => 1, 'parts' => $out, 'state' => 'awaiting_owner']);
}

// ── Withdraw a part nobody has accepted ─────────────────────────────────────────
if ($action === 'cancel') {
    $k = guest_key_auth($j);
    $code = (string)($j['code'] ?? '');
    $grp  = (string)($j['grp'] ?? '');
    db()->prepare('UPDATE key_invites SET status="cancelled"
                   WHERE (code = ? OR grp = ?) AND parent_key_id = ? AND status = "new"')
        ->execute([$code, $grp, (int)$k['id']]);
    jout(['ok' => 1]);
}

// ── One's parts and the keys issued through them ────────────────────────────────
if ($action === 'list') {
    $k = guest_key_auth($j);
    $st = db()->prepare(
        'SELECT code, grp, number_ids, ble_ids, depth, status, child_key_id, created_at, expires_at, redeemed_at
         FROM key_invites WHERE parent_key_id = ? ORDER BY id DESC LIMIT 50'
    );
    $st->execute([(int)$k['id']]);
    $inv = $st->fetchAll(PDO::FETCH_ASSOC);
    foreach ($inv as &$i) {
        if ($i['status'] === 'new' && strtotime($i['expires_at']) < time()) $i['status'] = 'expired';
        $i['number_ids'] = csv_ids($i['number_ids']);
        $i['ble_ids'] = csv_ids($i['ble_ids']);
    }
    unset($i);
    $ch = db()->prepare(
        'SELECT uk.id, uk.share_grp, uk.guest_pub, uk.ble_ids, uk.confirmed_ids, uk.bundle_dirty,
                (uk.bundle_cipher IS NOT NULL) AS has_bundle, uk.created_at,
                GROUP_CONCAT(kn.number_id) AS number_ids
         FROM user_keys uk LEFT JOIN key_numbers kn ON kn.user_key_id = uk.id
         WHERE uk.parent_key_id = ? GROUP BY uk.id ORDER BY uk.id DESC'
    );
    $ch->execute([(int)$k['id']]);
    $children = [];
    foreach ($ch->fetchAll(PDO::FETCH_ASSOC) as $c) {
        $children[] = [
            'id' => (int)$c['id'], 'grp' => $c['share_grp'], 'guest_pub' => $c['guest_pub'],
            'number_ids' => csv_ids($c['number_ids']), 'ble_ids' => csv_ids($c['ble_ids']),
            // What the current bundle covers: the rest waits for the owner.
            'confirmed_ids' => csv_ids($c['confirmed_ids']),
            'ready' => ((int)$c['has_bundle'] && !(int)$c['bundle_dirty']) ? 1 : 0,
            'created_at' => $c['created_at'],
        ];
    }
    jout(['depth' => (int)$k['delegate_depth'], 'invites' => $inv, 'children' => $children,
          'max_children' => DELEGATE_MAX_CHILDREN]);
}

// ── Change the objects of a key one passed on ───────────────────────────────────
if ($action === 'edit') {
    $k = guest_key_auth($j);
    rate_limit_check('key_delegate', 30);
    $c = own_child((int)$k['id'], (int)($j['child_id'] ?? 0));
    $ids  = array_values(array_intersect(int_ids($j['number_ids'] ?? []), key_numbers((int)$k['id'])));
    $bles = int_ids($j['ble_ids'] ?? []);
    // Nothing left: the part goes, together with whatever was passed on below it.
    if (!$ids && !$bles) {
        jout(['ok' => 1, 'revoked' => key_revoke_tree((int)$c['id'])]);
    }
    db()->prepare('DELETE FROM key_numbers WHERE user_key_id = ?')->execute([(int)$c['id']]);
    $ins = db()->prepare('INSERT INTO key_numbers (user_key_id, number_id) VALUES (?,?)');
    foreach ($ids as $nid) $ins->execute([(int)$c['id'], $nid]);
    // The current bundle stays in place: the recipient keeps opening what was
    // confirmed until the owner assembles the new one.
    db()->prepare('UPDATE user_keys SET ble_ids = ?, bundle_dirty = 1 WHERE id = ?')
        ->execute([$bles ? implode(',', $bles) : null, (int)$c['id']]);
    ask_owner((int)$c['host_id'], (int)$c['id'], (int)$k['id'], $ids, $bles);
    db()->prepare('INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?,?,NOW())')
        ->execute(['key_updated', (int)$c['id']]);
    jout(['ok' => 1]);
}

// ── Revoke a key one passed on ──────────────────────────────────────────────────
if ($action === 'revoke') {
    $k = guest_key_auth($j);
    $grp = (string)($j['grp'] ?? '');
    $revoked = [];
    if ((int)($j['child_id'] ?? 0) > 0) {
        $c = own_child((int)$k['id'], (int)$j['child_id']);
        $revoked = key_revoke_tree((int)$c['id']);
    } elseif ($grp !== '') {
        // The whole key: every part this parent holds in the link, accepted or not.
        $st = db()->prepare('SELECT id FROM user_keys WHERE parent_key_id = ? AND share_grp = ?');
        $st->execute([(int)$k['id'], $grp]);
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $cid) {
            $revoked = array_merge($revoked, key_revoke_tree((int)$cid));
        }
        db()->prepare('UPDATE key_invites SET status="cancelled" WHERE grp = ? AND parent_key_id = ? AND status = "new"')
            ->execute([$grp, (int)$k['id']]);
    } else {
        jout(['error' => 'bad_input'], 400);
    }
    jout(['ok' => 1, 'revoked' => $revoked]);
}

// ── A message to the recipient ──────────────────────────────────────────────────
if ($action === 'message') {
    $k = guest_key_auth($j);
    rate_limit_check('message_send', 60);
    $grp = (string)($j['grp'] ?? '');
    $cipher = (string)($j['cipher'] ?? '');
    if ($grp === '' || $cipher === '') jout(['error' => 'bad_input'], 400);
    if (strlen($cipher) > 4096) jout(['error' => 'too_long'], 400);
    // Sealed with the recipient's public key: the server passes a blob along.
    if (!preg_match('/^[A-Za-z0-9_.:|-]{1,4096}$/', $cipher)) jout(['error' => 'invalid_cipher_format'], 400);
    $st = db()->prepare('SELECT id, host_id, key_hash FROM user_keys
                         WHERE parent_key_id = ? AND share_grp = ? ORDER BY id LIMIT 1');
    $st->execute([(int)$k['id'], $grp]);
    $c = $st->fetch(PDO::FETCH_ASSOC);
    if (!$c) jout(['error' => 'not_found'], 404);
    // One recipient key is enough: their handset holds every part of the link.
    db()->prepare(
        'INSERT INTO guest_messages (host_id, user_key_id, cipher) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE cipher = VALUES(cipher), created_at = CURRENT_TIMESTAMP'
    )->execute([(int)$c['host_id'], (int)$c['id'], $cipher]);
    $ok = fcm_send_to_topic("k_{$c['key_hash']}", [
        'type' => 'share_message', 'hash' => $c['key_hash'], 'grp' => $grp, 'cipher' => $cipher,
    ]);
    jout(['ok' => true, 'fcm' => $ok]);
}

jout(['error' => 'unknown_action'], 400);
