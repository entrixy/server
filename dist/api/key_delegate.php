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
require_once __DIR__ . '/../lib/key_objects.php';
require_once __DIR__ . '/../lib/fcm.php';

const DELEGATE_INVITE_HOURS = 168; // a link nobody has opened lives a week; an opened one
                                    // reopens on its handset for as long as the key lives

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

/**
 * What the holder passes on and with what settings. Each object is checked
 * against the holder's own key: it must be there, allowed further down
 * (levels left) and still have keys to spare in the chain above. Levels and
 * the number of keys for the recipient stay within what came from above; "app
 * only" is inherited. Returns id → [n, d, p]; objects that may not be passed
 * are dropped.
 */
function pass_objects(array $k, array $j, ?int $skipChild = null, ?int $skipInvite = null, array $keep = []): array {
    $mine = key_obj_read((int)$k['id']);
    $req = [];
    foreach ((array)($j['objects'] ?? []) as $o) {
        if (is_array($o) && (int)($o['id'] ?? 0) > 0) $req[(int)$o['id']] = $o;
    }
    foreach (array_merge(int_ids($j['number_ids'] ?? []), int_ids($j['ble_ids'] ?? [])) as $id) {
        if (!isset($req[$id])) $req[$id] = ['id' => $id];
    }
    $out = [];
    foreach ($req as $id => $o) {
        $m = $mine[$id] ?? null;
        if (!$m || $m['d'] < 1) continue;
        // Already in the recipient's key: keeps its settings and its place.
        if (isset($keep[$id]) && !array_key_exists('depth', $o) && !array_key_exists('pool', $o)) {
            $out[$id] = $keep[$id]; continue;
        }
        // The recipient's own key is left out of the count ($skipChild), so
        // an object it already holds is weighed as if placed anew.
        $left = key_pool_left((int)$k['id'], $id, $skipChild, $skipInvite);
        if ($left < 1) continue;
        $maxD = $m['d'] - 1;
        $maxP = max(1, $left - 1);   // the recipient's own key takes one place
        $out[$id] = [
            'n' => $m['n'],
            'd' => max(0, min($maxD, (int)($o['depth'] ?? $maxD))),
            'p' => max(1, min($maxP, (int)($o['pool'] ?? min(KEY_OBJ_DEFAULTS['p'], $maxP)))),
        ];
    }
    return $out;
}

/** Numbers and Bluetooth locks of a set of objects, apart. */
function split_types(array $ids): array {
    if (!$ids) return [[], []];
    $in = implode(',', array_map('intval', $ids));
    $nums = []; $bles = [];
    foreach (db()->query("SELECT id, type FROM numbers WHERE id IN ($in)")->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if ($r['type'] === 'ble') $bles[] = (int)$r['id']; else $nums[] = (int)$r['id'];
    }
    return [$nums, $bles];
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

    // Against the owner's overall limit — the key is theirs after all. How
    // many keys the chain may issue is counted per object, below.
    $max = account_limits((int)$k['host_id'])['max_keys'];
    $have = db()->prepare('SELECT COUNT(*) FROM user_keys WHERE host_id = ? AND enabled = 1');
    $have->execute([(int)$k['host_id']]);
    if ((int)$have->fetchColumn() >= $max) jout(['error' => 'owner_limit_reached'], 403);

    // Objects and their settings; the chain may have run out of keys for some.
    $grp0 = (string)($j['grp'] ?? '');
    $prev = null;
    if ($grp0 !== '') {
        $pv = db()->prepare('SELECT id FROM key_invites WHERE grp = ? AND parent_key_id = ? AND status = "new"');
        $pv->execute([$grp0, (int)$k['id']]);
        $prev = (int)$pv->fetchColumn() ?: null;
    }
    $sets = pass_objects($k, $j, null, $prev);
    if (!$sets) {
        // Why nothing is left: the objects are not the holder's, may not be
        // passed on, or the chain has run out of keys for them.
        $mine = key_obj_read((int)$k['id']);
        $asked = array_merge(array_map(fn($o) => (int)($o['id'] ?? 0), (array)($j['objects'] ?? [])),
                             int_ids($j['number_ids'] ?? []), int_ids($j['ble_ids'] ?? []));
        $held = array_filter($asked, fn($id) => isset($mine[$id]));
        $err = !$held ? 'bad_numbers'
             : (!array_filter($held, fn($id) => $mine[$id]['d'] >= 1) ? 'not_allowed' : 'pool_exhausted');
        jout(['error' => $err], $err === 'bad_numbers' ? 400 : 403);
    }
    [$ids, $bles] = split_types(array_keys($sets));
    $objJson = json_encode(array_map(fn($id) => ['id' => $id] + $sets[$id], array_keys($sets)));
    $partDepth = max(array_column($sets, 'd'));

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
        db()->prepare('UPDATE key_invites SET number_ids = ?, ble_ids = ?, objects = ?, depth = ?,
                              expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR) WHERE id = ?')
            ->execute([implode(',', $ids), implode(',', $bles), $objJson, $partDepth, $hours, (int)$row['id']]);
        $code = $row['code'];
    } else {
        $code = null;
        for ($try = 0; $try < 5 && $code === null; $try++) {
            $c = new_code();
            try {
                db()->prepare(
                    'INSERT INTO key_invites (host_id, parent_key_id, code, grp, creator_fp, number_ids, ble_ids,
                                              objects, welcome_cipher, depth, expires_at, created_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())'
                )->execute([(int)$k['host_id'], (int)$k['id'], $c, $grp, $k['fp'] ?: null,
                            implode(',', $ids), implode(',', $bles), $objJson, $welcome ?: null, $partDepth, $hours]);
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
          'objects' => count($ids) + count($bles), 'depth' => $partDepth]);
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
    // The link lives until the one who passed it deletes it. An accepted part
    // whose key is still alive can be opened again on the same handset.
    $alive = db()->prepare('SELECT 1 FROM user_keys WHERE id = ?');
    foreach ($rows as $inv) {
        $state = $inv['status'];
        if ($state === 'redeemed') {
            $alive->execute([(int)$inv['child_key_id']]);
            if (!$alive->fetchColumn()) $state = 'cancelled';
        } elseif ($state === 'new' && strtotime($inv['expires_at']) < time()) {
            $state = 'expired';
        }
        if ($state === 'new' || $state === 'redeemed') $open++;
        if ($welcome === null && $inv['welcome_cipher']) $welcome = $inv['welcome_cipher'];
        $parts[] = ['code' => $inv['code'], 'state' => $state,
                    'objects' => count(csv_ids($inv['number_ids'])) + count(csv_ids($inv['ble_ids'])),
                    'depth' => (int)$inv['depth']];
    }
    jout(['grp' => $grp, 'state' => $open ? 'new' : 'cancelled', 'parts' => $parts,
          'welcome_cipher' => $welcome]);
}

// ── Accept: the recipient's device generates a key per part ─────────────────────
if ($action === 'redeem') {
    $grp = (string)($j['grp'] ?? '');
    // One encryption pair for the whole key: every owner seals their bundle key
    // with its public half, so neither the server nor the holder can read them.
    $guest_pub = (string)($j['guest_pub'] ?? '');
    // The handset opening the link: an accepted part moves to a new key only
    // on the handset it was bound to.
    $fp = (string)($j['device_fp'] ?? '');
    $parts_in = is_array($j['parts'] ?? null) ? $j['parts'] : [];
    if ($grp === '' || !$parts_in) jout(['error' => 'bad_input'], 400);
    if (!preg_match('/^[A-Za-z0-9_-]{40,200}$/', $guest_pub)) jout(['error' => 'bad_pubkey'], 400);   // a P-256 public half is 122 characters
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
        if (!$inv) { $out[] = ['code' => $code, 'error' => 'not_found']; continue; }
        $chk->execute([$key_hash]);
        if ($chk->fetch()) { $out[] = ['code' => $code, 'error' => 'user_key_collision']; continue; }

        // Opened again: the recipient removed the key and opens the same link.
        // The secret was born on their handset and is gone, so the part takes
        // the new key in place of the old one — on the same handset only. The
        // owner seals the bundle once more, for the new pair.
        if ($inv['status'] === 'redeemed') {
            $c = db()->prepare('SELECT id, host_id, parent_key_id, bound_device_fp FROM user_keys WHERE id = ?');
            $c->execute([(int)$inv['child_key_id']]);
            $child = $c->fetch(PDO::FETCH_ASSOC);
            if (!$child) { $out[] = ['code' => $code, 'error' => 'not_found']; continue; }
            if ($child['bound_device_fp'] && ($fp === '' || !hash_equals($child['bound_device_fp'], $fp))) {
                $out[] = ['code' => $code, 'error' => 'already_bound']; continue;
            }
            db()->prepare(
                'UPDATE user_keys SET key_hash = ?, sign_pub = ?, sign_suite = ?, sign_pub_device = NULL,
                                      guest_pub = ?, key_cipher = NULL, bundle_dirty = 1 WHERE id = ?'
            )->execute([$key_hash, $sign_pub, $suite, $guest_pub, (int)$child['id']]);
            [$cn, $cb] = split_types(array_keys(key_obj_read((int)$child['id'])));
            ask_owner((int)$child['host_id'], (int)$child['id'], (int)$child['parent_key_id'], $cn, $cb);
            $out[] = ['code' => $code, 'id' => (int)$child['id'], 'key_hash' => $key_hash, 'again' => 1];
            continue;
        }
        if ($inv['status'] !== 'new') { $out[] = ['code' => $code, 'error' => 'not_found']; continue; }
        if (strtotime($inv['expires_at']) < time()) { $out[] = ['code' => $code, 'error' => 'expired']; continue; }
        // Is the parent still alive?
        $par->execute([(int)$inv['parent_key_id']]);
        $pk = $par->fetch(PDO::FETCH_ASSOC);
        if (!$pk || !(int)$pk['enabled'] || ($pk['mode'] ?? 'auto') === 'off'
            || ($pk['expires_at'] && strtotime($pk['expires_at']) < time())) {
            $out[] = ['code' => $code, 'error' => 'parent_revoked']; continue;
        }
        // Settings of each object as the holder chose them. The chain may have
        // run out of keys since the link was made: such objects drop out.
        $sets = [];
        foreach ((array)json_decode((string)$inv['objects'], true) as $o) {
            $id = (int)($o['id'] ?? 0);
            if ($id > 0 && key_pool_left((int)$inv['parent_key_id'], $id, null, (int)$inv['id']) >= 1) {
                $sets[$id] = ['n' => (int)$o['n'], 'd' => (int)$o['d'], 'p' => (int)$o['p']];
            }
        }
        if (!$sets) { $out[] = ['code' => $code, 'error' => 'pool_exhausted']; continue; }
        // The child key is enabled but carries NO bundle: until the owner
        // assembles one it opens nothing. Lifetime is inherited from the parent.
        db()->prepare(
            'INSERT INTO user_keys (host_id, parent_key_id, share_grp, guest_pub, key_hash,
                                    sign_pub, sign_suite, enabled, mode, expires_at, created_at)
             VALUES (?,?,?,?,?,?,?,1,"auto",?,NOW())'
        )->execute([(int)$inv['host_id'], (int)$inv['parent_key_id'], $grp, $guest_pub, $key_hash,
                    $sign_pub, $suite, $pk['expires_at']]);
        $childId = (int)db()->lastInsertId();
        key_obj_write($childId, $sets);
        db()->prepare('UPDATE key_invites SET status="redeemed", child_key_id=?, redeemed_at=NOW() WHERE id=?')
            ->execute([$childId, (int)$inv['id']]);
        [$cn, $cb] = split_types(array_keys($sets));
        ask_owner((int)$inv['host_id'], $childId, (int)$inv['parent_key_id'], $cn, $cb);
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
        'SELECT code, grp, number_ids, ble_ids, objects, depth, status, child_key_id, created_at, expires_at, redeemed_at
         FROM key_invites WHERE parent_key_id = ? ORDER BY id DESC LIMIT 50'
    );
    $st->execute([(int)$k['id']]);
    $inv = $st->fetchAll(PDO::FETCH_ASSOC);
    foreach ($inv as &$i) {
        if ($i['status'] === 'new' && strtotime($i['expires_at']) < time()) $i['status'] = 'expired';
        $i['number_ids'] = csv_ids($i['number_ids']);
        $i['ble_ids'] = csv_ids($i['ble_ids']);
        $i['objects'] = array_map(fn($o) => ['id' => (int)$o['id'], 'depth' => (int)$o['d'], 'pool' => (int)$o['p']],
                                  (array)json_decode((string)$i['objects'], true));
    }
    unset($i);
    $ch = db()->prepare(
        'SELECT id, share_grp, guest_pub, confirmed_ids, bundle_dirty,
                (bundle_cipher IS NOT NULL) AS has_bundle, created_at
         FROM user_keys WHERE parent_key_id = ? ORDER BY id DESC'
    );
    $ch->execute([(int)$k['id']]);
    $children = [];
    foreach ($ch->fetchAll(PDO::FETCH_ASSOC) as $c) {
        $objs = key_obj_read((int)$c['id']);
        [$cn, $cb] = split_types(array_keys($objs));
        $children[] = [
            'id' => (int)$c['id'], 'grp' => $c['share_grp'], 'guest_pub' => $c['guest_pub'],
            'number_ids' => $cn, 'ble_ids' => $cb,
            'objects' => array_map(fn($id) => ['id' => $id, 'depth' => $objs[$id]['d'], 'pool' => $objs[$id]['p']],
                                   array_keys($objs)),
            // What the current bundle covers: the rest waits for the owner.
            'confirmed_ids' => csv_ids($c['confirmed_ids']),
            'ready' => ((int)$c['has_bundle'] && !(int)$c['bundle_dirty']) ? 1 : 0,
            'created_at' => $c['created_at'],
        ];
    }
    // What the holder may pass on, object by object: levels below them and
    // keys left in the chain above.
    $mine = [];
    foreach (key_obj_read((int)$k['id']) as $id => $o) {
        $mine[] = ['id' => $id, 'depth' => $o['d'], 'native_only' => $o['n'],
                   'pool_left' => $o['d'] >= 1 ? key_pool_left((int)$k['id'], $id) : 0];
    }
    jout(['depth' => (int)$k['delegate_depth'], 'objects' => $mine,
          'invites' => $inv, 'children' => $children]);
}

// ── Change the objects of a key one passed on ───────────────────────────────────
if ($action === 'edit') {
    $k = guest_key_auth($j);
    rate_limit_check('key_delegate', 30);
    $c = own_child((int)$k['id'], (int)($j['child_id'] ?? 0));
    // Objects already in the key keep their settings unless new ones came;
    // added ones are checked like at passing on.
    $cur = [];
    foreach (key_obj_read((int)$c['id']) as $id => $o) $cur[$id] = ['n' => $o['n'], 'd' => $o['d'], 'p' => $o['p']];
    $sets = pass_objects($k, $j, (int)$c['id'], null, $cur);
    // Nothing left: the part goes, together with whatever was passed on below it.
    if (!$sets) {
        jout(['ok' => 1, 'revoked' => key_revoke_tree((int)$c['id'])]);
    }
    key_obj_write((int)$c['id'], $sets);
    // The current bundle stays in place: the recipient keeps opening what was
    // confirmed until the owner assembles the new one.
    db()->prepare('UPDATE user_keys SET bundle_dirty = 1 WHERE id = ?')->execute([(int)$c['id']]);
    [$cn, $cb] = split_types(array_keys($sets));
    ask_owner((int)$c['host_id'], (int)$c['id'], (int)$k['id'], $cn, $cb);
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
