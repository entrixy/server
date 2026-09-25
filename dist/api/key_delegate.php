<?php
/**
 * Passing access down a chain. The key holder does NOT issue a key and does NOT
 * learn anyone else's secret: they create a single-use invitation. The secret is
 * born on the recipient's device when it is accepted and reaches the server from
 * there.
 *
 *   a=create  (guest)  create an invitation: a subset of one's objects
 *   a=info    (any)    what a code offers
 *   a=redeem  (any)    accept: the recipient's device sends its own user_key
 *   a=cancel  (guest)  cancel one's invitation
 *   a=list    (guest)  one's invitations and the keys issued through them
 *
 * A child key is an ordinary row on the OWNER's object: only the owner's device
 * can assemble its bundle, so after acceptance the key sits in a "waiting for
 * confirmation" state until the owner comes online.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/account.php';

const DELEGATE_MAX_CHILDREN = 5;    // how many children one key may have
const DELEGATE_INVITE_HOURS = 72;   // how long an invitation lives

$action = (string)($_GET['a'] ?? '');
$j = jin();

/** The guest, by their key plus the device fingerprint bound to it. */
function guest_key_auth(array $j): array {
    $user_key = (string)($j['user_key'] ?? '');
    $fp       = (string)($j['device_fp'] ?? '');
    if ($user_key === '') jout(['error' => 'auth'], 401);
    $st = db()->prepare(
        'SELECT id, host_id, enabled, mode, delegate_depth, expires_at, bound_device_fp, org_id
         FROM user_keys WHERE key_hash = ? LIMIT 1'
    );
    $st->execute([hash('sha256', $user_key)]);
    $k = $st->fetch(PDO::FETCH_ASSOC);
    if (!$k || !(int)$k['enabled']) jout(['error' => 'auth'], 401);
    if (($k['mode'] ?? 'auto') === 'off') jout(['error' => 'revoked'], 403);
    if ($k['expires_at'] && strtotime($k['expires_at']) < time()) jout(['error' => 'expired'], 403);
    if ($k['bound_device_fp'] && (!$fp || !hash_equals($k['bound_device_fp'], $fp))) {
        jout(['error' => 'already_bound'], 403);
    }
    return $k;
}

function key_numbers(int $keyId): array {
    $st = db()->prepare('SELECT number_id FROM key_numbers WHERE user_key_id = ?');
    $st->execute([$keyId]);
    return array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
}

// ── Create an invitation ──────────────────────────────────────────────────────────
if ($action === 'create') {
    $k = guest_key_auth($j);
    rate_limit_check('key_delegate', 20);
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

    $mine = key_numbers((int)$k['id']);
    $want = array_map('intval', (array)($j['number_ids'] ?? []));
    $ids  = $want ? array_values(array_intersect($want, $mine)) : $mine;
    if (!$ids) jout(['error' => 'bad_numbers'], 400);

    $hours = (int)($j['ttl_hours'] ?? DELEGATE_INVITE_HOURS);
    if ($hours < 1 || $hours > 720) $hours = DELEGATE_INVITE_HOURS;

    for ($try = 0; $try < 5; $try++) {
        $code = substr(rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='), 0, 22);
        try {
            db()->prepare(
                'INSERT INTO key_invites (host_id, parent_key_id, code, number_ids, depth, expires_at, created_at)
                 VALUES (?,?,?,?,?, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())'
            )->execute([(int)$k['host_id'], (int)$k['id'], $code, implode(',', $ids), $depth - 1, $hours]);
            jout(['code' => $code, 'url' => site_url('/i/' . $code),
                  'objects' => count($ids), 'depth' => $depth - 1, 'expires_in_hours' => $hours]);
        } catch (\Throwable $e) { /* code collision */ }
    }
    jout(['error' => 'try_later'], 503);
}

// ── What is offered ─────────────────────────────────────────────────────────────────
if ($action === 'info') {
    $code = (string)($_GET['code'] ?? ($j['code'] ?? ''));
    if ($code === '') jout(['error' => 'bad_input'], 400);
    rate_limit_check('key_invite_info', 60);
    $st = db()->prepare('SELECT * FROM key_invites WHERE code = ?');
    $st->execute([$code]);
    $inv = $st->fetch(PDO::FETCH_ASSOC);
    if (!$inv) jout(['error' => 'not_found'], 404);
    $state = $inv['status'];
    if ($state === 'new' && strtotime($inv['expires_at']) < time()) $state = 'expired';
    jout(['state' => $state, 'objects' => count(explode(',', $inv['number_ids'])),
          'depth' => (int)$inv['depth'], 'expires_at' => $inv['expires_at']]);
}

// ── Accept: the recipient's device generates the secret ────────────────
if ($action === 'redeem') {
    $code = (string)($j['code'] ?? '');
    $user_key = (string)($j['user_key'] ?? '');
    // The public half of the recipient's pair. The owner encrypts the bundle key
    // with it, so neither the server nor whoever passed the invitation can read
    // the bundle.
    $guest_pub = (string)($j['guest_pub'] ?? '');
    if ($code === '' || !preg_match('/^[A-Za-z0-9_-]{32,64}$/', $user_key)) jout(['error' => 'bad_input'], 400);
    if (!preg_match('/^[A-Za-z0-9_-]{40,120}$/', $guest_pub)) jout(['error' => 'bad_pubkey'], 400);
    rate_limit_check('key_invite_redeem', 20);

    $st = db()->prepare('SELECT * FROM key_invites WHERE code = ? FOR UPDATE');
    db()->beginTransaction();
    $st->execute([$code]);
    $inv = $st->fetch(PDO::FETCH_ASSOC);
    if (!$inv || $inv['status'] !== 'new') { db()->rollBack(); jout(['error' => 'not_found'], 404); }
    if (strtotime($inv['expires_at']) < time()) {
        db()->prepare('UPDATE key_invites SET status = "expired" WHERE id = ?')->execute([(int)$inv['id']]);
        db()->commit(); jout(['error' => 'expired'], 410);
    }
    // Is the parent still alive?
    $p = db()->prepare('SELECT id, enabled, mode, expires_at, native_only FROM user_keys WHERE id = ?');
    $p->execute([(int)$inv['parent_key_id']]);
    $par = $p->fetch(PDO::FETCH_ASSOC);
    if (!$par || !(int)$par['enabled'] || ($par['mode'] ?? 'auto') === 'off'
        || ($par['expires_at'] && strtotime($par['expires_at']) < time())) {
        db()->rollBack(); jout(['error' => 'parent_revoked'], 403);
    }
    $chk = db()->prepare('SELECT id FROM user_keys WHERE key_hash = ?');
    $chk->execute([hash('sha256', $user_key)]);
    if ($chk->fetch()) { db()->rollBack(); jout(['error' => 'user_key_collision'], 409); }

    // The child key is enabled but carries NO bundle: until the owner assembles one
    // it opens nothing. Lifetime and the "app only" mode are inherited from the
    // parent: nobody can pass on more than they hold.
    db()->prepare(
        'INSERT INTO user_keys (host_id, parent_key_id, delegate_depth, guest_pub, key_hash, enabled, mode,
                                native_only, expires_at, created_at)
         VALUES (?,?,?,?,?,1,"auto",?,?,NOW())'
    )->execute([(int)$inv['host_id'], (int)$inv['parent_key_id'], (int)$inv['depth'], $guest_pub,
                hash('sha256', $user_key), (int)$par['native_only'], $par['expires_at']]);
    $childId = (int)db()->lastInsertId();
    $ins = db()->prepare('INSERT INTO key_numbers (user_key_id, number_id) VALUES (?,?)');
    foreach (explode(',', $inv['number_ids']) as $nid) $ins->execute([$childId, (int)$nid]);
    db()->prepare('UPDATE key_invites SET status="redeemed", child_key_id=?, redeemed_at=NOW() WHERE id=?')
        ->execute([$childId, (int)$inv['id']]);

    // For the owner: assemble the bundle for the new key and show a notification.
    db()->prepare(
        'INSERT INTO pending_host_msgs (host_id, payload, created_at, dedup_key) VALUES (?,?,NOW(),?)'
    )->execute([(int)$inv['host_id'],
        json_encode(['type' => 'bundle_request', 'key_id' => $childId,
                     'parent_key_id' => (int)$inv['parent_key_id'],
                     'number_ids' => array_map('intval', explode(',', $inv['number_ids']))]),
        'bundle_req_' . $childId]);
    db()->prepare('INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?,?,NOW())')
        ->execute(['key_delegated', $childId]);
    db()->commit();

    jout(['ok' => 1, 'id' => $childId, 'state' => 'awaiting_owner']);
}

// ── Cancel one's invitation ─────────────────────────────────────────────────────
if ($action === 'cancel') {
    $k = guest_key_auth($j);
    $code = (string)($j['code'] ?? '');
    db()->prepare('UPDATE key_invites SET status="cancelled" WHERE code=? AND parent_key_id=? AND status="new"')
        ->execute([$code, (int)$k['id']]);
    jout(['ok' => 1]);
}

// ── One's invitations and their children ────────────────────────────────────────
if ($action === 'list') {
    $k = guest_key_auth($j);
    $st = db()->prepare(
        'SELECT code, number_ids, depth, status, child_key_id, created_at, expires_at, redeemed_at
         FROM key_invites WHERE parent_key_id = ? ORDER BY id DESC LIMIT 50'
    );
    $st->execute([(int)$k['id']]);
    $inv = $st->fetchAll(PDO::FETCH_ASSOC);
    foreach ($inv as &$i) {
        if ($i['status'] === 'new' && strtotime($i['expires_at']) < time()) $i['status'] = 'expired';
        $i['objects'] = count(explode(',', $i['number_ids']));
        unset($i['number_ids']);
    }
    $ch = db()->prepare(
        'SELECT id, enabled, mode, (bundle_cipher IS NOT NULL) AS ready, created_at
         FROM user_keys WHERE parent_key_id = ? ORDER BY id DESC'
    );
    $ch->execute([(int)$k['id']]);
    jout(['depth' => (int)$k['delegate_depth'], 'invites' => $inv,
          'children' => $ch->fetchAll(PDO::FETCH_ASSOC),
          'max_children' => DELEGATE_MAX_CHILDREN]);
}

jout(['error' => 'unknown_action'], 400);
