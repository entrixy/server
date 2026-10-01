<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_create', 30);
require_once __DIR__ . '/../lib/account.php';
require_once __DIR__ . '/../lib/org.php';
require_once __DIR__ . '/../lib/guest_auth.php';   // the company callback
require_once __DIR__ . '/../lib/key_objects.php';
[$host_id, $j] = host_auth();

// The guest's name is not stored in the database. The owner keeps it
// locally, as a map of user_key_id to label; the server sees only id and key_hash.
// Bluetooth-only keys have an empty number_ids: everything they need — tokens,
// the guest key, shares — is sealed inside bundle_cipher and the server does not
// need it for routing. So either number_ids or a non-empty bundle_cipher is
// required.
$number_ids = $j['number_ids'] ?? [];
if (!is_array($number_ids)) jout(['error' => 'bad_input'], 400);
// Bluetooth locks are objects of this server as well: they go into the key's
// list with their own settings, the live connection simply does not show them.
$number_ids = array_values(array_unique(array_merge(
    array_map('intval', $number_ids), array_map('intval', (array)($j['ble_ids'] ?? [])))));
$bundle_cipher_for_check = (string)($j['bundle_cipher'] ?? '');
if (!$number_ids && $bundle_cipher_for_check === '') {
    jout(['error' => 'bad_input'], 400);
}

// The limit comes from the plan, the same way synchronisation reads it: the
// account's plan if the device is attached to one, otherwise the device's own.
// Counting it differently here is not allowed — the app would show one number
// while the server refused by another.
$max = account_limits($host_id)['max_keys'];

$cnt = db()->prepare('SELECT COUNT(*) FROM user_keys WHERE host_id = ? AND enabled = 1');
$cnt->execute([$host_id]);
if ((int)$cnt->fetchColumn() >= $max) {
    jout(['error' => 'limit_reached', 'limit' => $max], 403);
}

// For a Bluetooth-only key with empty number_ids the check of object ids is
// skipped: there is nothing for the server to validate. bundle_cipher was
// already required above in that case.
$valid = [];
if ($number_ids) {
    $in  = implode(',', array_fill(0, count($number_ids), '?'));
    $st  = db()->prepare("SELECT id FROM numbers WHERE host_id = ? AND id IN ($in)");
    $st->execute(array_merge([$host_id], array_map('intval', $number_ids)));
    $valid = array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
    if (!$valid) jout(['error' => 'bad_numbers'], 400);
}

// The client may send its own user_key: in the offline-first case the key is
// created on the device and synchronised once the network appears. We accept
// 16 or more bytes of entropy as a base64url string, and generate one ourselves
// if the client sent none.
// The key that opens never reaches the server, neither at issue nor later.
// The owner sends the fingerprint, which the row is found by, and the public
// half of the signing pair, which the right is checked with. The string itself
// lives only on the phones.
$key_hash_in = strtolower(trim((string)($j['key_hash'] ?? '')));
$sign_pub_in = (string)($j['sign_pub'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/', $key_hash_in)) jout(['error' => 'bad_key_hash'], 400);
$sign_pub = base64_decode(strtr($sign_pub_in, '-_', '+/'), true);
if ($sign_pub === false || strlen($sign_pub) !== 32) jout(['error' => 'bad_sign_pub'], 400);
// Which suite the key is issued under. It must sign with that one later.
require_once __DIR__ . '/../lib/suites.php';
$sign_suite = (string)($j['suite'] ?? ENTRIXY_SUITE_PREFERRED);
if (!suite_known($sign_suite)) jout(['error' => 'unsupported_suite', 'suites' => suite_list()], 400);
$chk = db()->prepare('SELECT id FROM user_keys WHERE key_hash = ?');
$chk->execute([$key_hash_in]);
if ($chk->fetch()) jout(['error' => 'user_key_collision'], 409);
$key_hash = $key_hash_in;

$force_busy = (int)(bool)($j['force_when_busy'] ?? false);
// native_only — the key works in the native app only, not in the browser client.
$native_only = (int)(bool)($j['native_only'] ?? false);
// The bundle: {obj_keys, welcome} encrypted with the guest key. The server keeps
// it as an opaque blob.
$bundle_cipher = (string)($j['bundle_cipher'] ?? '');
if ($bundle_cipher === '') $bundle_cipher = null;
if (!is_valid_cipher($bundle_cipher)) jout(['error' => 'invalid_cipher_format'], 400);

// A company key is issued not as a link but by picking the company from a list
// after its QR was scanned. Only a reference to the row (key_ref) leaves the
// server, so there is nothing to forward. A company cannot pass such a key on.
$org_id = null;
$org_request = null;
$org_code = (string)($j['org_code'] ?? '');
if ($org_code !== '') {
    $st = db()->prepare(
        'SELECT r.id, r.org_id, r.status, r.expires_at
         FROM org_requests r JOIN orgs o ON o.id = r.org_id
         WHERE r.code = ? AND o.status <> "blocked"'
    );
    $st->execute([$org_code]);
    $org_request = $st->fetch(PDO::FETCH_ASSOC);
    if (!$org_request) jout(['error' => 'org_request_not_found'], 404);
    if (!in_array($org_request['status'], ['new', 'claimed'], true)) {
        jout(['error' => 'org_request_used'], 409);
    }
    if (strtotime($org_request['expires_at']) < time()) jout(['error' => 'org_request_expired'], 410);
    $org_id = (int)$org_request['org_id'];
}
// Picking a company from the list without a fresh QR: its id is enough if it is
// verified. The object's owner issues it, so this is their deliberate decision.
if ($org_id === null) {
    $oid = (int)($j['org_id'] ?? 0);
    if ($oid > 0) {
        $st = db()->prepare('SELECT id FROM orgs WHERE id = ? AND status <> "blocked"');
        $st->execute([$oid]);
        if (!$st->fetchColumn()) jout(['error' => 'org_not_found'], 404);
        $org_id = $oid;
    }
}

// Delegation depth: how many issues are allowed BELOW this key. Zero for a
// company — it opens itself and passes nothing on — and one level by default for
// a person.
$depth = $org_id !== null ? 0 : (int)($j['delegate_depth'] ?? 0);
if ($depth < 0) $depth = 0;
if ($depth > 255) $depth = 255;

// The key's lifetime. The field exists but is not used yet: the client does not
// send it, the value stays empty, and the key lives until it is revoked.
$expires_at = (string)($j['expires_at'] ?? '');
$expires_at = preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $expires_at) ? $expires_at : null;

// A company gets one key per owner: its set of objects can be edited, and a
// second key for the same company is merely the same access duplicated. Issuing
// again extends the existing one.
if ($org_id !== null) {
    $ex = db()->prepare(
        'SELECT id FROM user_keys WHERE host_id = ? AND org_id = ? AND enabled = 1 ORDER BY id ASC LIMIT 1'
    );
    $ex->execute([$host_id, $org_id]);
    $existing = (int)($ex->fetchColumn() ?: 0);
    if ($existing > 0) {
        $lbl = [];
        if (is_array($j['org_labels'] ?? null)) {
            foreach ($j['org_labels'] as $nid => $label) $lbl[(int)$nid] = mb_substr(trim((string)$label), 0, 64);
        }
        $ins = db()->prepare(
            'INSERT INTO key_numbers (user_key_id, number_id, org_label, delegate_depth) VALUES (?, ?, ?, 0)
             ON DUPLICATE KEY UPDATE org_label = VALUES(org_label)'
        );
        foreach ($valid as $nid) $ins->execute([$existing, $nid, $lbl[$nid] ?? null]);
        if ($org_request) {
            db()->prepare(
                'UPDATE org_requests SET status = "issued", user_key_id = ?, issued_at = NOW() WHERE id = ?'
            )->execute([$existing, (int)$org_request['id']]);
        } else {
            db()->prepare(
                'UPDATE org_requests SET status = "issued", user_key_id = ?, issued_at = NOW()
                 WHERE org_id = ? AND host_id = ? AND status IN ("new","claimed")'
            )->execute([$existing, $org_id, $host_id]);
        }
        db()->prepare(
            'INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?, ?, NOW())'
        )->execute(['key_updated', $existing]);
        $cq = db()->prepare('SELECT code FROM org_requests WHERE user_key_id = ?');
        $cq->execute([$existing]);
        foreach ($cq->fetchAll(PDO::FETCH_COLUMN) as $code) {
            org_callback($org_id, 'issued', ['code' => $code, 'key_ref' => $existing]);
        }
        audit_log($host_id, 'key_create_merge', 'user_key', $existing, ['numbers' => $valid, 'org' => $org_id]);
        jout(['id' => $existing, 'user_key' => null, 'org_id' => $org_id,
              'delegate_depth' => 0, 'merged' => 1]);
    }
}

$st = db()->prepare(
    'INSERT INTO user_keys (host_id, org_id, delegate_depth, key_hash, sign_pub, sign_suite, enabled, force_when_busy, native_only, created_at, expires_at, bundle_cipher, bundle_cipher_updated)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NOW(), ?, ?, ' . ($bundle_cipher !== null ? 'NOW()' : 'NULL') . ')'
);
$st->execute([$host_id, $org_id, $depth, $key_hash, $sign_pub, $sign_suite, $force_busy, $native_only, $expires_at, $bundle_cipher]);
$key_id = (int)db()->lastInsertId();

if ($org_request) {
    db()->prepare(
        'UPDATE org_requests SET status = "issued", user_key_id = ?, issued_at = NOW() WHERE id = ?'
    )->execute([$key_id, (int)$org_request['id']]);
} elseif ($org_id !== null) {
    // The key was issued with no code, from the company list. A request from that
    // company opened on the same phone is closed all the same: it has access now.
    db()->prepare(
        'UPDATE org_requests SET status = "issued", user_key_id = ?, issued_at = NOW()
         WHERE org_id = ? AND host_id = ? AND status IN ("new","claimed")'
    )->execute([$key_id, $org_id, $host_id]);
}

// Object names for the company. Normally the name is encrypted and the server
// does not know it; for a company the owner sends it openly and deliberately,
// otherwise its employee sees "object 93" at the gate instead of "Yard barrier".
$org_labels = [];
if ($org_id !== null && is_array($j['org_labels'] ?? null)) {
    foreach ($j['org_labels'] as $nid => $label) {
        $org_labels[(int)$nid] = mb_substr(trim((string)$label), 0, 64);
    }
}
// Settings of each object: "app only", pass-on levels, keys in all. A company
// does not pass access on. Without a list, the key-wide fields of an older app
// apply to every object.
$defaults = ['n' => $native_only, 'd' => $depth, 'p' => KEY_OBJ_DEFAULTS['p']];
$settings = key_obj_settings_in($org_id !== null ? [] : $j, $valid, $defaults);
if ($org_id !== null) foreach ($settings as &$s0) { $s0['d'] = 0; $s0['n'] = 0; } unset($s0);
key_obj_write($key_id, $settings, $org_labels);

// The company learns that access was granted; it fetches the details itself with a=status.
if ($org_id !== null) {
    $cq = db()->prepare('SELECT code FROM org_requests WHERE user_key_id = ?');
    $cq->execute([$key_id]);
    foreach ($cq->fetchAll(PDO::FETCH_COLUMN) as $code) {
        org_callback($org_id, 'issued', ['code' => $code, 'key_ref' => $key_id]);
    }
}

audit_log($host_id, 'key_create', 'user_key', $key_id, [
    'numbers' => $valid,
    'org'     => $org_id,
    'depth'   => $depth,
]);

jout(['id' => $key_id, 'org_id' => $org_id, 'delegate_depth' => $depth]);
