<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_edit', 60);
[$host_id, $j] = host_auth();

$id = (int)($j['id'] ?? 0);
$number_ids = $j['number_ids'] ?? [];
// The label is not stored on the server; the owner keeps it locally.
if ($id <= 0 || !is_array($number_ids)) jout(['error' => 'bad_input'], 400);

$st = db()->prepare('SELECT id, parent_key_id, org_id, ble_ids, UNIX_TIMESTAMP(bundle_cipher_updated) AS bct FROM user_keys WHERE id = ? AND host_id = ?');
$st->execute([$id, $host_id]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row) jout(['error' => 'not_found'], 404);

// Optimistic locking for bundle_cipher, as in number_update.php.
if (array_key_exists('bundle_cipher_ts_check', $j) && array_key_exists('bundle_cipher', $j)) {
    $clientTs = (int)$j['bundle_cipher_ts_check'];
    $serverTs = (int)($row['bct'] ?? 0);
    if ($serverTs > $clientTs) {
        jout(['error' => 'stale_bundle_cipher', 'server_ts' => $serverTs], 409);
    }
}

$valid = [];
if (!empty($number_ids)) {
    $in = implode(',', array_fill(0, count($number_ids), '?'));
    $st = db()->prepare("SELECT id FROM numbers WHERE host_id = ? AND id IN ($in)");
    $st->execute(array_merge([$host_id], array_map('intval', $number_ids)));
    $valid = array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN));
}
// A key with Bluetooth locks only has no objects on the server at all; a list
// that names objects none of which are this owner's is still a mistake.
if (!$valid && !empty($number_ids)) jout(['error' => 'no_numbers'], 400);

// Object names for a company arrive in the clear: the owner decides that the
// service may see them, as in key_create.
$org_labels = [];
if (is_array($j['org_labels'] ?? null)) {
    foreach ($j['org_labels'] as $nid => $label) $org_labels[(int)$nid] = mb_substr(trim((string)$label), 0, 64);
}
db()->prepare('DELETE FROM key_numbers WHERE user_key_id = ?')->execute([$id]);
$ins = db()->prepare('INSERT INTO key_numbers (user_key_id, number_id, org_label) VALUES (?, ?, ?)');
foreach ($valid as $nid) $ins->execute([$id, $nid, $org_labels[$nid] ?? null]);

// Two settings belong to the owner alone and apply to keys they issued
// themselves: a company does not pass access on, and a key passed on by a
// guest inherits both from its parent. Keys already passed on below are left
// as they are.
if ($row['parent_key_id'] === null && $row['org_id'] === null) {
    if (isset($j['native_only'])) {
        db()->prepare('UPDATE user_keys SET native_only = ? WHERE id = ?')
            ->execute([(int)(bool)$j['native_only'], $id]);
    }
    if (isset($j['delegate_depth'])) {
        $d = max(0, min(255, (int)$j['delegate_depth']));
        db()->prepare('UPDATE user_keys SET delegate_depth = ? WHERE id = ?')->execute([$d, $id]);
    }
}

if (isset($j['force_when_busy'])) {
    db()->prepare('UPDATE user_keys SET force_when_busy = ? WHERE id = ?')
        ->execute([(int)(bool)$j['force_when_busy'], $id]);
}
// The bundle may be overwritten: after one object is revoked, or an object key
// is rotated, the owner reassembles it and sends a new one.
if (array_key_exists('bundle_cipher', $j)) {
    $b = (string)$j['bundle_cipher'];
    $b = $b === '' ? null : $b;
    if (!is_valid_cipher($b)) jout(['error' => 'invalid_cipher_format'], 400);
    // What the bundle covers from now on: for a key passed on by a guest, the
    // difference with its current objects shows as "waiting for the owner".
    $cover = $valid;
    foreach (explode(',', (string)$row['ble_ids']) as $bid) if ((int)$bid > 0) $cover[] = (int)$bid;
    db()->prepare('UPDATE user_keys SET bundle_cipher = ?, bundle_cipher_updated = NOW(),
                          confirmed_ids = ?, bundle_dirty = 0 WHERE id = ?')
        ->execute([$b, $b === null ? null : implode(',', $cover), $id]);
}

// The bundle key for a guest further down a chain: encrypted with their public
// key, so the server sees only a blob.
if (array_key_exists('key_cipher', $j)) {
    $kc = (string)$j['key_cipher'];
    if ($kc !== '' && !preg_match('/^[A-Za-z0-9_.:-]{1,255}$/', $kc)) jout(['error' => 'bad_key_cipher'], 400);
    db()->prepare('UPDATE user_keys SET key_cipher = ? WHERE id = ?')
        ->execute([$kc === '' ? null : $kc, $id]);
}

db()->prepare(
    'INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?, ?, NOW())'
)->execute(['key_updated', $id]);

audit_log($host_id, 'key_edit', 'user_key', $id, [
    'numbers' => $valid,
    'fields' => array_intersect(array_keys($j), ['force_when_busy', 'bundle_cipher', 'native_only', 'delegate_depth']),
]);

jout(['ok' => 1]);
