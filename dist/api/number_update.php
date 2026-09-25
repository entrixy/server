<?php
require __DIR__ . '/_bootstrap.php';
[$host_id, $j] = host_auth();

$id = (int)($j['id'] ?? 0);
if (!$id) jout(['error' => 'bad_input'], 400);

// Check that the object belongs to this host
$st = db()->prepare('SELECT id, UNIX_TIMESTAMP(data_cipher_updated) AS dct FROM numbers WHERE id = ? AND host_id = ?');
$st->execute([$id, $host_id]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row) jout(['error' => 'forbidden'], 403);

// Optimistic locking: if the client sent data_cipher_ts_check we compare it with
// what is in the database. If the database is newer the update is refused with
// 409, and the client must synchronise and try again.
if (array_key_exists('data_cipher_ts_check', $j) && array_key_exists('data_cipher', $j)) {
    $clientTs = (int)$j['data_cipher_ts_check'];
    $serverTs = (int)($row['dct'] ?? 0);
    if ($serverTs > $clientTs) {
        jout(['error' => 'stale_data_cipher', 'server_ts' => $serverTs], 409);
    }
}

// The fields being updated, only those that were sent
$fields = [];
$params = [];

// The server accepts in the clear ONLY the fields it routes by. The sensitive
// ones — label, phone, radius, time, geo, wifi, share, has_avatar and the rest —
// are encrypted into data_cipher and no longer arrive here. If an older client
// sends them anyway they are ignored silently rather than failing.
$allowed = [
    'webhook_url'    => 'string_null',
    'webhook_secret' => 'string_null',
    'webhook_mode'   => 'enum:phone,server',
    // An encrypted blob: the server passes it through without interpreting it.
    'data_cipher'    => 'string_null',
];

if (array_key_exists('data_cipher', $j) && !is_valid_cipher($j['data_cipher'])) {
    jout(['error' => 'invalid_cipher_format'], 400);
}

// SSRF: the same filter of internal addresses as when a webhook object is created.
if (array_key_exists('webhook_url', $j)) {
    $wu = trim((string)$j['webhook_url']);
    if ($wu !== '' && ssrf_host_blocked(parse_url($wu, PHP_URL_HOST))) {
        jout(['error' => 'webhook_url_forbidden'], 400);
    }
}

foreach ($allowed as $col => $type) {
    if (!array_key_exists($col, $j)) continue;
    $v = $j[$col];
    switch ($type) {
        case 'string':
            $v = trim((string)$v);
            break;
        case 'string_null':
            $v = $v === null ? null : trim((string)$v);
            if ($v === '') $v = null;
            break;
        case 'int':
            $v = (int)$v;
            break;
        case 'bool':
            $v = $v ? 1 : 0;
            break;
        case 'float_null':
            $v = $v === null ? null : (float)$v;
            break;
        case 'time':
            $v = $v === null ? null : trim((string)$v);
            if ($v === '') $v = null;
            break;
        default:
            if (str_starts_with($type, 'enum:')) {
                $vals = explode(',', substr($type, 5));
                if (!in_array((string)$v, $vals)) continue 2;
                $v = (string)$v;
            }
    }
    $fields[] = "$col = ?";
    $params[] = $v;
}

if (empty($fields)) jout(['error' => 'nothing_to_update'], 400);

// If data_cipher is among the updated fields, its timestamp is updated with it.
if (array_key_exists('data_cipher', $j)) {
    $fields[] = 'data_cipher_updated = NOW()';
}

// In phone mode the webhook URL and secret are cleared by force: the server needs
// them ONLY in server mode, where it fires the request itself. In phone mode the
// secret must live only on the owner's phone.
$effectiveMode = null;
foreach ($fields as $i => $f) {
    if ($f === 'webhook_mode = ?') $effectiveMode = $params[$i];
}
if ($effectiveMode === null) {
    // Not in this update, so take the current one from the database
    $st2 = db()->prepare('SELECT webhook_mode FROM numbers WHERE id = ?');
    $st2->execute([$id]);
    $effectiveMode = (string)($st2->fetchColumn() ?: 'phone');
}
if ($effectiveMode === 'phone') {
    // Overwrite, or add, webhook_url and secret as NULL
    $hasUrl = false; $hasSec = false;
    foreach ($fields as $i => $f) {
        if ($f === 'webhook_url = ?')    { $params[$i] = null; $hasUrl = true; }
        if ($f === 'webhook_secret = ?') { $params[$i] = null; $hasSec = true; }
    }
    if (!$hasUrl) { $fields[] = 'webhook_url = ?';    $params[] = null; }
    if (!$hasSec) { $fields[] = 'webhook_secret = ?'; $params[] = null; }
}

$params[] = $id;
$sql = 'UPDATE numbers SET ' . implode(', ', $fields) . ' WHERE id = ?';
db()->prepare($sql)->execute($params);

// Every guest holding this object in a key is notified, so they re-read the
// label, the phone number, the avatar and the rest.
$st = db()->prepare('SELECT user_key_id FROM key_numbers WHERE number_id = ?');
$st->execute([$id]);
$ukids = $st->fetchAll(PDO::FETCH_COLUMN);
$ins = db()->prepare(
    'INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?, ?, NOW())'
);
foreach ($ukids as $ukid) {
    $ins->execute(['key_updated', (int)$ukid]);
}

audit_log($host_id, 'number_update', 'number', $id, [
    'fields' => array_keys($j),
]);

jout(['ok' => true]);
