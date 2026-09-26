<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('number_add', 30);
require_once __DIR__ . '/../lib/account.php';
[$host_id, $j] = host_auth();

$type  = (string)($j['type'] ?? 'call');
// Bluetooth objects live in the numbers table with data_cipher, rather than only
// locally inside bundle_cipher as they once did. That is what lets changes
// propagate to guests through synchronisation.
if (!in_array($type, ['call','webhook','device','ble'])) $type = 'call';

// The limit comes from the plan, the same way synchronisation reads it: the
// account's plan if the device is attached to one, otherwise the device's own.
// Counting it differently here is not allowed — the app would show one number
// while the server refused by another.
$max = account_limits($host_id)['max_numbers'];

$cnt = db()->prepare('SELECT COUNT(*) FROM numbers WHERE host_id = ?');
$cnt->execute([$host_id]);
if ((int)$cnt->fetchColumn() >= $max) {
    jout(['error' => 'limit_reached', 'limit' => $max], 403);
}

// The webhook URL and secret are stored in the clear ONLY for server mode, where
// the server sends the request itself. In phone mode they live on the owner's
// phone and stay NULL here.
$webhook_mode   = $type === 'webhook' ? ((string)($j['webhook_mode'] ?? 'phone')) : 'phone';
if ($type === 'webhook' && !in_array($webhook_mode, ['phone','server'])) $webhook_mode = 'phone';
$webhook_url    = ($type === 'webhook' && $webhook_mode === 'server') ? trim((string)($j['webhook_url'] ?? '')) : null;
$webhook_secret = ($type === 'webhook' && $webhook_mode === 'server') ? trim((string)($j['webhook_secret'] ?? '')) : null;
// SSRF: a server-side webhook is fired from inside our network, so internal
// addresses — loopback, private ranges, metadata services — must not be allowed.
if ($webhook_url !== null && $webhook_url !== '' && ssrf_host_blocked(parse_url($webhook_url, PHP_URL_HOST))) {
    jout(['error' => 'webhook_url_forbidden'], 400);
}

$device_id = $type === 'device' ? (int)($j['device_id_ref'] ?? 0) : null;
if ($device_id === 0) $device_id = null;
// An object may be attached only to one's OWN device: without this check a host
// could bind an object to someone else's device_id and send it commands.
if ($device_id !== null) {
    $chk = db()->prepare('SELECT 1 FROM devices WHERE id = ? AND host_id = ?');
    $chk->execute([$device_id, $host_id]);
    if (!$chk->fetchColumn()) jout(['error' => 'device_not_owned'], 403);
}

// The client sends an encrypted blob with every sensitive field: label, phone,
// avatar, snapshot and so on. The server does not read it, only stores it.
$data_cipher = (string)($j['data_cipher'] ?? '');
if ($data_cipher === '') $data_cipher = null;
if (!is_valid_cipher($data_cipher)) jout(['error' => 'invalid_cipher_format'], 400);

$st = db()->prepare(
    'INSERT INTO numbers (host_id, type, webhook_url, webhook_secret, webhook_mode, device_id, data_cipher, data_cipher_updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ' . ($data_cipher !== null ? 'NOW()' : 'NULL') . ')'
);
$st->execute([$host_id, $type, $webhook_url, $webhook_secret, $webhook_mode, $device_id, $data_cipher]);
$newId = (int)db()->lastInsertId();
// The audit log carries no personal data, only the object's type.
audit_log($host_id, 'number_add', 'number', $newId, ['type' => $type]);
jout(['id' => $newId]);
