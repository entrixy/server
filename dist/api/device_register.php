<?php
require __DIR__ . '/_bootstrap.php';
[$host_id, $j] = host_auth();

$label = trim((string)($j['label'] ?? ''));
if ($label === '') jout(['error' => 'bad_input'], 400);

$device_key    = bin2hex(random_bytes(16));
$device_secret = bin2hex(random_bytes(16));
$secret_hash   = hash('sha256', $device_secret);

$st = db()->prepare(
    'INSERT INTO devices (host_id, device_key, secret_hash, label) VALUES (?, ?, ?, ?)'
);
$st->execute([$host_id, $device_key, $secret_hash, $label]);
$device_id = (int)db()->lastInsertId();

jout([
    'device_id'     => $device_id,
    'device_key'    => $device_key,
    'device_secret' => $device_secret,
]);
