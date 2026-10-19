<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('device_register', 20);
[$host_id, $j] = host_auth();

// A controller is born per object; past this many the requests are a loop or
// abuse, not a household.
$cnt = db()->prepare('SELECT COUNT(*) FROM devices WHERE host_id = ?');
$cnt->execute([$host_id]);
if ((int)$cnt->fetchColumn() >= 200) jout(['error' => 'limit_reached'], 403);

$device_key    = bin2hex(random_bytes(16));
$device_secret = bin2hex(random_bytes(16));
$secret_hash   = hash('sha256', $device_secret);

$st = db()->prepare(
    "INSERT INTO devices (host_id, device_key, secret_hash, label) VALUES (?, ?, ?, '')"
);
// Название контроллера сервер не хранит: оно у владельца, в зашифрованной
// записи объекта. Старые приложения его ещё присылают — пропускаем мимо.
$st->execute([$host_id, $device_key, $secret_hash]);
$device_id = (int)db()->lastInsertId();

jout([
    'device_id'     => $device_id,
    'device_key'    => $device_key,
    'device_secret' => $device_secret,
]);
