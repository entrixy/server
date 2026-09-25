<?php
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/account.php';
rate_limit_check('register_host', 5);

$j = jin();

// Who the server admits at all: see lib/access.php. On an open server the check
// returns at once.
require_once __DIR__ . '/../lib/access.php';
$invite_id = access_gate($j);
$fcm   = (string)($j['fcm_token'] ?? '');
// An account is optional: without one the device lives on its own, as before.
// With one the plan comes from the person and survives a reinstall.
$user_id = account_user_id((string)($j['account_token'] ?? ''));

$device_id     = bin2hex(random_bytes(16));
$device_secret = bin2hex(random_bytes(32));

// The owner's name is not sent to the server; it lives inside bundle_cipher.
$st = db()->prepare(
    'INSERT INTO hosts (device_id, user_id, secret_hash, fcm_token, created_at)
     VALUES (?, ?, ?, ?, NOW())'
);
$st->execute([$device_id, $user_id, hash('sha256', $device_secret), $fcm]);
$host_id = (int)db()->lastInsertId();

access_note_use($invite_id, (int)$host_id);

jout([
    'device_id'     => $device_id,
    'device_secret' => $device_secret,
    'host_id'       => $host_id,
    'account'       => $user_id !== null,
]);
