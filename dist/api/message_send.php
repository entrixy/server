<?php
require __DIR__ . '/_bootstrap.php';
require __DIR__ . '/../lib/fcm.php';

[$host_id, $j] = host_auth();

$user_key_id = (int)($j['user_key_id'] ?? 0);
$cipher      = (string)($j['cipher'] ?? '');

if ($user_key_id <= 0 || $cipher === '') jout(['error' => 'bad_input'], 400);
if (strlen($cipher) > 4096) jout(['error' => 'too_long'], 400);
if (!is_valid_cipher($cipher)) jout(['error' => 'invalid_cipher_format'], 400);

// Check that the user_key belongs to this owner and fetch key_hash, which is also
// the name of the client's topic: topic = "k_$hash".
$st = db()->prepare('SELECT key_hash FROM user_keys WHERE id = ? AND host_id = ?');
$st->execute([$user_key_id, $host_id]);
$keyHash = $st->fetchColumn();
if (!$keyHash) jout(['error' => 'not_found'], 404);

// A single slot in the database: the fallback for websocket delivery, and for a
// failed push.
$st = db()->prepare(
    'INSERT INTO guest_messages (host_id, user_key_id, cipher)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE cipher = VALUES(cipher), created_at = CURRENT_TIMESTAMP'
);
$st->execute([$host_id, $user_key_id, $cipher]);

// A data push to the topic k_<hash>. Clients subscribed to it — every device of
// the guest holding this key — receive it even with the app killed. On receipt
// the client acknowledges, and the worker deletes the row.
$fcmOk = fcm_send_to_topic("k_{$keyHash}", [
    'type'   => 'message',
    'hash'   => $keyHash,
    'cipher' => $cipher,
]);

jout(['ok' => true, 'fcm' => $fcmOk]);
