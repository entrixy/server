<?php
require __DIR__ . '/_bootstrap.php';
[$host_id, $j] = host_auth();

$id = (int)($j['id'] ?? 0);
$mode = (string)($j['mode'] ?? '');
if (!in_array($mode, ['off', 'auto', 'notify', 'confirm'], true)) {
    jout(['error' => 'bad_mode'], 400);
}

$st = db()->prepare('UPDATE user_keys SET mode = ? WHERE id = ? AND host_id = ?');
$st->execute([$mode, $id, $host_id]);

db()->prepare(
    'INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?, ?, NOW())'
)->execute(['key_mode_changed', $id]);

audit_log($host_id, 'key_set_mode', 'user_key', $id, ['mode' => $mode]);

jout(['ok' => 1]);
