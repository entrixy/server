<?php
/**
 * A guest's acknowledgement comes in two phases:
 *   kind="delivered" — the push arrived and the client decrypted it. The owner is
 *                      told "message_delivered"; the row still stands.
 *   kind="read"      — the person actually opened the dialogue. The owner is told
 *                      "message_read" and the row is deleted.
 *   kind="read"      — the person actually opened the dialogue. The owner is told
 *                      "message_read" and the row is deleted.
 */
require __DIR__ . '/_bootstrap.php';
rate_limit_check('message_ack', 300);
$j = jin();
$user_key = (string)($j['user_key'] ?? '');
$kind = (string)($j['kind'] ?? 'read');
if (!in_array($kind, ['delivered', 'read'], true)) $kind = 'read';
if ($user_key === '') jout(['error' => 'bad_input'], 400);

$hash = hash('sha256', $user_key);
$st = db()->prepare('SELECT id FROM user_keys WHERE key_hash = ? AND enabled = 1');
$st->execute([$hash]);
$ukid = (int)$st->fetchColumn();
if (!$ukid) jout(['error' => 'not_found'], 404);

if ($kind === 'read') {
    db()->prepare('DELETE FROM guest_messages WHERE user_key_id = ?')->execute([$ukid]);
}
db()->prepare(
    'INSERT INTO pending_notifications (kind, user_key_id, created_at)
     VALUES (?, ?, NOW())'
)->execute(['message_' . $kind, $ukid]);

jout(['ok' => true]);
