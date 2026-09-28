<?php
/**
 * A guest's acknowledgement comes in two phases:
 *   kind="delivered" — the push arrived and the client decrypted it. The owner is
 *                      told "message_delivered"; the row still stands.
 *   kind="read"      — the person actually opened the dialogue. The owner is told
 *                      "message_read" and the row is deleted.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/guest_auth.php';
rate_limit_check('message_ack', 300);
$j = jin();
$kind = (string)($j['kind'] ?? 'read');
if (!in_array($kind, ['delivered', 'read'], true)) $kind = 'read';
// Recognised by the signature on the request; see lib/guest_auth.php.
$row = guest_auth($j, 'message_ack', file_get_contents('php://input'));
if (!$row || !(int)$row['enabled']) jout(['error' => 'not_found'], 404);
$ukid = (int)$row['id'];
if (!$ukid) jout(['error' => 'not_found'], 404);

if ($kind === 'read') {
    db()->prepare('DELETE FROM guest_messages WHERE user_key_id = ?')->execute([$ukid]);
}
db()->prepare(
    'INSERT INTO pending_notifications (kind, user_key_id, created_at)
     VALUES (?, ?, NOW())'
)->execute(['message_' . $kind, $ukid]);

jout(['ok' => true]);
