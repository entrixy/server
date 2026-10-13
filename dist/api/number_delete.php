<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('number_delete', 30);
[$host_id, $j] = host_auth();

require_once __DIR__ . '/../lib/key_objects.php';

$id = (int)($j['id'] ?? 0);
$st = db()->prepare('DELETE FROM numbers WHERE id = ? AND host_id = ?');
$st->execute([$id, $host_id]);
$revoked = [];
if ($st->rowCount() > 0) {
    // The keys that held the object lose it the same way as when it is taken
    // out of a key: their bundles are reassembled, an empty key is revoked.
    $had = db()->prepare('SELECT DISTINCT user_key_id FROM key_numbers WHERE number_id = ?');
    $had->execute([$id]);
    $keys = $had->fetchAll(PDO::FETCH_COLUMN);
    db()->prepare('DELETE FROM key_numbers WHERE number_id = ?')->execute([$id]);
    $revoked = key_objects_lost($keys);
}
audit_log($host_id, 'number_delete', 'number', $id);
jout(['ok' => 1, 'revoked' => $revoked]);
