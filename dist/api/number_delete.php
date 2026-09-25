<?php
require __DIR__ . '/_bootstrap.php';
[$host_id, $j] = host_auth();

$id = (int)($j['id'] ?? 0);
$st = db()->prepare('DELETE FROM numbers WHERE id = ? AND host_id = ?');
$st->execute([$id, $host_id]);
db()->prepare('DELETE FROM key_numbers WHERE number_id = ?')->execute([$id]);
audit_log($host_id, 'number_delete', 'number', $id);
jout(['ok' => 1]);
