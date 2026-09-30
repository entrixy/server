<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_revoke', 60);
require_once __DIR__ . '/../lib/key_tree.php';   // the cascade
[$host_id, $j] = host_auth();

$id = (int)($j['id'] ?? 0);
$st = db()->prepare('SELECT id FROM user_keys WHERE id = ? AND host_id = ?');
$st->execute([$id, $host_id]);
if (!$st->fetchColumn()) jout(['error' => 'not_found'], 404);

$tree = key_revoke_tree($id);

audit_log($host_id, 'key_revoke', 'user_key', $id, ['cascade' => $tree]);
jout(['ok' => 1, 'revoked' => $tree]);
