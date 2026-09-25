<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_check', 300);

[$host_id, $j] = host_auth();
$key = (string)($j['user_key'] ?? '');
if ($key === '') jout(['error' => 'bad_input'], 400);

$hash = hash('sha256', $key);
$st = db()->prepare('SELECT host_id FROM user_keys WHERE key_hash = ? LIMIT 1');
$st->execute([$hash]);
$row = $st->fetch(PDO::FETCH_ASSOC);

jout([
    'ok' => 1,
    'exists' => $row ? 1 : 0,
    'is_own' => ($row && (int)$row['host_id'] === (int)$host_id) ? 1 : 0,
]);
