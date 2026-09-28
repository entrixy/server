<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_check', 300);

[$host_id, $j] = host_auth();
// The owner asks by fingerprint: the server does not need the key even here.
$hash = strtolower(trim((string)($j['key_hash'] ?? '')));
if (!preg_match('/^[a-f0-9]{64}$/', $hash)) jout(['error' => 'bad_input'], 400);
$st = db()->prepare('SELECT host_id FROM user_keys WHERE key_hash = ? LIMIT 1');
$st->execute([$hash]);
$row = $st->fetch(PDO::FETCH_ASSOC);

jout([
    'ok' => 1,
    'exists' => $row ? 1 : 0,
    'is_own' => ($row && (int)$row['host_id'] === (int)$host_id) ? 1 : 0,
]);
