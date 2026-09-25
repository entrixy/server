<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_validate', 30);
$j = jin();
$key = (string)($j['user_key'] ?? '');
$device_id = (string)($j['device_id'] ?? '');
$device_secret = (string)($j['device_secret'] ?? '');
if ($key === '') jout(['valid' => 0, 'is_own' => 0]);

$hash = hash('sha256', $key);
$st = db()->prepare('SELECT host_id, enabled FROM user_keys WHERE key_hash = ? LIMIT 1');
$st->execute([$hash]);
$row = $st->fetch(PDO::FETCH_ASSOC);

$isOwn = 0;
if ($row && $device_id !== '') {
    $hst = db()->prepare('SELECT id, secret_hash FROM hosts WHERE device_id = ?');
    $hst->execute([$device_id]);
    $h = $hst->fetch(PDO::FETCH_ASSOC);
    if ($h && hash_equals($h['secret_hash'], hash('sha256', $device_secret))) {
        if ((int)$row['host_id'] === (int)$h['id']) $isOwn = 1;
    }
}

$hostActive = 0;
if ($row) {
    $hst2 = db()->prepare('SELECT last_seen FROM hosts WHERE id = ?');
    $hst2->execute([$row['host_id']]);
    $ls = $hst2->fetchColumn();
    if ($ls && strtotime($ls) > time() - 300) $hostActive = 1; // active within the last 5 minutes
}

jout([
    'valid'       => ($row && $row['enabled']) ? 1 : 0,
    'is_own'      => $isOwn,
    'host_active' => $hostActive,
]);
