<?php
// A buyer attaches an unowned, factory-fresh device to their host with the claim
// code printed on the case. Once attached, host_id is set and the code is spent,
// so the device cannot be claimed again. After that the app creates the object in
// the usual way.
require __DIR__ . '/_bootstrap.php';
[$host_id, $j] = host_auth();

// Against guessing the claim code: the space is four bytes, and hammering it is
// not allowed.
rate_limit_check('device_claim', 20);

$code = strtoupper(trim((string)($j['claim_code'] ?? '')));
if ($code === '') jout(['error' => 'bad_input'], 400);

$pdo = db();
$st = $pdo->prepare('SELECT id, label FROM devices WHERE claim_code = ? AND host_id IS NULL');
$st->execute([$code]);
$dev = $st->fetch(PDO::FETCH_ASSOC);
if (!$dev) jout(['error' => 'not_found'], 404);

// Atomic: attach only while it is still unowned, which also settles any race.
$up = $pdo->prepare('UPDATE devices SET host_id = ?, claim_code = NULL WHERE id = ? AND host_id IS NULL');
$up->execute([$host_id, (int)$dev['id']]);
if ($up->rowCount() !== 1) jout(['error' => 'conflict'], 409);

jout(['device_id' => (int)$dev['id'], 'label' => $dev['label']]);
