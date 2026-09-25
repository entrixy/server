<?php
require __DIR__ . '/_bootstrap.php';

// Looks a key up by user_key for the current host.
// The offline-first client needs it: if key_create answered user_key_collision —
// the key had already been synchronised but the client forgot, after a reinstall
// for instance — resolve tells it the server's id, and local metadata is moved
// under that.
[$host_id, $j] = host_auth();

$user_key = (string)($j['user_key'] ?? '');
if (!preg_match('/^[A-Za-z0-9_-]{20,64}$/', $user_key)) {
    jout(['error' => 'bad_input'], 400);
}

$st = db()->prepare(
    'SELECT id FROM user_keys WHERE host_id = ? AND key_hash = ? LIMIT 1'
);
$st->execute([$host_id, hash('sha256', $user_key)]);
$id = (int)($st->fetchColumn() ?: 0);

if ($id === 0) jout(['error' => 'not_found'], 404);
jout(['id' => $id]);
