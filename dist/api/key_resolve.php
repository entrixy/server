<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_resolve', 60);

// Looks a key up by user_key for the current host.
// The offline-first client needs it: if key_create answered user_key_collision —
// the key had already been synchronised but the client forgot, after a reinstall
// for instance — resolve tells it the server's id, and local metadata is moved
// under that.
[$host_id, $j] = host_auth();

// By fingerprint here as well: the owner is looking up their own key, and
// there is no reason to show it to the server.
$key_hash = strtolower(trim((string)($j['key_hash'] ?? '')));
if (!preg_match('/^[a-f0-9]{64}$/', $key_hash)) {
    jout(['error' => 'bad_input'], 400);
}

$st = db()->prepare(
    'SELECT id FROM user_keys WHERE host_id = ? AND key_hash = ? LIMIT 1'
);
$st->execute([$host_id, $key_hash]);
$id = (int)($st->fetchColumn() ?: 0);

if ($id === 0) jout(['error' => 'not_found'], 404);
jout(['id' => $id]);
