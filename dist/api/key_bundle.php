<?php
/**
 * Hands a guest their encrypted bundle, looked up by their user_key.
 * bundle_cipher is an opaque blob the server does not read.
 * No host authentication here: a guest is not registered as a host.
 *
 * Rate limiting is left to the common layer, see _bootstrap.php.
 */
require __DIR__ . '/_bootstrap.php';
rate_limit_check('key_bundle', 30);

$j = jin();
$user_key = (string)($j['user_key'] ?? '');
if ($user_key === '') jout(['error' => 'bad_input'], 400);

$hash = hash('sha256', $user_key);
$st = db()->prepare(
    'SELECT id, enabled, native_only, parent_key_id, delegate_depth, key_cipher,
            bundle_cipher, bundle_cipher_updated
     FROM user_keys WHERE key_hash = ? LIMIT 1'
);
$st->execute([$hash]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row) jout(['error' => 'not_found'], 404);
if (!(int)$row['enabled']) jout(['error' => 'disabled'], 403);

jout([
    'bundle_cipher' => $row['bundle_cipher'],
    'bundle_cipher_ts' => $row['bundle_cipher_updated'],
    'native_only' => (int)$row['native_only'] === 1,
    // How many further steps this key may be passed along.
    'delegate_depth' => (int)$row['delegate_depth'],
    // The bundle key, encrypted with this recipient's public key.
    'key_cipher' => $row['key_cipher'],
    // A key received down a chain waits for the object's owner to assemble a bundle.
    'state' => ($row['bundle_cipher'] === null && $row['parent_key_id'] !== null)
        ? 'awaiting_owner' : 'ready',
]);
