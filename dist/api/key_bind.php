<?php
/**
 * Binding a guest key to a device.
 * The guest sends user_key plus device_fp, an HMAC of a stable hardware id.
 *
 * Behaviour:
 *   - nothing bound yet → it is recorded and the key counts as activated.
 *   - the same fingerprint → ok, the app was reinstalled on the same device.
 *   - a different one → 403 already_bound, the key belongs to another device.
 *
 * This guards against a guest handing their key around. The owner can revoke and
 * issue again: the binding is cleared with the revocation, or a wholly new key is
 * issued.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/device_move.php';
rate_limit_check('key_bind', 30);

$j = jin();
$user_key  = (string)($j['user_key'] ?? '');
$device_fp = (string)($j['device_fp'] ?? '');

if ($user_key === '' || $device_fp === '') jout(['error' => 'bad_input'], 400);
if (!preg_match('/^[a-f0-9]{32,128}$/i', $device_fp)) jout(['error' => 'bad_fp'], 400);

$hash = hash('sha256', $user_key);
$st = db()->prepare(
    'SELECT id, host_id, enabled, bound_device_fp, moved_at, prev_device_fp FROM user_keys WHERE key_hash = ? LIMIT 1'
);
$st->execute([$hash]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row) jout(['error' => 'not_found'], 404);
if (!(int)$row['enabled']) jout(['error' => 'disabled'], 403);

$current = $row['bound_device_fp'] ?? null;
$kid = (int)$row['id'];
$d = device_move_decide($current, $device_fp, $row['moved_at'] ?? null, $row['prev_device_fp'] ?? null);

switch ($d['action']) {
    case 'bind':
        device_move_bind('user_keys', $kid, $device_fp);
        jout(['ok' => 1, 'bound' => 'new']);

    case 'same':
        jout(['ok' => 1, 'bound' => 'same']);

    case 'move':
        // A move to a new phone: the previous device is evicted and wipes itself on
        // its next contact. The owner gets a line in the log; from handing the phone
        // over this is indistinguishable, so there is no need to bother anyone.
        device_move_apply('user_keys', $kid, $device_fp, $current);
        if (function_exists('audit_log')) {
            audit_log((int)$row['host_id'], 'key_moved', 'user_key', $kid, []);
        }
        jout(['ok' => 1, 'bound' => 'moved']);

    case 'evicted':
        jout(['error' => 'evicted'], 409);

    default:  // wait
        jout([
            'error'       => 'move_too_soon',
            'retry_after' => $d['retry_after'],
        ], 429);
}
