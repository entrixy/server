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
require_once __DIR__ . '/../lib/guest_auth.php';
rate_limit_check('key_bind', 30);

$j = jin();
$device_fp = (string)($j['device_fp'] ?? '');
if ($device_fp === '') jout(['error' => 'bad_input'], 400);
if (!preg_match('/^[a-f0-9]{32,128}$/i', $device_fp)) jout(['error' => 'bad_fp'], 400);

// The device's own public half, if the client has one. From the moment it is
// stored, the pair derived from the link stops being accepted anywhere: a copy
// of the link that surfaces later opens nothing, and the binding stops being a
// string the server compares and becomes something only this phone can produce.
$device_pub_in = (string)($j['device_pub'] ?? '');
$device_pub = null;
if ($device_pub_in !== '') {
    $device_pub = base64_decode(strtr($device_pub_in, '-_', '+/'), true);
    if ($device_pub === false || strlen($device_pub) !== 32) jout(['error' => 'bad_device_pub'], 400);
}

// Who is asking is told by the signature; the server never sees the key.
$via = null;
$who = guest_auth($j, 'key_bind', file_get_contents('php://input'), $via);
if (!$who) {
    // The link is genuine, but the key has already settled on another handset
    // and does not travel. Said plainly, so the app asks for a new key instead
    // of deciding the key is dead.
    if ($via === 'link_elsewhere') jout(['error' => 'needs_new_key'], 409);
    jout(['error' => 'bad_key'], 403);
}
$st = db()->prepare(
    'SELECT id, host_id, enabled, bound_device_fp, moved_at, prev_device_fp, sign_pub_device
       FROM user_keys WHERE id = ? LIMIT 1'
);
$st->execute([(int)$who['id']]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row) jout(['error' => 'not_found'], 404);
if (!(int)$row['enabled']) jout(['error' => 'disabled'], 403);

$current = $row['bound_device_fp'] ?? null;
$kid = (int)$row['id'];
$d = device_move_decide($current, $device_fp, $row['moved_at'] ?? null, $row['prev_device_fp'] ?? null);

/** Remember the device's own pair, once, at the moment it settles here. */
$remember_pub = function () use ($device_pub, $kid) {
    if ($device_pub === null) return;
    db()->prepare('UPDATE user_keys SET sign_pub_device = ? WHERE id = ?')
       ->execute([$device_pub, $kid]);
};

switch ($d['action']) {
    case 'bind':
        device_move_bind('user_keys', $kid, $device_fp);
        $remember_pub();
        jout(['ok' => 1, 'bound' => 'new', 'device_key' => $device_pub !== null]);

    case 'same':
        // The same phone after a reinstall: it derives the same pair from the
        // key and its own hardware, so there is nothing to replace.
        $remember_pub();
        jout(['ok' => 1, 'bound' => 'same', 'device_key' => $device_pub !== null]);

    case 'move':
        // A key belongs to the device that used it first, and it does not
        // travel: a browser, a phone, another phone — whichever came first
        // keeps it. Whoever arrives second is told so plainly, and the owner
        // issues them a key of their own. Letting the second device take over
        // would mean a copy of the link is enough to walk in.
        jout(['error' => 'already_bound'], 403);

    case 'evicted':
        jout(['error' => 'evicted'], 409);

    default:
        // A key that moved once, long ago, and is asked for again: the same
        // answer as any second device gets.
        jout(['error' => 'already_bound'], 403);
}
