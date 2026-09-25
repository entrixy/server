<?php
/**
 * A request to move: "I restored a backup and I am taking over."
 *
 * Asked BEFORE the app applies the backup. The server either allows it — the
 * previous handset is then evicted and wipes itself at its first contact — or
 * refuses, if the window between moves has not passed. A refusal means the backup
 * is not applied on this phone at all: otherwise the limit would mean nothing,
 * since calls and Bluetooth work without the server.
 *
 * The identifiers come from the backup itself, so the request can be made by
 * whoever holds the file and its password.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/device_move.php';
rate_limit_check('host_claim', 20);

$j         = jin();
$device_id = (string)($j['device_id'] ?? '');
$secret    = (string)($j['device_secret'] ?? '');
$fp        = (string)($j['device_fp'] ?? '');

if ($device_id === '' || $secret === '') jout(['error' => 'bad_input'], 400);
if (!preg_match('/^[a-f0-9]{32,128}$/i', $fp)) jout(['error' => 'bad_fp'], 400);

$st = db()->prepare(
    'SELECT id, secret_hash, bound_device_fp, moved_at, prev_device_fp FROM hosts WHERE device_id = ?'
);
$st->execute([$device_id]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row || !hash_equals($row['secret_hash'], hash('sha256', $secret))) {
    jout(['error' => 'auth'], 401);
}

$cur = $row['bound_device_fp'] ?? null;
$hid = (int)$row['id'];

// The same handset: nowhere to move, simply allow it.
if ($fp !== '' && $cur !== null && $cur !== '' && hash_equals($cur, $fp)) {
    jout(['ok' => 1, 'claim' => 'same']);
}

// Nothing was bound yet: the first handset, the window is not spent.
if ($cur === null || $cur === '') {
    device_move_bind('hosts', $hid, $fp);
    jout(['ok' => 1, 'claim' => 'bound']);
}

// A change of handset: the window is measured from the previous move.
$last  = !empty($row['moved_at']) ? strtotime($row['moved_at']) : 0;
$since = time() - $last;
if ($last > 0 && $since < MOVE_COOLDOWN) {
    jout([
        'error'       => 'move_too_soon',
        'retry_after' => MOVE_COOLDOWN - $since,
    ], 429);
}

device_move_apply('hosts', $hid, $fp, $cur);
audit_log($hid, 'host_moved', 'host', $hid, []);
jout(['ok' => 1, 'claim' => 'moved']);
