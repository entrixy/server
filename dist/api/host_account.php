<?php
/**
 * Attaching an already registered device to an account, and detaching it.
 *
 * For those who used the app first and created an account later: registering
 * again would create a new device and lose the access it holds. Detaching returns
 * the device to its own plan.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/account.php';
rate_limit_check('host_account', 20);

[$host_id, $j] = host_auth();    // checks device_id and device_secret
$token = (string)($j['account_token'] ?? '');

$st = db()->prepare('SELECT user_id FROM hosts WHERE id = ?');
$st->execute([$host_id]);
$current = $st->fetchColumn();
$current = $current !== false && $current !== null ? (int)$current : null;

if ($token === '') {
    // An empty token means detach: the plan comes from the device again.
    db()->prepare('UPDATE hosts SET user_id = NULL WHERE id = ?')->execute([$host_id]);
    if ($current !== null) audit_log($host_id, 'host_account_unlinked', 'host', $host_id, []);
    jout(['ok' => 1, 'account' => null]);
}

$uid = account_user_id($token);
if ($uid === null) jout(['error' => 'account_auth'], 401);

/* A device already attached to another person cannot be taken over. Otherwise
   whoever obtained the device's credentials could quietly move it to their own
   account: that gives away no access, but the phone would start counting against
   a stranger's plan and appear in their list. Detaching from the other side comes
   first — and only the phone itself can do that. */
if ($current !== null && $current !== $uid) {
    jout(['error' => 'already_linked'], 409);
}

db()->prepare('UPDATE hosts SET user_id = ? WHERE id = ?')->execute([$uid, $host_id]);
$st = db()->prepare('SELECT email FROM users WHERE id = ?');
$st->execute([$uid]);
$email = (string)($st->fetchColumn() ?: '');

audit_log($host_id, 'host_account_linked', 'host', $host_id, []);
jout(['ok' => 1, 'account' => $email]);
