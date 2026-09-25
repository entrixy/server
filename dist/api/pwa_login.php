<?php
require __DIR__ . '/_bootstrap.php';
rate_limit_check('pwa_login', 60);

$j = jin();
$email = strtolower(trim((string)($j['email'] ?? '')));
$pass  = (string)($j['password'] ?? '');

if ($email === '' || $pass === '') jout(['error' => 'missing_fields'], 400);

/* A per-address limit does not stop guessing: addresses change more often than
   passwords. So failures are counted per account as well, wherever they come
   from. A successful sign-in clears the counter. */
$emailKey = 'pwa_login_fail:' . hash_hmac('sha256', $email, (string)$GLOBALS['jwt_secret']);
if (function_exists('apcu_fetch')) {
    $fails = (int)apcu_fetch($emailKey);
    if ($fails >= 10) jout(['error' => 'throttled', 'retry_after' => 900], 429);
}

$st = db()->prepare('SELECT id, password_hash, sess_ver FROM users WHERE email = ?');
$st->execute([$email]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row || !password_verify($pass, $row['password_hash'])) {
    if (function_exists('apcu_inc')) {
        apcu_add($emailKey, 0, 900);   // a 15 minute window
        apcu_inc($emailKey);
    }
    jout(['error' => 'invalid_credentials'], 401);
}
if (function_exists('apcu_delete')) apcu_delete($emailKey);

// sv is the session version: changing the password bumps it and kills old tokens.
$token = jwt_encode(['uid' => (int)$row['id'], 'email' => $email, 'sv' => (int)($row['sess_ver'] ?? 0)]);
jout(['ok' => 1, 'token' => $token, 'email' => $email]);
