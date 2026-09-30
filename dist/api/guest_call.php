<?php
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/guest_auth.php';
/* The per-key counter below limits the key's holder, but not someone hammering
   the endpoint with other people's or invented keys: every such request hits the
   database. So there is a per-address limit too, a generous one: thousands of
   subscribers sit behind one carrier address, and a strict cap would cut off the
   neighbours along with the bot. */
rate_limit_check('guest_call', 300);

$j = jin();
$number_id = (int)($j['number_id'] ?? 0);
if ($number_id <= 0) jout(['error' => 'bad_input'], 400);

// Who is asking is settled by the signature on the request.
$who = guest_auth($j, 'guest_call', file_get_contents('php://input'));
if (!$who) jout(['error' => 'bad_key'], 403);
$st = db()->prepare(
    'SELECT uk.id AS user_key_id, uk.host_id
     FROM user_keys uk
     JOIN key_numbers kn ON kn.user_key_id = uk.id
     WHERE uk.id = ? AND uk.enabled = 1 AND kn.number_id = ?
       AND uk.org_id IS NULL
       -- An "app only" object opens only through the live connection of the app,
       -- which proves it is the app; this plain request cannot.
       AND kn.native_only = 0
       AND (uk.expires_at IS NULL OR uk.expires_at > NOW())'
);
$st->execute([(int)$who['id'], $number_id]);
$row = $st->fetch(PDO::FETCH_ASSOC);
if (!$row) jout(['error' => 'forbidden'], 403);

$st = db()->prepare(
    'SELECT COUNT(*) FROM call_log
     WHERE user_key_id = ? AND ts > DATE_SUB(NOW(), INTERVAL 1 MINUTE)'
);
$st->execute([$row['user_key_id']]);
if ((int)$st->fetchColumn() >= $GLOBALS['rate_limit_per_min']) {
    jout(['error' => 'rate_limit'], 429);
}

// The phone number is not on the server; the owner resolves it locally.
db()->prepare(
    'INSERT INTO pending_actions (host_id, number_id, user_key_id, source, created_at)
     VALUES (?, ?, ?, ?, NOW())'
)->execute([$row['host_id'], $number_id, $row['user_key_id'], 'guest_geo']);

db()->prepare(
    'INSERT INTO call_log (user_key_id, number_id, ts, status)
     VALUES (?, ?, NOW(), ?)'
)->execute([$row['user_key_id'], $number_id, 'requested_geo']);

jout(['ok' => 1]);
