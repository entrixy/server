<?php
/**
 * What this server can do.
 *
 * A client asks before it issues a key: which suite to sign with, whether
 * there is a websocket, whether an access code is expected. The answer is
 * open — there is nothing sensitive in it — and without it a client would only
 * learn about a mismatch from a refusal.
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/suites.php';
rate_limit_check('meta', 60);

$suites = [];
foreach (suite_list() as $id) $suites[$id] = ENTRIXY_SUITES[$id];

jout([
    'software' => 'entrixy',
    'protocol' => [
        'suites'    => array_keys($suites),
        'preferred' => ENTRIXY_SUITE_PREFERRED,
        'detail'    => $suites,
    ],
    'features' => [
        'websocket'   => true,
        'delegation'  => true,
        'access_code' => (bool)($GLOBALS['access_code'] ?? getenv('ACCESS_CODE')),
    ],
]);
