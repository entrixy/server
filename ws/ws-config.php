<?php
/**
 * Settings for the websocket worker, taken from the server's own configuration.
 *
 * The worker is a separate program and cannot read a PHP file, so the values it
 * needs are written out here as JSON. Running this after a change to the
 * configuration keeps the two halves of the server from disagreeing about the
 * database.
 *
 *   php w/ws-config.php > w/ws-config.json
 */
require __DIR__ . '/../dist/_config.php';

echo json_encode([
    'ws_addr'            => $GLOBALS['ws_host'] . ':' . $GLOBALS['ws_port'],
    'db_host'            => $GLOBALS['db']['host'],
    'db_name'            => $GLOBALS['db']['name'],
    'db_user'            => $GLOBALS['db']['user'],
    'db_pass'            => $GLOBALS['db']['pass'],
    'app_attest_secret'  => $GLOBALS['app_attest_secret'],
    'rate_limit_per_min' => (int)$GLOBALS['rate_limit_per_min'],
    'promo_base_url'     => 'https://entrixy.com',
    'access_code'        => (string)($GLOBALS['access_code'] ?? ''),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
