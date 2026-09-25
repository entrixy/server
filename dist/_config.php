<?php
/**
 * Configuration for a self-hosted server: the values come from .env. The shared
 * functions live beside this file, outside the configuration itself, so the code
 * does not drift between installations.
 */
function envv(string $key, string $default = ''): string {
    $v = getenv($key);
    return ($v === false || $v === '') ? $default : $v;
}

$GLOBALS['db'] = [
    'host' => envv('DB_HOST', 'db'),
    'name' => envv('DB_NAME', 'entrixy'),
    'user' => envv('DB_USER', 'entrixy'),
    'pass' => envv('DB_PASS'),
];

$GLOBALS['ws_host'] = envv('WS_HOST', '0.0.0.0');
$GLOBALS['ws_port'] = (int)envv('WS_PORT', '8095');

$GLOBALS['rate_limit_per_min'] = (int)envv('RATE_LIMIT_PER_MIN', '60');

$GLOBALS['jwt_secret']        = envv('JWT_SECRET');
$GLOBALS['jwt_ttl']           = 30 * 86400;
// A closed server: while no code is set, anyone may register a device.
$GLOBALS['access_code']     = envv('ACCESS_CODE', '');
$GLOBALS['app_attest_secret'] = envv('APP_ATTEST_SECRET');



$GLOBALS['fcm_server_key'] = '';                     // push notifications: see the README
$GLOBALS['download_page_url']  = envv('SITE_URL') . '/download';

if ($GLOBALS['jwt_secret'] === '') {
    http_response_code(500);
    exit('JWT_SECRET is not set: fill in .env before starting.');
}

require __DIR__ . '/_config_functions.php';
