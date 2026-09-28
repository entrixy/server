<?php
/**
 * Configuration for a self-hosted server.
 *
 * Values come from the environment, which is how the containers are given
 * them. An installation without Docker has no such environment, and editing
 * this file would mean the next update overwrites the secrets — so a file
 * beside it, `_config.local.php`, is read afterwards and wins. It is not part
 * of the distribution and is never touched by an update; put the database, the
 * secrets and the address there.
 *
 * The shared functions live beside this file, outside the configuration
 * itself, so the code does not drift between installations.
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
// The ceiling on requests to one endpoint from one address per minute.
$GLOBALS['requests_per_min']   = (int)envv('REQUESTS_PER_MIN', 300);

$GLOBALS['jwt_secret']        = envv('JWT_SECRET');
$GLOBALS['jwt_ttl']           = 30 * 86400;
// A closed server: while no code is set, anyone may register a device.
$GLOBALS['access_code']     = envv('ACCESS_CODE', '');
$GLOBALS['app_attest_secret'] = envv('APP_ATTEST_SECRET');



$GLOBALS['fcm_server_key'] = '';                     // push notifications: see the README
$GLOBALS['download_page_url']  = envv('SITE_URL') . '/download';

// The installation's own settings, if this server is not run from containers.
// Anything set here replaces what came from the environment above.
if (is_file(__DIR__ . '/_config.local.php')) {
    require __DIR__ . '/_config.local.php';
}

if ($GLOBALS['jwt_secret'] === '') {
    http_response_code(500);
    exit('JWT_SECRET is not set: fill in .env, or _config.local.php when running without Docker.');
}

require __DIR__ . '/_config_functions.php';
