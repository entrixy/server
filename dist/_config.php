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
// Seconds of silence after which a controller shows offline.
$GLOBALS['device_offline_s']   = (int)envv('DEVICE_OFFLINE_S', '30');
// The ceiling on requests to one endpoint from one address per minute.
$GLOBALS['requests_per_min']   = (int)envv('REQUESTS_PER_MIN', 300);

$GLOBALS['jwt_secret']        = envv('JWT_SECRET');
$GLOBALS['jwt_ttl']           = 30 * 86400;
// A closed server: while no code is set, anyone may register a device.
$GLOBALS['access_code']     = envv('ACCESS_CODE', '');
// Refuse owner requests that carry no device fingerprint (apps 10.53+ always send one).
$GLOBALS['require_device_fp'] = in_array(strtolower(envv('REQUIRE_DEVICE_FP', '')), ['1', 'true', 'yes'], true);
// Whose page may read this server's answers in a browser. The browser client
// lives at entrixy.com; point this at yourself if you host a copy of it.
$GLOBALS['app_origin']      = envv('APP_ORIGIN', 'https://entrixy.com');
$GLOBALS['app_attest_secret'] = envv('APP_ATTEST_SECRET');



$GLOBALS['fcm_server_key'] = '';                     // push notifications: see the README
$GLOBALS['download_page_url']  = envv('SITE_URL') . '/download';

// The installation's own settings, if this server is not run from containers.
// Anything set here replaces what came from the environment above.
if (is_file(__DIR__ . '/_config.local.php')) {
    require __DIR__ . '/_config.local.php';
}

// A secret copied from the example is public: anyone could sign tokens with it.
// (The database password is not checked: in the Docker stack the database sits
// on the internal network only, and installations have long run with the
// example value.)
if ($GLOBALS['jwt_secret'] === '' || strlen($GLOBALS['jwt_secret']) < 32
    || stripos($GLOBALS['jwt_secret'], 'CHANGE_ME') !== false) {
    $msg = 'JWT_SECRET is not set or still the example value: put 32+ random characters in .env '
         . '(openssl rand -hex 32), or in _config.local.php when running without Docker.';
    // From the command line (installer, worker config): to stderr and a failing
    // status, so the text is never taken for data.
    if (PHP_SAPI === 'cli') { fwrite(STDERR, $msg . "\n"); exit(1); }
    http_response_code(500);
    exit($msg);
}

require __DIR__ . '/_config_functions.php';
