<?php
/**
 * Settings for an installation without Docker. Copy to `_config.local.php`
 * next to `_config.php` and fill in. An update never overwrites this file.
 *
 *   cp _config.local.example.php _config.local.php
 *   chmod 600 _config.local.php     # it holds the database password
 *
 * Everything here replaces what the environment would have given.
 */

$GLOBALS['db'] = [
    'host' => '127.0.0.1',
    'name' => 'entrixy',
    'user' => 'entrixy',
    'pass' => '',
];

// The address this server answers on. Links out of it are built from this
// value rather than from the request's Host header, which can be forged.
$GLOBALS['site_host'] = 'gate.example.com';
$GLOBALS['download_page_url'] = 'https://' . $GLOBALS['site_host'] . '/download';

// Two secrets. Generate each once, with `openssl rand -hex 32`, and keep them:
// changing the first signs everyone out, changing the second stops the app
// from proving it is the app.
$GLOBALS['jwt_secret']        = '';
$GLOBALS['app_attest_secret'] = '';

// Who may register a device on this server. Empty means anyone who knows the
// address; set a code, or hand out single-use invitations instead.
$GLOBALS['access_code'] = '';

// The websocket worker listens here, and your web server proxies /ws to it.
$GLOBALS['ws_host'] = '127.0.0.1';
$GLOBALS['ws_port'] = 8095;
