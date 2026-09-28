<?php
/**
 * Is this server alive, and is the database with it.
 *
 * Meant for a monitor and for the first minute after an installation, when the
 * question is simply whether the thing works. It says nothing that would help
 * a stranger: a version, a yes or no about the database, and the time.
 */
require __DIR__ . '/_bootstrap.php';
rate_limit_check('health', 60);

$dbOk = false;
try {
    $dbOk = (bool)db()->query('SELECT 1')->fetchColumn();
} catch (Throwable $e) {
    $dbOk = false;
}

$version = 'source';
$vf = dirname(__DIR__) . '/VERSION';
if (is_file($vf)) $version = trim((string)@file_get_contents($vf));

http_response_code($dbOk ? 200 : 503);
jout([
    'status'   => $dbOk ? 'ok' : 'degraded',
    'database' => $dbOk,
    'version'  => $version,
    'time'     => gmdate('c'),
]);
