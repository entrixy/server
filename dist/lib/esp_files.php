<?php
/* Built firmware and its source carry the Wi-Fi password and the device code.
   They are not served as static files: a link is signed and lives an hour, so a
   link left in a history, a log or a screenshot opens nothing later. */

function esp_file_sig(string $name, int $exp): string {
    // jwt_secret signs the links. The config is loaded late and only if nobody
    // has yet: some callers include it with a plain require, and a second load
    // would redeclare its functions.
    if (empty($GLOBALS['jwt_secret'])) require_once __DIR__ . '/../_config.php';
    return substr(hash_hmac('sha256', "esp-file|$name|$exp", (string)($GLOBALS['jwt_secret'] ?? '')), 0, 32);
}

function esp_file_url(string $name): string {
    $exp = time() + 3600;
    return '/api/esp_file.php?f=' . rawurlencode($name) . '&e=' . $exp . '&s=' . esp_file_sig($name, $exp);
}

/* Output filter for the build endpoints: every /esp/cache/<file> in the JSON
   becomes a signed link. */
function esp_sign_output(string $buf): string {
    return preg_replace_callback('#\\\\?/esp\\\\?/cache\\\\?/([0-9a-f]{16}_[A-Za-z0-9._-]+)#', function ($m) {
        return str_replace('/', '\\/', esp_file_url($m[1]));
    }, $buf);
}
