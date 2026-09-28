<?php
/**
 * Push through FCM HTTP v1, authorised by a service account (OAuth2 JWT bearer).
 *
 * Only a data payload is used, so that Android always wakes our messaging service
 * and lets it decide how to show the message, since the ciphertext has to be
 * decrypted first. A notification payload is never sent: the system would show it
 * before decryption, with unreadable text.
 *
 * The access token is cached in APCu for an hour, matching Google's own lifetime.
 */

function fcm_sa_path(): string {
    return getenv('FCM_SA_FILE') ?: '/app/secrets/fcm-service-account.json';
}

function fcm_get_access_token(): ?string {
    static $cached = null;
    static $expiry = 0;
    if ($cached !== null && time() < $expiry - 60) return $cached;

    $raw = @file_get_contents(fcm_sa_path());
    if (!$raw) return null;
    $sa = json_decode($raw, true);
    if (!$sa || empty($sa['client_email']) || empty($sa['private_key'])) return null;

    $now = time();
    $header = ['alg' => 'RS256', 'typ' => 'JWT'];
    $claims = [
        'iss'   => $sa['client_email'],
        'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
        'aud'   => 'https://oauth2.googleapis.com/token',
        'iat'   => $now,
        'exp'   => $now + 3600,
    ];
    $b64 = fn($s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    $signingInput = $b64(json_encode($header)) . '.' . $b64(json_encode($claims));
    $signature = '';
    if (!openssl_sign($signingInput, $signature, $sa['private_key'], 'SHA256')) return null;
    $jwt = $signingInput . '.' . $b64($signature);

    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => $jwt,
        ]),
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200) return null;
    $j = json_decode($resp, true);
    if (!$j || empty($j['access_token'])) return null;
    $cached = $j['access_token'];
    $expiry = $now + (int)($j['expires_in'] ?? 3600);
    return $cached;
}

/**
 * Sends a data push to an FCM topic.
 * Returns true on HTTP 200, false otherwise.
 */
function fcm_send_to_topic(string $topic, array $data): bool {
    $token = fcm_get_access_token();
    if (!$token) return false;

    $raw = @file_get_contents(fcm_sa_path());
    $sa = $raw ? json_decode($raw, true) : null;
    if (!$sa || empty($sa['project_id'])) return false;
    $projectId = $sa['project_id'];

    // FCM HTTP v1 requires every data value to be a string.
    $strData = [];
    foreach ($data as $k => $v) $strData[(string)$k] = (string)$v;

    $body = [
        'message' => [
            'topic'    => $topic,
            'data'     => $strData,
            'android'  => [
                'priority' => 'high',
            ],
        ],
    ];
    $ch = curl_init("https://fcm.googleapis.com/v1/projects/{$projectId}/messages:send");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($body, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200) {
        @error_log("FCM send failed http=$code body=$resp topic=$topic");
    }
    return $code === 200;
}
