<?php
// Shared configuration functions.
function jwt_encode(array $payload): string {
    $header = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload['exp'] = $payload['exp'] ?? time() + $GLOBALS['jwt_ttl'];
    $body = base64url_encode(json_encode($payload));
    $sig = base64url_encode(hash_hmac('sha256', "$header.$body", $GLOBALS['jwt_secret'], true));
    return "$header.$body.$sig";
}

function jwt_decode(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $sig = base64url_encode(hash_hmac('sha256', "$parts[0].$parts[1]", $GLOBALS['jwt_secret'], true));
    if (!hash_equals($sig, $parts[2])) return null;
    $payload = json_decode(base64url_decode($parts[1]), true);
    if (!is_array($payload)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}

/* An SSRF shield for the server-side webhook. The owner sets an arbitrary URL and
   the worker fires it, so without a filter it could be aimed at 127.0.0.1, at the
   cloud metadata address 169.254.169.254, or into the private network of the
   machine. Loopback, private and reserved ranges are blocked, and the name is
   resolved so the check cannot be sidestepped with a domain pointing at a private
   address. */
function ssrf_host_blocked(?string $host): bool
{
    $host = trim((string)$host);
    if ($host === '') return true;
    $host = trim($host, '[]');                 // IPv6 in brackets
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips = [$host];
    } else {
        // gethostbynamel sees IPv4 only. A name with an IPv6 address would pass the
        // fourth-version check while the connection went out over the sixth, straight
        // into the private network. So both record types are asked for.
        $ips = @gethostbynamel($host) ?: [];
        $aaaa = @dns_get_record($host, DNS_AAAA) ?: [];
        foreach ($aaaa as $rec) {
            if (!empty($rec['ipv6'])) $ips[] = $rec['ipv6'];
        }
    }
    if (!$ips) return true;                     // does not resolve: not allowed out
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP,
              FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return true;
    }
    return false;
}

function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function base64url_decode(string $data): string {
    return base64_decode(strtr($data, '-_', '+/'));
}





/** Checks the JWT in the Authorization: Bearer header, returning the user id or
 *  answering 401. */
function pwa_auth(): int {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($h, 'Bearer ')) $token = substr($h, 7);
    else $token = (jin())['token'] ?? '';
    $p = jwt_decode($token);
    if (!$p || !isset($p['uid'])) jout(['error' => 'auth'], 401);
    // Changing a password bumps users.sess_ver, as it does for site sessions.
    // Without this check a stolen token would live its full thirty days even after
    // the password had been changed.
    $st = db()->prepare('SELECT sess_ver FROM users WHERE id = ? LIMIT 1');
    $st->execute([(int)$p['uid']]);
    $sv = $st->fetchColumn();
    if ($sv === false) jout(['error' => 'auth'], 401);
    if ((int)$sv !== (int)($p['sv'] ?? -1)) jout(['error' => 'auth'], 401);
    return (int)$p['uid'];
}

function db() {
    static $pdo = null;
    if ($pdo === null) {
        $c = $GLOBALS['db'];
        $pdo = new PDO(
            "mysql:host={$c['host']};dbname={$c['name']};charset=utf8mb4",
            $c['user'], $c['pass'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
        );
    }
    return $pdo;
}

