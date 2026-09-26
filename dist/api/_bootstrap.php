<?php
require __DIR__ . '/../_config.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store, must-revalidate');

function jin() {
    $raw = file_get_contents('php://input');
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}
function jout($a, $code = 200) {
    http_response_code($code);
    echo json_encode($a, JSON_UNESCAPED_UNICODE);
    exit;
}
/**
 * A per-address, per-bucket rate limit in APCu, over a one-minute window.
 * Throws 429 past $limitPerMin. If APCu is unavailable it does nothing, so the
 * endpoint keeps working.
 */
function rate_limit_check(string $bucketKey, ?int $limitPerMin = null): void {
    $limitPerMin = $limitPerMin ?? (int)($GLOBALS['requests_per_min'] ?? 300);
    if (!function_exists('apcu_inc')) return;
    $ipH = client_ip_hash();
    if ($ipH === '') return;
    $window = intval(time() / 60);
    $key = "rl:{$bucketKey}:{$ipH}:{$window}";
    apcu_add($key, 0, 120);
    $count = apcu_inc($key);
    if ($count !== false && $count > $limitPerMin) {
        jout(['error' => 'rate_limit', 'retry_after' => 60 - (time() % 60)], 429);
    }
}

/**
 * HMAC-SHA256 of the client address with jwt_secret. The server stores no plain
 * address: every "same client" check — invitation pickup, audit — compares
 * hashes. Without the secret the hash cannot be reversed.
 */
function client_ip_hash(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($ip === '') return '';
    $k = $GLOBALS['jwt_secret'] ?? '';
    return hash_hmac('sha256', $ip, $k);
}

/**
 * A sanity check for encrypted blobs: data_cipher, bundle_cipher, a message
 * cipher. The format is "v1:<base64url>", where the raw bytes are a 12-byte nonce
 * plus ciphertext plus a 16-byte tag, at least 28 bytes in all. It catches
 * accidental plaintext when a client forgot to encrypt. Returns true when the
 * value is valid OR empty.
 */
function is_valid_cipher(?string $blob): bool {
    if ($blob === null || $blob === '') return true;
    if (!str_starts_with($blob, 'v1:')) return false;
    $b64 = substr($blob, 3);
    if (strlen($b64) > 200000) return false; // ~150 KB, far beyond any sensible blob
    $raw = base64_decode(strtr($b64, '-_', '+/'), true);
    if ($raw === false) return false;
    return strlen($raw) >= 28;
}

/**
 * The audit log: one row in audit_log. It never throws — an exception here is
 * swallowed, because auditing must not break the logic it is watching.
 */
function audit_log(?int $hostId, string $action, string $targetType, ?int $targetId = null, array $payload = []): void {
    try {
        $st = db()->prepare(
            'INSERT INTO audit_log (host_id, action, target_type, target_id, payload, ip)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        // The address is not kept in the log. A fingerprint alone says little, but
        // next to a timestamp it becomes a record of who did what and when: a person
        // could be matched to activity if the database leaked together with the
        // secret. It is not needed for the work — access is checked by the device's
        // credentials, not by its address.
        $st->execute([
            $hostId, $action, $targetType, $targetId,
            $payload ? json_encode($payload, JSON_UNESCAPED_UNICODE) : null,
            null,
        ]);
    } catch (\Throwable $e) {}
}

function host_auth() {
    $j = jin();
    $device_id = (string)($j['device_id'] ?? '');
    $secret    = (string)($j['device_secret'] ?? '');
    if ($device_id === '' || $secret === '') jout(['error' => 'auth'], 401);
    $st = db()->prepare('SELECT id, secret_hash, bound_device_fp, moved_at, prev_device_fp FROM hosts WHERE device_id = ?');
    $st->execute([$device_id]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row || !hash_equals($row['secret_hash'], hash('sha256', $secret))) {
        jout(['error' => 'auth'], 401);
    }

    // An owner's device: a host holds exactly one. An app that knows how to move
    // sends device_fp; older versions do not, and then the check simply does not
    // apply.
    $fp = (string)($j['device_fp'] ?? '');
    if ($fp !== '' && preg_match('/^[a-f0-9]{32,128}$/i', $fp)) {
        require_once __DIR__ . '/../lib/device_move.php';
        $cur = $row['bound_device_fp'] ?? null;
        $d = device_move_decide($cur, $fp, $row['moved_at'] ?? null, $row['prev_device_fp'] ?? null);
        if ($d['action'] === 'bind') {
            device_move_bind('hosts', (int)$row['id'], $fp);
            $row['bound_device_fp'] = $fp;          // otherwise the check below would see the old one
        } elseif ($d['action'] === 'move') {
            device_move_apply('hosts', (int)$row['id'], $fp, $cur);
            $row['bound_device_fp'] = $fp;
        } elseif ($d['action'] === 'wait') {
            jout(['error' => 'move_too_soon', 'retry_after' => $d['retry_after']], 429);
        } elseif ($d['action'] === 'evicted') {
            jout(['error' => 'evicted'], 409);
        }
    } elseif (!empty($row['bound_device_fp']) && $fp !== '') {
        jout(['error' => 'bad_fp'], 400);
    }

    // An evicted handset learns of it here: on 'evicted' the app wipes its storage
    // and is left bare.
    if ($fp !== '' && device_is_evicted($row['bound_device_fp'] ?? null, $fp)) {
        jout(['error' => 'evicted'], 409);
    }

    return [(int)$row['id'], $j];
}

/**
 * A baseline for every endpoint, applied the moment this file is included.
 *
 * Explicit rate_limit_check() calls stay where they are and keep the sensitive
 * points tighter; this is the floor under everything else, so that a new
 * endpoint is never born without a limit. The bucket is the script's own name,
 * the ceiling comes from REQUESTS_PER_MIN.
 */
rate_limit_check('ep:' . basename((string)($_SERVER['SCRIPT_FILENAME'] ?? 'api')));
