<?php
/**
 * A guest is recognised by a signature, never by the key itself.
 *
 * A signing pair is derived from the key string (Ed25519, seed through HKDF).
 * The public half lives here; the private half never leaves the phone. Every
 * request is signed and the server only checks it.
 *
 * The server accepts no key strings at all, neither at issue nor in use: the
 * string is needed only by whoever opens, and it stays on their phone.
 */

require_once __DIR__ . '/suites.php';

/** The public half, derived from the key string. */
function guest_pub_from_key(string $user_key, string $suite = ENTRIXY_SUITE_PREFERRED): string
{
    if ($suite !== 'v1') throw new RuntimeException('unsupported_suite');
    $seed = hash_hkdf('sha256', $user_key, 32, 'entrixy-guest-sign-v1', '');
    $pair = sodium_crypto_sign_seed_keypair($seed);
    return sodium_crypto_sign_publickey($pair);
}

/** The line the client signs. The body is covered whole, by its hash. */
function guest_sign_material(string $key_id, string $ts, string $nonce,
                             string $endpoint, string $body,
                             string $suite = ENTRIXY_SUITE_PREFERRED): string
{
    return $suite . '.' . $key_id . '.' . $ts . '.' . $nonce . '.' . $endpoint
         . '.' . hash('sha256', $body);
}

/**
 * Checks a guest's request and returns the key's row.
 *
 * A request is recognised by its signature alone: key_id, ts, nonce and sig
 * travel in headers.
 *
 * @return array|null the user_keys row, or null when not recognised.
 */
function guest_auth(array $j, string $endpoint, string $rawBody, ?string &$via = null): ?array
{
    $via = null;
    // The signature travels in headers, not in the body: it covers the body
    // whole, so putting it inside would mean signing itself.
    $key_id = strtolower(trim((string)($_SERVER['HTTP_X_ENTRIXY_KEY'] ?? '')));
    $sig    = (string)($_SERVER['HTTP_X_ENTRIXY_SIG'] ?? '');
    $ts     = (string)($_SERVER['HTTP_X_ENTRIXY_TS'] ?? '');
    $nonce  = (string)($_SERVER['HTTP_X_ENTRIXY_NONCE'] ?? '');
    // The suite name travels in a header and, at the same time, as the first
    // field of the signed material: rewriting it in transit breaks the match.
    $suite  = (string)($_SERVER['HTTP_X_ENTRIXY_SUITE'] ?? ENTRIXY_SUITE_PREFERRED);

    if ($key_id !== '' && $sig !== '') {
        if (!preg_match('/^[a-f0-9]{64}$/', $key_id)) return null;
        if (!suite_known($suite)) return null;
        // A five-minute window and a one-time nonce: someone else's request
        // cannot be repeated, even when it was overheard in full.
        if (!ctype_digit($ts) || abs(time() - (int)$ts) > 300) return null;
        if (!preg_match('/^[a-f0-9]{16,64}$/', $nonce)) return null;

        $st = db()->prepare('SELECT * FROM user_keys WHERE key_hash = ?');
        $st->execute([$key_id]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row || empty($row['sign_pub'])) return null;
        // Once the key has settled on a device, only that device's own pair is
        // accepted. The pair derived from the link is dead from that moment, so
        // a copy of the link that surfaces later opens nothing.
        $pub = !empty($row['sign_pub_device']) ? $row['sign_pub_device'] : $row['sign_pub'];
        $via = !empty($row['sign_pub_device']) ? 'device' : 'link';
        // A key works only under the suite it was issued with: otherwise a key
        // issued under a strong suite could be presented under a weak one.
        $keySuite = (string)($row['sign_suite'] ?? 'v1');
        if ($keySuite !== $suite) return null;

        $raw = base64_decode($sig, true);
        if ($raw === false || strlen($raw) !== 64) return null;
        $material = guest_sign_material($key_id, $ts, $nonce, $endpoint, $rawBody, $suite);
        if (!sodium_crypto_sign_verify_detached($raw, $material, $pub)) {
            // The key has settled on a device, and this is the link's own pair:
            // whoever is asking does hold the link, but on another handset. The
            // caller decides what to say; the request itself goes no further.
            if ($via === 'device'
                && sodium_crypto_sign_verify_detached($raw, $material, $row['sign_pub'])) {
                $via = 'link_elsewhere';
            } else {
                $via = null;
            }
            return null;
        }

        // One use per signature: the same nonce is not accepted twice.
        try {
            db()->prepare('INSERT INTO guest_nonces (key_hash, nonce, used_at) VALUES (?, ?, NOW())')
               ->execute([$key_id, $nonce]);
        } catch (Throwable $e) {
            return null;                      // a repeat — refused
        }
        return $row;
    }

    return null;                          // no signature — not recognised
}
