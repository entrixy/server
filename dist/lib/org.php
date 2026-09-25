<?php
// Helpers for companies. The application and the profile live in the `orgs`
// table. In the interface this is a "company"; in the code it is an org.

/** A user's company application or profile, or null. */
function org_row(int $userId): ?array {
    $st = db()->prepare('SELECT * FROM orgs WHERE user_id = ? LIMIT 1');
    $st->execute([$userId]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}

/** An active company, not blocked. There is no moderation: a registration is
    live at once. */
function org_active(int $userId): ?array {
    $o = org_row($userId);
    return ($o && $o['status'] !== 'blocked') ? $o : null;
}

/** The domain is tied to the company cryptographically: a domain plus a live key from it. */
function org_domain_verified(array $o): bool {
    return !empty($o['domain']) && !empty($o['pubkey']);
}

/**
 * Fetches a company's key from its domain: https://<domain>/.well-known/entrixy.json
 * holding {"key":"<32 bytes of Ed25519 in base64>"}. One file does two jobs: it
 * proves ownership of the domain, through TLS and its contents, and it hands over
 * the key that signs EVERY later request. There is no one-off "domain verified"
 * tick here: if the file disappears or the domain moves, signatures stop being
 * accepted at the next check.
 */
function org_fetch_pubkey(string $domain): ?string {
    return org_fetch_pubkey_ex($domain)[0];
}

/**
 * The same, but with a reason for the refusal, which is shown to the company.
 * To someone who has just published the file, "could not read it" says nothing:
 * a 404, a self-signed certificate and a key of the wrong length are different
 * failures calling for different actions.
 *
 * Returns [key|null, reason]: ok | bad_domain | blocked | unreachable |
 * http_<code> | not_json | no_key | bad_key
 */
function org_fetch_pubkey_ex(string $domain): array {
    $domain = strtolower(trim($domain));
    if (!preg_match('/^[a-z0-9.-]{4,190}$/', $domain)) return [null, 'bad_domain'];
    if (function_exists('ssrf_host_blocked') && ssrf_host_blocked($domain)) return [null, 'blocked'];
    $ctx = stream_context_create([
        'http' => ['timeout' => 5, 'follow_location' => 0, 'ignore_errors' => true],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);
    $body = @file_get_contents('https://' . $domain . '/.well-known/entrixy.json', false, $ctx, 0, 4096);
    // We land here both when the certificate did not match and when the host was silent.
    if (!is_string($body)) return [null, 'unreachable'];
    $code = 0;
    foreach ($http_response_header ?? [] as $h) {
        if (preg_match('~^HTTP/\S+\s+(\d{3})~', $h, $m)) $code = (int)$m[1];
    }
    if ($code >= 400) return [null, 'http_' . $code];
    $j = json_decode($body, true);
    if (!is_array($j)) return [null, 'not_json'];
    $key = (string)($j['key'] ?? '');
    if ($key === '') return [null, 'no_key'];
    if (strlen(base64_decode($key, true) ?: '') !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) return [null, 'bad_key'];
    return [$key, 'ok'];
}

/** A key counts as fresh for a day; after that the domain is checked again. */
function org_pubkey_fresh(array $o): bool {
    return !empty($o['pubkey']) && !empty($o['pubkey_seen_at'])
        && strtotime($o['pubkey_seen_at']) > time() - 86400;
}

/** The older TXT-record domain check, kept for compatibility. */
function org_check_domain(string $domain, string $token): bool {
    $domain = strtolower(trim($domain));
    if ($domain === '' || $token === '') return false;
    if (!preg_match('/^[a-z0-9.-]{4,190}$/', $domain)) return false;
    $needle = 'entrixy-verify=' . $token;
    foreach ([$domain, '_entrixy.' . $domain] as $host) {
        $recs = @dns_get_record($host, DNS_TXT) ?: [];
        foreach ($recs as $r) {
            $txt = (string)($r['txt'] ?? '');
            if (strpos($txt, $needle) !== false) return true;
        }
    }
    $url = 'https://' . $domain . '/.well-known/entrixy-' . $token;
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true],
                                  'ssl' => ['verify_peer' => true]]);
    $body = @file_get_contents($url, false, $ctx, 0, 512);
    return is_string($body) && strpos($body, $token) !== false;
}

/** A company's latest requests with their state. */
function org_requests(int $orgId, int $limit = 30): array {
    $limit = max(1, min(100, $limit));
    $st = db()->prepare(
        "SELECT code, ref, status, user_key_id, created_at, claimed_at, issued_at, expires_at
           FROM org_requests WHERE org_id = ? ORDER BY id DESC LIMIT $limit"
    );
    $st->execute([$orgId]);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$r) {
        if ($r['status'] === 'new' && strtotime($r['expires_at']) < time()) $r['status'] = 'expired';
    }
    return $rows;
}

/** How many keys the company holds right now. */
function org_keys_count(int $orgId): int {
    $st = db()->prepare('SELECT COUNT(*) FROM user_keys WHERE org_id = ? AND enabled = 1');
    $st->execute([$orgId]);
    return (int)$st->fetchColumn();
}

/** The domain in machine form: non-ASCII names go to punycode, because that is
 *  how the HTTPS client fetches the key. An empty string if the name does not
 *  parse. */
function org_domain_ascii(string $domain): string
{
    $domain = strtolower(trim($domain));
    $domain = trim(explode('/', preg_replace('~^https?://~', '', $domain))[0]);
    if ($domain === '') return '';
    if (preg_match('/[^a-z0-9.-]/u', $domain) && function_exists('idn_to_ascii')) {
        $a = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($a === false) return '';
        $domain = strtolower($a);
    }
    return preg_match('/^[a-z0-9.-]{4,190}$/', $domain) ? $domain : '';
}

/** The domain in human form: punycode is unfolded again, because a person
 *  compares this string by eye with the company's site. */
function org_domain_display(?string $domain): ?string
{
    if ($domain === null || $domain === '') return $domain;
    if (strpos($domain, 'xn--') !== false && function_exists('idn_to_utf8')) {
        $u = idn_to_utf8($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($u !== false) return $u;
    }
    return $domain;
}

/**
 * Tells a company that something happened with its request. The callback means
 * "come and look", not the truth itself: the body is deliberately short, and the
 * company fetches the details with its usual signed a=status call.
 *
 * Sent once, with no queue and no retries: if it does not arrive, the company
 * sees it at its next poll.
 */
function org_callback(int $orgId, string $event, array $data = []): void {
    try {
        $st = db()->prepare('SELECT callback_url FROM orgs WHERE id = ? AND status <> "blocked"');
        $st->execute([$orgId]);
        $url = (string)($st->fetchColumn() ?: '');
        if ($url === '' || strncmp($url, 'https://', 8) !== 0) return;
        $host = parse_url($url, PHP_URL_HOST);
        if (!$host || (function_exists('ssrf_host_blocked') && ssrf_host_blocked($host))) return;

        $body = json_encode(['event' => $event, 'org_id' => $orgId] + $data, JSON_UNESCAPED_UNICODE);
        $ctx = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/json\r\nUser-Agent: Entrixy\r\n",
                'content' => $body,
                'timeout' => 3,
                'ignore_errors' => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        @file_get_contents($url, false, $ctx);
    } catch (\Throwable $e) { /* the company will find out when it polls */ }
}
