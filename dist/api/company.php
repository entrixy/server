<?php
/**
 * The companies API. A company's key is NOT a string that can be forwarded: the
 * owner issues it by picking the company from a list, and only a reference to the
 * row (key_ref) leaves the server. The company opens with its own secret, naming
 * the person doing it, who then appears in the owner's log.
 *
 *   a=request  (secret)   create a request → a code for the QR
 *   a=status   (secret)   the state of a request
 *   a=open     (secret)   open an object: key_ref + number_id + actor
 *   a=invite   (public)   a company profile by code, for the page and the app
 *   a=claim    (phone)    "the client arrived": the app marked the request
 */
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/account.php';
require_once __DIR__ . '/../lib/org.php';   // the key from the domain, freshness, checks

$action = (string)($_GET['a'] ?? '');
$j = jin();

/**
 * Two schemes of authentication.
 *
 * 1. A SIGNATURE tied to the domain, for companies that have one. Headers:
 *      X-Entrixy-Org:   the company's domain
 *      X-Entrixy-Ts:    unix time, a 300 second window
 *      X-Entrixy-Nonce: 32 hex characters, single use
 *      X-Entrixy-Sig:   Ed25519 in base64 over "<domain>.<ts>.<nonce>.<sha256 of body>"
 *    The key is taken from the domain itself: https://<domain>/.well-known/entrixy.json.
 *    It is re-checked at least daily: if the file disappears, the domain moves or
 *    changes hands, signatures stop being accepted. There is no one-off "verified"
 *    tick.
 *
 * 2. A SECRET, for those with no domain. Such a company is shown to the client by
 *    name only, with no logo and no domain. A company that has a domain may NOT
 *    fall back to the secret: otherwise a leaked secret would pass for a verified
 *    company.
 */
function org_auth(array $j): array {
    $hdr = function (string $n): string {
        $k = 'HTTP_' . strtoupper(str_replace('-', '_', $n));
        return (string)($_SERVER[$k] ?? '');
    };
    $domain = org_domain_ascii((string)$hdr('X-Entrixy-Org'));
    if ($domain !== '') {
        $ts    = (int)$hdr('X-Entrixy-Ts');
        $nonce = strtolower($hdr('X-Entrixy-Nonce'));
        $sig   = $hdr('X-Entrixy-Sig');
        if ($ts <= 0 || abs(time() - $ts) > 300) jout(['error' => 'stale_timestamp'], 401);
        if (!preg_match('/^[a-f0-9]{32}$/', $nonce)) jout(['error' => 'bad_nonce'], 401);
        $st = db()->prepare('SELECT * FROM orgs WHERE domain = ? AND status <> "blocked"');
        $st->execute([$domain]);
        $o = $st->fetch(PDO::FETCH_ASSOC);
        if (!$o) jout(['error' => 'auth'], 401);
        // The key is fetched from the domain on EVERY call: the right to speak for a
        // domain lasts exactly as long as the domain says so. Sell the domain, remove
        // the file, rotate the key, and earlier signatures stop being accepted at
        // once rather than when some cache expires. If the key cannot be fetched
        // there is no access: the domain is the credential, and keeping it alive is
        // the company's job. The single concession is ten seconds, so that a run of
        // openings does not drum on their site; that is a burst guard, not a
        // staleness window.
        $reuse = !empty($o['pubkey']) && !empty($o['pubkey_seen_at'])
              && strtotime($o['pubkey_seen_at']) > time() - 10;
        if (!$reuse) {
            $fresh = org_fetch_pubkey($domain);
            if ($fresh === null) jout(['error' => 'domain_key_unavailable'], 401);
            if ($fresh !== $o['pubkey']) {
                db()->prepare('UPDATE orgs SET pubkey=?, pubkey_seen_at=NOW() WHERE id=?')
                    ->execute([$fresh, (int)$o['id']]);
            } else {
                db()->prepare('UPDATE orgs SET pubkey_seen_at=NOW() WHERE id=?')->execute([(int)$o['id']]);
            }
            $o['pubkey'] = $fresh;
        }
        $raw  = file_get_contents('php://input') ?: '';
        $base = $domain . '.' . $ts . '.' . $nonce . '.' . hash('sha256', $raw);
        $ok = false;
        try {
            $ok = sodium_crypto_sign_verify_detached(
                base64_decode($sig, true) ?: '', $base, base64_decode($o['pubkey'], true) ?: ''
            );
        } catch (\Throwable $e) { $ok = false; }
        if (!$ok) jout(['error' => 'bad_signature'], 401);
        /* The phone must verify the company itself: a server can lie that a domain
           is confirmed, but it cannot forge the signature — the key lives on the
           domain. So the signed material is stored and passed along. */
        $GLOBALS['org_sig_material'] = [
            'sig' => $sig, 'ts' => $ts, 'nonce' => $nonce, 'body' => $raw, 'domain' => $domain,
        ];
        // Single use: the same nonce will not pass twice.
        try {
            db()->prepare('INSERT INTO org_nonces (org_id, nonce, ts) VALUES (?,?,?)')
                ->execute([(int)$o['id'], $nonce, $ts]);
        } catch (\Throwable $e) { jout(['error' => 'replay'], 401); }
        db()->prepare('DELETE FROM org_nonces WHERE ts < ?')->execute([time() - 600]);
        return $o;
    }

    $id     = (int)($j['org_id'] ?? 0);
    $secret = (string)($j['secret'] ?? '');
    if ($id <= 0 || $secret === '') jout(['error' => 'auth'], 401);
    $st = db()->prepare('SELECT * FROM orgs WHERE id = ?');
    $st->execute([$id]);
    $o = $st->fetch(PDO::FETCH_ASSOC);
    if (!$o || !$o['secret_hash'] || !hash_equals($o['secret_hash'], hash('sha256', $secret))) {
        jout(['error' => 'auth'], 401);
    }
    if ($o['status'] === 'blocked') jout(['error' => 'org_blocked'], 403);
    // The secret is closed to a company whose domain is already confirmed by a
    // key: otherwise a leaked secret would speak for a verified one. While there
    // is no key on the domain the company is shown as unverified anyway, so the
    // secret does no harm.
    if (!empty($o['domain']) && !empty($o['pubkey'])) jout(['error' => 'sign_required'], 401);
    return $o;
}
function org_public(array $o): array {
    // The logo and the domain are shown ONLY when the domain is tied to the company
    // cryptographically: the key lives on the domain and signs every call.
    $verified = !empty($o['domain']) && !empty($o['pubkey']);
    return [
        'org_id'   => (int)$o['id'],
        'name'     => $o['name'],
        // The domain is shown to a person and compared by eye, so it goes out the way
        // the company wrote it, not in punycode.
        'domain'   => $verified ? org_domain_display($o['domain']) : null,
        'verified' => $verified,
        'logo'     => ($verified && $o['logo_hash']) ? '/img/org/' . $o['logo_hash'] . '.png' : null,
    ];
}

// ── A request: the code behind the QR ──────────────────────────────────────────
if ($action === 'request') {
    $o = org_auth($j);
    rate_limit_check('org_request', 120);
    $m    = $GLOBALS['org_sig_material'] ?? [];
    $ref  = substr(trim((string)($j['ref'] ?? '')), 0, 64);
    $hours = (int)($j['ttl_hours'] ?? 72);
    if ($hours < 1 || $hours > 720) $hours = 72;
    for ($try = 0; $try < 5; $try++) {
        $code = substr(rtrim(strtr(base64_encode(random_bytes(12)), '+/', '-_'), '='), 0, 16);
        try {
            db()->prepare(
                'INSERT INTO org_requests (org_id, code, ref, sig, sig_ts, sig_nonce, sig_body,
                                            status, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, "new", NOW(), DATE_ADD(NOW(), INTERVAL ? HOUR))'
            )->execute([
                $o['id'], $code, $ref !== '' ? $ref : null,
                $m['sig'] ?? null, $m['ts'] ?? null, $m['nonce'] ?? null, $m['body'] ?? null,
                $hours,
            ]);
            jout(['code' => $code, 'url' => site_url('/c/' . $code), 'expires_in_hours' => $hours]);
        } catch (\Throwable $e) { /* code collision — try again */ }
    }
    jout(['error' => 'try_later'], 503);
}

// ── The state of a request ───────────────────────────────────────────────────────
if ($action === 'status') {
    $o = org_auth($j);
    $code = (string)($j['code'] ?? '');
    $st = db()->prepare(
        'SELECT code, ref, status, user_key_id, created_at, claimed_at, issued_at, expires_at
         FROM org_requests WHERE org_id = ? AND code = ?'
    );
    $st->execute([$o['id'], $code]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (!$r) jout(['error' => 'not_found'], 404);
    if ($r['status'] === 'new' && strtotime($r['expires_at']) < time()) $r['status'] = 'expired';
    // The key may have been revoked when the client removed the company: the
    // request is closed then, but we check against the key itself in any case.
    if ($r['status'] === 'issued' && $r['user_key_id']) {
        $chk = db()->prepare('SELECT enabled, mode FROM user_keys WHERE id = ?');
        $chk->execute([(int)$r['user_key_id']]);
        $kk = $chk->fetch(PDO::FETCH_ASSOC);
        if (!$kk || (int)$kk['enabled'] !== 1 || ($kk['mode'] ?? 'auto') === 'off') {
            $r['status'] = 'revoked';
        }
    }
    // Once access has been granted the key's contents go straight back: the service
    // needs number_id to open, and its employee needs the object's name.
    $numbers = [];
    if ($r['user_key_id']) {
        $nq = db()->prepare(
            'SELECT kn.number_id, kn.org_label, n.type
             FROM key_numbers kn JOIN numbers n ON n.id = kn.number_id
             WHERE kn.user_key_id = ?'
        );
        $nq->execute([(int)$r['user_key_id']]);
        foreach ($nq->fetchAll(PDO::FETCH_ASSOC) as $nr) {
            $numbers[] = [
                'number_id' => (int)$nr['number_id'],
                'name'      => $nr['org_label'] !== null && $nr['org_label'] !== '' ? $nr['org_label'] : null,
                'type'      => $nr['type'] ?: 'call',
                'openable'  => ($nr['type'] ?: 'call') === 'call',
            ];
        }
    }
    jout([
        'code' => $r['code'], 'ref' => $r['ref'], 'state' => $r['status'],
        'key_ref' => $r['user_key_id'] ? (int)$r['user_key_id'] : null,
        'numbers' => $numbers,
        'claimed_at' => $r['claimed_at'], 'issued_at' => $r['issued_at'],
    ]);
}

// ── Opening: the key, the object and who pressed ──────────────────────────
if ($action === 'objects') {
    // What the issued key actually opens. Without this the service has nowhere to
    // get the number_id for an open call, nor its employee a name at the gate.
    $o = org_auth($j);
    $key_ref = (int)($j['key_ref'] ?? 0);
    $code    = (string)($j['code'] ?? '');
    if ($key_ref <= 0 && $code !== '') {
        $st = db()->prepare('SELECT user_key_id FROM org_requests WHERE org_id = ? AND code = ?');
        $st->execute([$o['id'], $code]);
        $key_ref = (int)($st->fetchColumn() ?: 0);
    }
    if ($key_ref <= 0) jout(['error' => 'bad_input'], 400);

    $st = db()->prepare(
        'SELECT kn.number_id, kn.org_label, n.type
         FROM key_numbers kn
         JOIN numbers n ON n.id = kn.number_id
         JOIN user_keys uk ON uk.id = kn.user_key_id
         WHERE kn.user_key_id = ? AND uk.org_id = ? AND uk.enabled = 1'
    );
    $st->execute([$key_ref, $o['id']]);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    if (!$rows) jout(['error' => 'revoked'], 403);

    $out = [];
    foreach ($rows as $r) {
        $out[] = [
            'number_id' => (int)$r['number_id'],
            // The client stores the object's name encrypted; it reaches the service only
            // if the client agreed to show it when granting access.
            'name'      => $r['org_label'] !== null && $r['org_label'] !== '' ? $r['org_label'] : null,
            'type'      => $r['type'] ?: 'call',
            // Only an object opened by the owner's call can be opened this way.
            'openable'  => ($r['type'] ?: 'call') === 'call',
        ];
    }
    jout(['key_ref' => $key_ref, 'numbers' => $out]);
}

if ($action === 'open') {
    $o = org_auth($j);
    $key_ref   = (int)($j['key_ref'] ?? 0);
    $number_id = (int)($j['number_id'] ?? 0);
    $actor     = substr(trim((string)($j['actor'] ?? '')), 0, 64);
    if ($key_ref <= 0) jout(['error' => 'bad_input'], 400);
    // The object may be left unnamed when the key has only one: then the service
    // has no need to know about numbers at all.
    if ($number_id <= 0) {
        $one = db()->prepare('SELECT number_id FROM key_numbers WHERE user_key_id = ?');
        $one->execute([$key_ref]);
        $all = $one->fetchAll(PDO::FETCH_COLUMN);
        if (count($all) === 1) $number_id = (int)$all[0];
    }
    if ($number_id <= 0) jout(['error' => 'number_id_required'], 400);
    if ($actor === '') jout(['error' => 'actor_required'], 400);

    $st = db()->prepare(
        'SELECT uk.id, uk.host_id, uk.enabled, uk.mode, uk.expires_at, n.type
         FROM user_keys uk
         JOIN key_numbers kn ON kn.user_key_id = uk.id
         JOIN numbers n ON n.id = kn.number_id
         WHERE uk.id = ? AND uk.org_id = ? AND kn.number_id = ?'
    );
    $st->execute([$key_ref, $o['id'], $number_id]);
    $k = $st->fetch(PDO::FETCH_ASSOC);
    if (!$k) {
        // There is no key at all: the client removed the company on their side. For
        // the service that is a revocation, not a bad request.
        $gone = db()->prepare('SELECT id FROM user_keys WHERE id = ?');
        $gone->execute([$key_ref]);
        jout(['error' => $gone->fetchColumn() ? 'forbidden' : 'revoked'], 403);
    }
    if ((int)$k['enabled'] !== 1 || ($k['mode'] ?? 'auto') === 'off') jout(['error' => 'revoked'], 403);
    if ($k['expires_at'] && strtotime($k['expires_at']) < time()) jout(['error' => 'expired'], 403);

    // Only an object opened by the owner's phone (a call) is supported so far. For
    // encrypted objects the command is signed by the key holder, and a company has
    // no key material.
    $type = $k['type'] ?: 'call';
    if ($type !== 'call') jout(['error' => 'unsupported_object', 'type' => $type], 400);

    $cnt = db()->prepare(
        'SELECT COUNT(*) FROM call_log WHERE user_key_id = ? AND ts > DATE_SUB(NOW(), INTERVAL 1 MINUTE)'
    );
    $cnt->execute([$key_ref]);
    if ((int)$cnt->fetchColumn() >= $GLOBALS['rate_limit_per_min']) jout(['error' => 'rate_limit'], 429);

    // The employee's name travels to the owner with the task: the log must show not
    // only which company opened the gate but who pressed the button.
    db()->prepare(
        'INSERT INTO pending_actions (host_id, number_id, user_key_id, source, actor, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())'
    )->execute([$k['host_id'], $number_id, $key_ref, 'org_api', $actor]);
    db()->prepare(
        'INSERT INTO call_log (user_key_id, number_id, ts, status, actor) VALUES (?, ?, NOW(), ?, ?)'
    )->execute([$key_ref, $number_id, 'requested_org', $actor]);

    jout(['ok' => 1]);
}

// ── A company profile by code: the page and the app ────────────────
if ($action === 'invite') {
    $code = (string)($_GET['code'] ?? ($j['code'] ?? ''));
    if ($code === '') jout(['error' => 'bad_input'], 400);
    rate_limit_check('org_invite', 120);
    $st = db()->prepare(
        'SELECT r.status, r.expires_at, r.sig, r.sig_ts, r.sig_nonce, r.sig_body,
                o.id, o.name, o.logo_hash, o.domain, o.pubkey, o.status AS org_status
         FROM org_requests r JOIN orgs o ON o.id = r.org_id WHERE r.code = ?'
    );
    $st->execute([$code]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (!$r || $r['org_status'] === 'blocked') jout(['error' => 'not_found'], 404);
    $state = $r['status'];
    if ($state === 'new' && strtotime($r['expires_at']) < time()) $state = 'expired';
    /* The signature goes out as is: the phone fetches the key from the company's
       domain itself and checks it. A "domain verified" flag cannot be trusted —
       it is computed by a server, and the server may belong to anyone. */
    jout(org_public($r) + ['state' => $state, 'sig' => [
        'sig'    => $r['sig'] ?? null,
        'ts'     => $r['sig_ts'] !== null ? (int)$r['sig_ts'] : null,
        'nonce'  => $r['sig_nonce'] ?? null,
        'body'   => $r['sig_body'] ?? null,
        'domain' => $r['domain'] ?? null,
    ]]);
}

// ── A company profile by id: the app refreshes its card ──────────
if ($action === 'profile') {
    $ids = array_slice(array_map('intval', (array)($j['org_ids'] ?? [])), 0, 50);
    if (!$ids) jout(['orgs' => []]);
    $in = implode(',', array_fill(0, count($ids), '?'));
    $st = db()->prepare("SELECT id, name, logo_hash, domain, pubkey FROM orgs WHERE status <> 'blocked' AND id IN ($in)");
    $st->execute($ids);
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $o) $out[] = org_public($o);
    jout(['orgs' => $out]);
}

// ── "The client arrived": the app marked the request ───────────────────
if ($action === 'claim') {
    [$host_id, $j] = host_auth();
    $code = (string)($j['code'] ?? '');
    $st = db()->prepare('SELECT id, org_id, status, expires_at, host_id FROM org_requests WHERE code = ?');
    $st->execute([$code]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (!$r) jout(['error' => 'not_found'], 404);
    if ($r['status'] === 'new' && strtotime($r['expires_at']) < time()) jout(['error' => 'expired'], 410);
    // We remember whose phone opened the link: the request is closed by it if the
    // key is later issued from the company list rather than from this window.
    if ($r['status'] === 'new') {
        db()->prepare('UPDATE org_requests SET status = "claimed", claimed_at = NOW(), host_id = ? WHERE id = ?')
            ->execute([$host_id, $r['id']]);
        org_callback((int)$r['org_id'], 'claimed', ['code' => $code]);
    } elseif (empty($r['host_id'])) {
        db()->prepare('UPDATE org_requests SET host_id = ? WHERE id = ?')->execute([$host_id, $r['id']]);
    }
    $o = db()->prepare('SELECT id, name, logo_hash, domain, pubkey FROM orgs WHERE id = ?');
    $o->execute([$r['org_id']]);
    $org = $o->fetch(PDO::FETCH_ASSOC);
    audit_log($host_id, 'org_claim', 'org_request', (int)$r['id'], ['org' => (int)$r['org_id']]);
    jout(org_public($org) + ['state' => 'claimed']);
}

jout(['error' => 'unknown_action'], 400);
