<?php
/**
 * An owner's account on the server.
 *
 * Registering a device is anonymous by itself: the server issues a pair of
 * credentials and creates a row. An account is an optional layer on top — if the
 * device presented a sign-in token, the row is attached to a person and the plan
 * is taken from them. The plan then survives a reinstall and covers all of that
 * person's devices rather than one installation.
 *
 * Accounts do not touch keys: they are still encrypted on the phone, and the
 * server sees them neither with an account nor without one.
 */

/** The user behind a sign-in token from api/pwa_login.php, or null. */
function account_user_id(string $token): ?int {
    if ($token === '') return null;
    $p = jwt_decode($token);
    $uid = (int)($p['uid'] ?? 0);
    if ($uid <= 0) return null;
    // A token issued before a password change is no longer valid.
    $st = db()->prepare('SELECT sess_ver FROM users WHERE id = ?');
    $st->execute([$uid]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) return null;
    if ((int)($p['sv'] ?? 0) !== (int)($row['sess_ver'] ?? 0)) return null;
    return $uid;
}

/**
 * Limits for a device: the person's plan if the device is attached to one,
 * otherwise the device's own plan, otherwise the server's default.
 */
function account_limits(int $host_id): array {
    $st = db()->prepare(
        'SELECT COALESCE(pu.max_numbers, ph.max_numbers) AS max_numbers,
                COALESCE(pu.max_keys,    ph.max_keys)    AS max_keys,
                u.email AS account_email
           FROM hosts h
           LEFT JOIN users u  ON u.id = h.user_id
           LEFT JOIN plans pu ON pu.id = u.plan_id
           LEFT JOIN plans ph ON ph.id = h.plan_id
          WHERE h.id = ?'
    );
    $st->execute([$host_id]);
    $r = $st->fetch(PDO::FETCH_ASSOC) ?: [];
    return [
        'max_numbers'   => (int)($r['max_numbers'] ?? 10),
        'max_keys'      => (int)($r['max_keys'] ?? 10),
        'account_email' => $r['account_email'] ?? null,
    ];
}

/** The phones attached to an account. */
function account_devices(int $uid): array {
    $st = db()->prepare(
        'SELECT h.id, h.device_id, h.created_at, h.last_seen,
                (SELECT COUNT(*) FROM numbers n WHERE n.host_id = h.id)   AS objects,
                (SELECT COUNT(*) FROM user_keys k WHERE k.host_id = h.id) AS keys_issued
           FROM hosts h
          WHERE h.user_id = ?
          ORDER BY h.last_seen IS NULL, h.last_seen DESC, h.id DESC'
    );
    $st->execute([$uid]);
    return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
}

/** An account's plan: how many objects and keys are allowed on each phone. */
function account_plan(int $uid): array {
    $st = db()->prepare(
        'SELECT COALESCE(p.name, "default") AS name,
                COALESCE(p.max_numbers, 10) AS max_numbers,
                COALESCE(p.max_keys, 20)    AS max_keys
           FROM users u LEFT JOIN plans p ON p.id = u.plan_id WHERE u.id = ?'
    );
    $st->execute([$uid]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: ['name' => 'default', 'max_numbers' => 10, 'max_keys' => 20];
}

/**
 * The server's own address.
 *
 * Everything the server puts into a QR code or an answer to the app must lead
 * back to itself: an invitation, a company link. A hardcoded domain would mean
 * one server handing out links to another, sending people somewhere other than
 * where their access lives.
 *
 * The Host header comes from the client, so its format is checked; when SITE_URL
 * is configured, as on a self-hosted installation, that is used instead.
 */
function site_host(): string {
    // The configured address is the primary source. The Host header comes from the
    // client, and forging it could produce a link pointing at someone else's site,
    // so on a configured server it is not consulted at all.
    $fixed = (string)($GLOBALS['site_host'] ?? '');
    if ($fixed !== '') return $fixed;

    $env = (string)getenv('SITE_URL');
    if ($env !== '') {
        $h = parse_url($env, PHP_URL_HOST);
        if ($h) return $h;
    }
    $h = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    return preg_match('/^[a-z0-9.-]+(:[0-9]{1,5})?$/', $h) ? $h : (string)($GLOBALS['site_host'] ?? 'localhost');
}

/** An address of the form https://host — the base for outbound links. */
function site_url(string $path = ''): string {
    return 'https://' . site_host() . $path;
}
