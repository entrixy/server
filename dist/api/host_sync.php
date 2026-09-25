<?php
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/account.php';
require_once __DIR__ . '/../lib/org.php';

[$host_id, $j] = host_auth();

// The server keeps in the clear ONLY the fields it needs for routing: id, type,
// webhook_mode for dispatching calls, device_id for matching a controller. The
// webhook URL and secret only when mode='server', since then the server fires the
// request itself. Everything else — label, phone, radius, time, geo, wifi, share,
// avatar and the rest — lives EXCLUSIVELY in data_cipher and is decrypted by the
// client with its own object key.
$st = db()->prepare(
    'SELECT id, type, webhook_mode, webhook_url, webhook_secret, device_id,
            data_cipher, data_cipher_updated,
            last_state, UNIX_TIMESTAMP(last_state_at) AS last_state_ts
     FROM numbers WHERE host_id = ?'
);
$st->execute([$host_id]);
$numbers = [];
foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $n) {
    $numbers[] = [
        'id'              => (int)$n['id'],
        'type'            => $n['type'],
        'webhook_mode'    => $n['webhook_mode'],
        'webhook_url'     => $n['webhook_mode'] === 'server' ? $n['webhook_url']    : null,
        'webhook_secret'  => $n['webhook_mode'] === 'server' ? $n['webhook_secret'] : null,
        'device_id'       => $n['device_id'] !== null ? (int)$n['device_id'] : null,
        'data_cipher'     => $n['data_cipher'],
        'data_cipher_ts'  => $n['data_cipher_updated'],
        // The lock's state, for bistable objects. null means the object does not
        // report one, or has never sent a position yet. The client draws the marks
        // on the avatar only for 'open'.
        'last_state'      => $n['last_state'],
        'last_state_ts'   => $n['last_state_ts'] !== null ? (int)$n['last_state_ts'] : null,
    ];
}

// The guest's label is not stored on the server: the owner resolves it locally
// from their own map of user_key_id to label.
$st = db()->prepare(
    'SELECT uk.id, uk.enabled, uk.mode, uk.force_when_busy,
            uk.bundle_cipher, uk.bundle_cipher_updated,
            uk.parent_key_id, uk.delegate_depth, uk.guest_pub, uk.key_cipher,
            uk.org_id, o.name AS org_name, o.logo_hash,
            o.domain AS org_domain, o.pubkey AS org_pubkey,
            GROUP_CONCAT(kn.number_id) AS number_ids
     FROM user_keys uk
     LEFT JOIN key_numbers kn ON kn.user_key_id = uk.id
     LEFT JOIN orgs o ON o.id = uk.org_id
     WHERE uk.host_id = ?
     GROUP BY uk.id'
);
$st->execute([$host_id]);
$keys = $st->fetchAll(PDO::FETCH_ASSOC);
foreach ($keys as &$k) {
    $k['number_ids'] = $k['number_ids'] ? array_map('intval', explode(',', $k['number_ids'])) : [];
    // The company's domain and logo are shown only when the domain is tied to it
    // cryptographically: the key lives on the domain and signs every call.
    $verified = !empty($k['org_domain']) && !empty($k['org_pubkey']);
    $k['org_verified'] = $verified ? 1 : 0;
    // The logo goes out as a ready address, as in every other answer: a bare hash
    // is not an address to the app, and the image would not load.
    $k['org_logo'] = ($verified && !empty($k['logo_hash']))
        ? '/img/org/' . $k['logo_hash'] . '.png' : null;
    unset($k['logo_hash']);
    if (!$verified) { $k['org_domain'] = null; }
    // A person compares the domain by eye with the company's site, so it goes out
    // as written rather than in punycode.
    elseif (function_exists('org_domain_display')) $k['org_domain'] = org_domain_display($k['org_domain']);
    unset($k['org_pubkey']);
    $k['parent_key_id']  = $k['parent_key_id'] !== null ? (int)$k['parent_key_id'] : null;
    $k['delegate_depth'] = (int)$k['delegate_depth'];
    // A key issued down a chain arrives without a bundle: only the owner can
    // assemble it, since only they hold the object keys. Until then the key counts
    // as pending and opens nothing.
    $k['needs_bundle'] = ($k['parent_key_id'] !== null && $k['bundle_cipher'] === null) ? 1 : 0;
    // bundle_cipher goes out as it is; the client makes sense of it.
    $k['bundle_cipher_ts'] = $k['bundle_cipher_updated'];
    unset($k['bundle_cipher_updated']);
}
unset($k);

// Limits: the account's plan if the device is attached to one, otherwise its own.
$limits = account_limits($host_id);

jout([
    'numbers' => $numbers,
    'keys'    => $keys,
    'limits'  => [
        'max_numbers' => $limits['max_numbers'],
        'max_keys'    => $limits['max_keys'],
    ],
    // The account address, so the app can show whom it works as on this server.
    // Null means "no account", which is a normal mode.
    'account' => $limits['account_email'],
]);
