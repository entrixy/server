<?php
require __DIR__ . '/../_config.php';
require __DIR__ . '/vendor/autoload.php';

use Workerman\Worker;
use Workerman\Connection\TcpConnection;
use Workerman\Connection\AsyncTcpConnection;
use Workerman\Timer;

/** Logs to private/wh.log — for step-by-step diagnosis of the webhook flow. */
function whlog(string $line): void {
    $f = '/app/wh.log';
    @file_put_contents($f, '[' . date('H:i:s') . '] ' . $line . "\n", FILE_APPEND);
}

/** Splits a raw HTTP response into (headers, body). */
function parseHttpResponse(string $raw): array {
    $pos = strpos($raw, "\r\n\r\n");
    if ($pos === false) return ['', $raw];
    return [substr($raw, 0, $pos), substr($raw, $pos + 4)];
}
/** Decodes a Transfer-Encoding: chunked body. */
function decodeChunked(string $body): string {
    $out = ''; $i = 0; $len = strlen($body);
    while ($i < $len) {
        $eol = strpos($body, "\r\n", $i);
        if ($eol === false) break;
        $sizeHex = trim(substr($body, $i, $eol - $i));
        $size = hexdec(explode(';', $sizeHex)[0]);
        if ($size === 0) break;
        $i = $eol + 2;
        $out .= substr($body, $i, $size);
        $i += $size + 2; // chunk + CRLF
    }
    return $out;
}

$worker = new Worker("websocket://{$GLOBALS['ws_host']}:{$GLOBALS['ws_port']}");
$worker->name = 'entrixy-ws';
$worker->count = 1;

$hosts   = [];
$guests  = [];
$calls   = [];
$devices = [];   // device_id => TcpConnection (ESP32)
/** Queues a message for the owner in the database; flushed on host_hello.
 *  Used when the owner is offline at the moment something must reach them.
 *  Survives a restart of the PHP worker, which an in-memory queue did not.
 *
 *  For `ble_token_renew` the dedup_key is "renew:bleId:userKeyId". The UNIQUE KEY
 *  (host_id, dedup_key) in the schema guarantees one request per object+key pair
 *  in the queue — INSERT IGNORE quietly drops repeats. This cures the case of a
 *  guest whose websocket flaps (1300 reconnects in 4 hours = 1300 identical rows).
 *  `ble_fire_event` is NOT deduplicated — every event is unique by `ts`, and the
 *  dedup_key stays NULL (MySQL allows several NULLs in a UNIQUE KEY). */
function enqueueHostMsg(int $hostId, array $payload): void {
    if ($hostId <= 0) return;
    try {
        $dedupKey = null;
        if (($payload['type'] ?? '') === 'ble_token_renew') {
            $bleId    = (int)($payload['ble_id'] ?? 0);
            $userKeyId = (int)($payload['user_key_id'] ?? 0);
            $dedupKey = "renew:{$bleId}:{$userKeyId}";
        }
        db()->prepare(
            'INSERT IGNORE INTO pending_host_msgs (host_id, payload, dedup_key, created_at)
             VALUES (?, ?, ?, NOW())'
        )->execute([$hostId, json_encode($payload, JSON_UNESCAPED_UNICODE), $dedupKey]);

        // Per-host cap: keeps the queue from growing under abuse.
        // If a host has more than HOST_QUEUE_CAP messages queued, the oldest
        // are dropped. Renew dedup already keeps duplicates out, but fire_event
        // with unique ts values can still grow; the cap covers that.
        $cap = 500;
        $st = db()->prepare('SELECT COUNT(*) FROM pending_host_msgs WHERE host_id = ?');
        $st->execute([$hostId]);
        $cnt = (int)$st->fetchColumn();
        if ($cnt > $cap) {
            db()->prepare(
                'DELETE FROM pending_host_msgs WHERE host_id = ? ORDER BY id ASC LIMIT ?'
            )->execute([$hostId, $cnt - $cap]);
        }
    } catch (Throwable $e) { whlog("enqueueHostMsg fail host=$hostId: ".$e->getMessage()); }
}

/**
 * Applies a new object state (position) with diff, rate limit and broadcast.
 * Sources: device_status.position, a server-mode webhook response, obj_state_push
 * (phone-mode webhook), a BLE state update (over the websocket, if it appears).
 *
 * Returns true if the state actually changed and the broadcast went out.
 */
function applyObjectState(int $hostId, int $numId, string $position, array &$hosts, array &$guests): bool {
    if (!in_array($position, ['open','closed','unknown'], true)) return false;

    // Fetch last_state and the host.
    $sf = db()->prepare('SELECT last_state, host_id FROM numbers WHERE id = ?');
    $sf->execute([$numId]);
    $row = $sf->fetch(PDO::FETCH_ASSOC);
    if (!$row || (int)$row['host_id'] !== $hostId) return false;
    if ($position === $row['last_state']) return false;

    // Rate limit: one broadcast per 5 seconds per num_id.
    static $rl = [];
    $now_ms = (int)(microtime(true) * 1000);
    $last = $rl[$numId] ?? 0;
    if (($now_ms - $last) < 5000) return false;
    $rl[$numId] = $now_ms;

    db()->prepare('UPDATE numbers SET last_state = ?, last_state_at = NOW() WHERE id = ?')
        ->execute([$position, $numId]);
    $ts = time();
    $payload = json_encode([
        'type'       => 'obj_state_update',
        'num_id'     => $numId,
        'position'   => $position,
        'updated_at' => $ts,
    ]);
    $hostConn = $hosts[$hostId] ?? null;
    if ($hostConn) try { $hostConn->send($payload); } catch (\Throwable $e) {}
    $kn = db()->prepare('SELECT DISTINCT user_key_id FROM key_numbers WHERE number_id = ?');
    $kn->execute([$numId]);
    $ukids = $kn->fetchAll(PDO::FETCH_COLUMN);
    if ($ukids) {
        foreach ($guests as $g) {
            if (isset($g->user_key_id) && in_array((int)$g->user_key_id, $ukids, true)) {
                try { $g->send($payload); } catch (\Throwable $e) {}
            }
        }
    }
    return true;
}

/** Pulls the owner's queue from the database and sends everything accumulated. */
function flushHostQueue(TcpConnection $host, int $hostId): void {
    try {
        $st = db()->prepare('SELECT id, payload FROM pending_host_msgs WHERE host_id = ? ORDER BY id ASC');
        $st->execute([$hostId]);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC);
        if (!$rows) return;
        $ids = [];
        foreach ($rows as $r) {
            $host->send($r['payload']);
            $ids[] = (int)$r['id'];
        }
        if ($ids) {
            $in = implode(',', array_fill(0, count($ids), '?'));
            db()->prepare("DELETE FROM pending_host_msgs WHERE id IN ($in)")->execute($ids);
        }
    } catch (Throwable $e) { whlog("flushHostQueue fail host=$hostId: ".$e->getMessage()); }
}

// Heartbeat: if a client does not answer a ping for 60s the connection is dead
$worker->onConnect = function (TcpConnection $c) {
    $c->role = null;
    $c->lastPong = time();
};

$worker->onWorkerStart = function ($worker) use (&$hosts, &$guests, &$calls, &$devices) {
    // Moving to a new phone: the old handset can sit on a connection for hours
    // asking nothing. Twice a minute we compare the fingerprints of connected
    // owners with what the database says and evict the ones that no longer match.
    Timer::add(30, function () use ($worker) {
        // We walk EVERY connection rather than the table by host_id: after a backup is
        // restored two phones share one host_id, and the table keeps only the one
        // that connected last, leaving the earlier one hanging unnoticed.
        $bound = [];                                   // cache for a single pass
        $seen = 0; $withHost = 0; $withFp = 0;
        foreach ($worker->connections as $c) {
            $seen++;
            if (($c->host_id ?? null) !== null) $withHost++;
            if (($c->device_fp ?? '') !== '') $withFp++;
            $hid = $c->host_id ?? null;
            $fp  = $c->device_fp ?? '';
            if ($hid === null || $fp === '') continue;  // leave guests and older versions alone
            if (!array_key_exists($hid, $bound)) {
                $st = db()->prepare('SELECT bound_device_fp FROM hosts WHERE id = ?');
                $st->execute([(int)$hid]);
                $bound[$hid] = (string)($st->fetchColumn() ?: '');
            }
            if ($bound[$hid] !== '' && !hash_equals($bound[$hid], $fp)) {
                echo date('c') . " evicted host $hid: fingerprint " . substr($fp, 0, 10) .
                     " is no longer the owner\n";
                // close with data: workerman sends the frame first, then closes.
                $c->close(json_encode(['type' => 'evicted']));
            }
        }
        $detail = [];
        foreach ($worker->connections as $c) {
            if (($c->host_id ?? null) === null) continue;
            $detail[] = $c->host_id . ':' . (($c->device_fp ?? '') !== ''
                ? substr($c->device_fp, 0, 8) : 'no-fingerprint');
        }
        echo date('c') . " watchdog: connections $seen, hosts $withHost, with fingerprint $withFp — "
             . implode(', ', $detail) . "\n";
    });

    Timer::add(1, function () use (&$hosts, &$guests, &$calls) {
        $st = db()->query(
            'SELECT pa.id, pa.host_id, pa.number_id, pa.user_key_id, pa.source, pa.actor,
                    o.name AS org_name
             FROM pending_actions pa
             LEFT JOIN user_keys uk ON uk.id = pa.user_key_id
             LEFT JOIN orgs o ON o.id = uk.org_id
             WHERE pa.created_at > DATE_SUB(NOW(), INTERVAL 30 SECOND)
             ORDER BY pa.id ASC LIMIT 50'
        );
        $rows = $st->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $r) {
            db()->prepare('DELETE FROM pending_actions WHERE id = ?')->execute([$r['id']]);
            $host = $hosts[(int)$r['host_id']] ?? null;
            if (!$host) continue;
            $call_id = bin2hex(random_bytes(8));
            $calls[$call_id] = [
                'guest_oid'   => null,
                'user_key_id' => (int)$r['user_key_id'],
                'number_id'   => (int)$r['number_id'],
            ];
            // An opening by a company is labelled with its name and employee: "org_api"
            // tells the owner nothing.
            $isOrg = !empty($r['org_name']);
            $host->send(json_encode([
                'type'        => 'do_call',
                'call_id'     => $call_id,
                'number_id'   => (int)$r['number_id'],
                'user_key_id' => (int)$r['user_key_id'],
                'guest_label' => $isOrg ? $r['org_name'] : $r['source'],
                'org'         => $isOrg ? 1 : 0,
                'actor'       => (string)($r['actor'] ?? ''),
            ], JSON_UNESCAPED_UNICODE));
        }
        db()->query('DELETE FROM pending_actions WHERE created_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)');

        $ns = db()->query(
            'SELECT id, kind, user_key_id FROM pending_notifications
             WHERE created_at > DATE_SUB(NOW(), INTERVAL 60 SECOND)
             ORDER BY id ASC LIMIT 100'
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($ns as $n) {
            db()->prepare('DELETE FROM pending_notifications WHERE id = ?')->execute([$n['id']]);
            $ukid = (int)$n['user_key_id'];
            if ($n['kind'] === 'key_revoked') {
                foreach ($guests as $oid => $g) {
                    if (isset($g->user_key_id) && $g->user_key_id === $ukid) {
                        $g->send(json_encode(['type' => 'error', 'reason' => 'bad_key']));
                        $g->close();
                    }
                }
                continue;
            }
            if ($n['kind'] === 'key_mode_changed') {
                $st = db()->prepare('SELECT mode FROM user_keys WHERE id = ?');
                $st->execute([$ukid]);
                $newMode = $st->fetchColumn() ?: 'auto';
                foreach ($guests as $g) {
                    if (isset($g->user_key_id) && $g->user_key_id === $ukid) {
                        $g->key_mode = $newMode;
                        $g->send(json_encode(['type' => 'mode_update', 'mode' => $newMode]));
                    }
                }
                continue;
            }
            if ($n['kind'] === 'message_read' || $n['kind'] === 'message_delivered') {
                // The guest confirmed delivery or reading — tell the owner.
                $st = db()->prepare('SELECT host_id FROM user_keys WHERE id = ?');
                $st->execute([$ukid]);
                $hid = (int)$st->fetchColumn();
                $host = $hosts[$hid] ?? null;
                if ($host) {
                    try {
                        $host->send(json_encode([
                            'type'        => $n['kind'],
                            'user_key_id' => $ukid,
                        ]));
                    } catch (\Throwable $e) {}
                }
                continue;
            }
            if ($n['kind'] === 'key_delegated') {
                // The guest passed access on. For the owner this is both news and work:
                // only they can assemble the bundle for the new key.
                $st = db()->prepare(
                    'SELECT host_id, parent_key_id FROM user_keys WHERE id = ?'
                );
                $st->execute([$ukid]);
                $row = $st->fetch(PDO::FETCH_ASSOC) ?: [];
                $host = $hosts[(int)($row['host_id'] ?? 0)] ?? null;
                if ($host) {
                    try {
                        $host->send(json_encode([
                            'type'          => 'key_delegated',
                            'user_key_id'   => $ukid,
                            'parent_key_id' => (int)($row['parent_key_id'] ?? 0),
                        ]));
                    } catch (\Throwable $e) {}
                }
                continue;
            }
            if ($n['kind'] === 'key_updated') {
                $st = db()->prepare(
                    'SELECT n.id, n.type, n.device_id, n.data_cipher
                     FROM key_numbers kn
                     JOIN numbers n ON n.id = kn.number_id
                     WHERE kn.user_key_id = ?'
                );
                $st->execute([$ukid]);
                $nums = [];
                foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $nr) {
                    $nums[] = [
                        'id'              => (int)$nr['id'],
                        'type'            => $nr['type'],
                        'device_id'       => $nr['device_id'] !== null ? (int)$nr['device_id'] : null,
                        'data_cipher'     => $nr['data_cipher'],
                    ];
                }
                foreach ($guests as $g) {
                    if (isset($g->user_key_id) && $g->user_key_id === $ukid) {
                        $g->send(json_encode([
                            'type'    => 'numbers_update',
                            'numbers' => $nums,
                        ]));
                    }
                }
            }
        }
        db()->query('DELETE FROM pending_notifications WHERE created_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)');
    });


    // Messages reach a guest over FCM now (api/message_send.php both stores a row
    // and pushes). The client confirms receipt through api/message_ack.php →
    // pending_notifications kind=message_read, and the worker below delivers
    // "message_read" to an owner who is online.

    // TTL: once an hour messages older than 7 days are deleted. Before that,
    // owners who are online get "message_expired" so the interface shows
    // "not delivered" instead of a stuck "Sent".
    Timer::add(3600, function () use (&$hosts) {
        $rows = db()->query(
            'SELECT host_id, user_key_id FROM guest_messages
             WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)'
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $r) {
            $host = $hosts[(int)$r['host_id']] ?? null;
            if ($host) {
                try {
                    $host->send(json_encode([
                        'type'        => 'message_expired',
                        'user_key_id' => (int)$r['user_key_id'],
                    ]));
                } catch (\Throwable $e) {}
            }
        }
        db()->exec(
            'DELETE FROM guest_messages WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)'
        );
    });

    // Heartbeat for PHONES (host/guest): the server pings every 10s and reaps the
    // silent after 20s — fast presence. There are few of them and they expect it.
    Timer::add(10, function () use (&$hosts, &$guests) {
        $now = time();
        foreach (array_merge(array_values($hosts), array_values($guests)) as $c) {
            if (isset($c->lastPong) && $now - $c->lastPong > 20) {
                $c->close();
                continue;
            }
            try { $c->send(json_encode(['type' => 'ping'])); } catch (\Throwable $e) { $c->close(); }
        }
    });
    // Heartbeat for CONTROLLERS: the server does NOT ping them — a fan-out of O(N)
    // does not scale to tens of thousands of boards. A board sends {type:ping}
    // itself every 30s (the server answers pong, see case 'ping'), and here we
    // only passively close those silent for more than 90s. No sends at all,
    // just a comparison of timestamps.
    Timer::add(30, function () use (&$devices) {
        $now = time();
        foreach ($devices as $c) {
            if (isset($c->lastPong) && $now - $c->lastPong > 90) $c->close();
        }
    });
};

/** Anti-flap for hello messages. If the same client sends host_hello or
 *  guest_hello more often than once per HELLO_MIN_INTERVAL_S seconds, the
 *  connection is closed without touching the database. This guards against a
 *  reconnect storm: while the websocket flaps a client could throw a hello at
 *  the server every second or two, each costing a TLS handshake and a SELECT
 *  over hosts/user_keys. Kept in the worker's memory, keyed by device_id for a
 *  host or user_key for a guest. Survives a flap, not a worker restart — which
 *  is acceptable. */
const HELLO_MIN_INTERVAL_S = 5;
$lastHelloAt = [];   // string clientKey => int unixSec

$worker->onMessage = function (TcpConnection $c, $data) use (&$hosts, &$guests, &$calls, &$devices, &$lastHelloAt) {
    $c->lastPong = time();
    $msg = json_decode($data, true);
    if (!is_array($msg) || empty($msg['type'])) {
        $c->send(json_encode(['type' => 'error', 'reason' => 'bad_msg']));
        return;
    }

    // Anti-flap throttle. host_hello and guest_hello are the heaviest messages
    // (a database lookup plus a state update). Every other type passes unchecked.
    $type = $msg['type'];
    if ($type === 'host_hello' || $type === 'guest_hello') {
        $clientKey = $type === 'host_hello'
            ? ('h:' . (string)($msg['device_id'] ?? ''))
            : ('g:' . (string)($msg['user_key'] ?? ''));
        $now = time();
        $prev = $lastHelloAt[$clientKey] ?? 0;
        if ($now - $prev < HELLO_MIN_INTERVAL_S) {
            // Hello too often: close quietly, without an answer. The client reconnects
            // on its own backoff, which grows since 6.62.
            $c->close();
            return;
        }
        $lastHelloAt[$clientKey] = $now;
        // Clean out old entries every 200 messages so the map does not grow.
        if (count($lastHelloAt) > 10000) {
            $cutoff = $now - 60;
            foreach ($lastHelloAt as $k => $t) {
                if ($t < $cutoff) unset($lastHelloAt[$k]);
            }
        }
    }

    switch ($msg['type']) {

        case 'host_hello': {
            $device_id = (string)($msg['device_id'] ?? '');
            $secret    = (string)($msg['device_secret'] ?? '');
            $fcm       = (string)($msg['fcm_token'] ?? '');
            if ($device_id === '' || $secret === '') { $c->close(); return; }

            $fp        = (string)($msg['device_fp'] ?? '');
            $st = db()->prepare('SELECT id, secret_hash, bound_device_fp FROM hosts WHERE device_id = ?');
            $st->execute([$device_id]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row || !hash_equals($row['secret_hash'], hash('sha256', $secret))) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'auth']));
                $c->close();
                return;
            }
            $c->role    = 'host';
            $c->host_id = (int)$row['id'];
            $c->clientLang = (string)($msg['lang'] ?? '');
            $hosts[$c->host_id] = $c;

            // Moving to another phone: the new handset took the access and this one is
            // the old one. We say so right here instead of waiting to be asked.
            // An empty fingerprint (older versions) is left alone — they know nothing of this.
            $c->device_fp = $fp;
            if ($fp !== '' && !empty($row['bound_device_fp'])
                && !hash_equals((string)$row['bound_device_fp'], $fp)) {
                echo date('c') . " evicted on connect: host {$c->host_id}, fingerprint "
                     . substr($fp, 0, 10) . "\n";
                $c->send(json_encode(['type' => 'evicted']));
                // Not closed immediately: closing on the same tick risks cutting the frame
                // before the phone has parsed it. A second is plenty.
                Timer::add(1, function () use ($c) { $c->close(); }, [], false);
                return;
            }

            // End-to-end encryption: the IP is no longer stored, the last_ip column is gone.
            $upd = db()->prepare('UPDATE hosts SET last_seen = NOW(), fcm_token = COALESCE(NULLIF(?, ""), fcm_token) WHERE id = ?');
            $upd->execute([$fcm, $c->host_id]);

            $c->send(json_encode(['type' => 'host_ok']));

            // Snapshot of this host's online devices (for the green dots in the interface)
            $onlineIds = [];
            foreach ($devices as $did => $dc) {
                if (isset($dc->host_id) && $dc->host_id === $c->host_id) {
                    $onlineIds[] = (int)$did;
                }
            }
            $c->send(json_encode([
                'type' => 'devices_online',
                'device_ids' => $onlineIds,
            ]));

            foreach ($guests as $g) {
                if (isset($g->host_id) && $g->host_id === $c->host_id) {
                    $g->send(json_encode(['type' => 'host_status', 'online' => true]));
                }
            }

            // Drain pending host messages from the database (ble_token_renew, ble_fire_event
            // and anything else queued for the owner). Survives a restart of the PHP
            // worker. Rows are removed only after a successful send.
            flushHostQueue($c, (int)$c->host_id);
            break;
        }

        case 'guest_hello': {
            $key = (string)($msg['user_key'] ?? '');
            $deviceFp = (string)($msg['device_fp'] ?? '');
            if ($key === '') { $c->close(); return; }
            $hash = hash('sha256', $key);

            $st = db()->prepare(
                'SELECT uk.id, uk.host_id, uk.mode, uk.bound_device_fp, uk.native_only,
                        uk.org_id, uk.expires_at
                 FROM user_keys uk
                 WHERE uk.key_hash = ? AND uk.enabled = 1'
            );
            $st->execute([$hash]);
            $uk = $st->fetch(PDO::FETCH_ASSOC);
            if (!$uk) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'bad_key']));
                $c->close();
                return;
            }
            // A company's key lives on the company's own server and works only through
            // api/company.php with its secret. Even if the key string leaked from the
            // owner's app, it cannot open anything.
            if (!empty($uk['org_id'])) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'org_key']));
                $c->close();
                return;
            }
            // Key lifetime. The field is not filled in yet, but the check is in place.
            if (!empty($uk['expires_at']) && strtotime($uk['expires_at']) < time()) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'expired']));
                $c->close();
                return;
            }
            // native_only — a key for the native app only. The app signs its hello with
            // an attestation: attest = HMAC(app_attest_secret, user_key|ts). The browser
            // client does not know the secret, so it is turned away. Forging it means
            // decompiling the installable file.
            if ((int)($uk['native_only'] ?? 0) === 1) {
                $ts = (int)($msg['ts'] ?? 0);
                $attest = (string)($msg['attest'] ?? '');
                $expect = hash_hmac('sha256', $key . '|' . $ts, $GLOBALS['app_attest_secret']);
                if ($ts <= 0 || abs(time() - $ts) > 120 || $attest === '' || !hash_equals($expect, $attest)) {
                    $c->send(json_encode(['type' => 'error', 'reason' => 'native_only']));
                    $c->close();
                    return;
                }
            }
            // Device binding: the key belongs to one device. If bound_device_fp is
            // already stored:
            //   - a missing or mismatched device_fp is refused (passing without a
            //     fingerprint must be impossible, otherwise an old or forged client
            //     would sidestep the check by omitting the field). If nothing is
            //     bound yet, the connection passes and key_bind will bind it.
            $boundFp = (string)($uk['bound_device_fp'] ?? '');
            // Automatic binding on the first websocket connection when nothing is stored.
            // This covers keys created before the client-side protection existed: the
            // first device to connect gets bound, and any later one with a different
            // fingerprint is turned away with already_bound.
            if ($boundFp === '' && $deviceFp !== '') {
                db()->prepare(
                    'UPDATE user_keys SET bound_device_fp = ?, bound_at = NOW() WHERE id = ?'
                )->execute([$deviceFp, $uk['id']]);
                $boundFp = $deviceFp;
            }
            if ($boundFp !== '' && ($deviceFp === '' || !hash_equals($boundFp, $deviceFp))) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'already_bound']));
                $c->close();
                return;
            }

            $st = db()->prepare(
                'SELECT n.id, n.type, n.device_id, n.data_cipher
                 FROM key_numbers kn
                 JOIN numbers n ON n.id = kn.number_id
                 WHERE kn.user_key_id = ?'
            );
            $st->execute([$uk['id']]);
            $nums = [];
            foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $n) {
                $nums[] = [
                    'id'              => (int)$n['id'],
                    'type'            => $n['type'],
                    'device_id'       => $n['device_id'] !== null ? (int)$n['device_id'] : null,
                    'data_cipher'     => $n['data_cipher'],
                ];
            }

            $c->role        = 'guest';
            $c->user_key_id = (int)$uk['id'];
            $c->host_id     = (int)$uk['host_id'];
            $c->guest_label = '';
            $c->key_mode    = $uk['mode'] ?: 'auto';
            $guests[spl_object_id($c)] = $c;

            // End-to-end encryption: the owner's name now reaches the guest inside
            // bundle_cipher (host_label) rather than in the clear from hosts.label
            // or uk.label.
            $c->send(json_encode([
                'type'    => 'guest_ok',
                'numbers' => $nums,
                'mode'    => $uk['mode'] ?: 'auto',
            ]));
            $hostOnline = isset($hosts[$c->host_id]);
            $statusMsg = ['type' => 'host_status', 'online' => $hostOnline];
            if (!$hostOnline) {
                $st2 = db()->prepare('SELECT last_seen FROM hosts WHERE id = ?');
                $st2->execute([$c->host_id]);
                $ls = $st2->fetchColumn();
                if ($ls) $statusMsg['last_seen'] = $ls;
            }
            $c->send(json_encode($statusMsg));
            // Snapshot of this host's online devices — a guest sees them too, so the red
            // and green status dot on device objects is shown correctly.
            $onlineIdsG = [];
            foreach ($devices as $did2 => $dc2) {
                if (isset($dc2->host_id) && $dc2->host_id === $c->host_id) {
                    $onlineIdsG[] = (int)$did2;
                }
            }
            $c->send(json_encode([
                'type' => 'devices_online',
                'device_ids' => $onlineIdsG,
            ]));
            break;
        }

        case 'call': {
            if ($c->role !== 'guest') { return; }
            $number_id = (int)($msg['number_id'] ?? 0);

            $st = db()->prepare('SELECT mode, force_when_busy FROM user_keys WHERE id = ?');
            $st->execute([$c->user_key_id]);
            $ukRow = $st->fetch(PDO::FETCH_ASSOC);
            $current_mode = ($ukRow['mode'] ?? '') ?: 'auto';
            $force_busy = (int)($ukRow['force_when_busy'] ?? 0);
            $c->key_mode = $current_mode;
            if ($current_mode === 'off') {
                $c->send(json_encode(['type' => 'error', 'reason' => 'disabled']));
                return;
            }

            $st = db()->prepare(
                'SELECT n.type, n.webhook_url, n.webhook_secret,
                        n.webhook_mode, n.device_id
                 FROM key_numbers kn
                 JOIN numbers n ON n.id = kn.number_id
                 WHERE kn.user_key_id = ? AND kn.number_id = ?'
            );
            $st->execute([$c->user_key_id, $number_id]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'forbidden']));
                return;
            }
            $obj_type = $row['type'] ?: 'call';

            $st = db()->prepare(
                'SELECT COUNT(*) FROM call_log
                 WHERE user_key_id = ? AND ts > DATE_SUB(NOW(), INTERVAL 1 MINUTE)'
            );
            $st->execute([$c->user_key_id]);
            if ((int)$st->fetchColumn() >= $GLOBALS['rate_limit_per_min']) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'rate_limit']));
                return;
            }

            $call_id = bin2hex(random_bytes(8));
            $calls[$call_id] = [
                'guest_oid'   => spl_object_id($c),
                'user_key_id' => $c->user_key_id,
                'number_id'   => $number_id,
                // Whose call this is: only the owner of this object may confirm it, not
                // anyone who happens to hold an owner connection.
                'host_id'     => $c->host_id,
            ];

            $ins = db()->prepare('INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)');
            $ins->execute([$c->user_key_id, $number_id, 'requested']);

            if ($obj_type === 'webhook') {
                whlog("GUEST guest_oid=" . spl_object_id($c) . " num=$number_id mode={$row['webhook_mode']} url_set=" . (!empty($row['webhook_url']) ? 1 : 0));
            }
            // ── Type: webhook from the server (asynchronous) ──
            if ($obj_type === 'webhook' && $row['webhook_mode'] === 'server'
                && $row['webhook_url']) {
                $whSecret = $row['webhook_secret'] ?: '';
                $payloadArr = ['action' => 'open', 'object_id' => $number_id];
                if ($whSecret !== '') {
                    $payloadArr['timestamp'] = time();
                    $payloadArr['nonce'] = bin2hex(random_bytes(8));
                    // The signature is HMAC-SHA256 over the canonical string "ts.nonce.action.object_id"
                    // rather than raw JSON, so the receiver need not reproduce the
                    // serialisation byte for byte. It builds the same string, computes the
                    // HMAC, compares with hash_equals and requires |now - timestamp| < 300s
                    // against replay. Specification: entrixy.com/webhook
                    $signBase = $payloadArr['timestamp'] . '.' . $payloadArr['nonce'] . '.'
                              . $payloadArr['action'] . '.' . $payloadArr['object_id'];
                    $payloadArr['signature'] = hash_hmac('sha256', $signBase, $whSecret);
                }
                $payload = json_encode($payloadArr);

                $parsed = parse_url($row['webhook_url']);
                // SSRF shield on send: older rows could have been stored before the filter
                // existed, and a domain can start resolving to an internal address.
                if (ssrf_host_blocked($parsed['host'] ?? '')) {
                    whlog("GUEST webhook blocked (ssrf): " . ($parsed['host'] ?? ''));
                    try { $c->send(json_encode(['type'=>'device_status','call_id'=>$call_id,'level'=>'danger','message'=>'webhook target not allowed','final'=>true])); } catch (\Throwable $e) {}
                    unset($calls[$call_id]);
                    return;
                }
                $scheme = ($parsed['scheme'] ?? 'http') === 'https' ? 'ssl' : 'tcp';
                $whHost = $parsed['host'] ?? '';
                $whPort = $parsed['port'] ?? ($scheme === 'ssl' ? 443 : 80);
                $whPath = ($parsed['path'] ?? '/') . (isset($parsed['query']) ? '?'.$parsed['query'] : '');

                $guestConn = $c;
                $hostId = $c->host_id;
                try {
                    $http = new AsyncTcpConnection("$scheme://$whHost:$whPort");
                    if ($scheme === 'ssl') {
                        $http->transport = 'ssl';
                    }
                    // Watchdog: if the webhook target stays silent the call is closed after 15
                    // seconds, so $calls[] does not pile up and leak memory.
                    $watchdog = Timer::add(15, function () use ($http, $call_id, $guestConn, &$calls) {
                        try { $http->close(); } catch (\Throwable $e) {}
                        try {
                            $guestConn->send(json_encode([
                                'type' => 'device_status', 'call_id' => $call_id,
                                'level' => 'danger', 'message' => 'webhook timeout',
                                'final' => true,
                            ]));
                        } catch (\Throwable $e) {}
                        unset($calls[$call_id]);
                    }, [], false);
                    $httpBuffer = '';
                    $http->onConnect = function ($conn) use ($whHost, $whPath, $payload) {
                        $len = strlen($payload);
                        $conn->send(
                            "POST $whPath HTTP/1.1\r\n" .
                            "Host: $whHost\r\n" .
                            "Content-Type: application/json\r\n" .
                            "Content-Length: $len\r\n" .
                            "Connection: close\r\n\r\n" .
                            $payload
                        );
                    };
                    $http->onMessage = function ($conn, $data) use (&$httpBuffer) {
                        $httpBuffer .= $data;
                    };
                    $http->onClose = function () use (
                        &$httpBuffer, $guestConn, $call_id, $number_id,
                        &$hosts, $hostId, &$calls, &$watchdog
                    ) {
                        if ($watchdog !== null) { Timer::del($watchdog); $watchdog = null; }
                        list($headers, $body) = parseHttpResponse($httpBuffer);
                        if (stripos($headers, 'transfer-encoding: chunked') !== false) {
                            $body = decodeChunked($body);
                        }
                        $result = json_decode($body, true);
                        // New format: {level: success|warning|danger|info, message}.
                        // Legacy: {status: ok|error, message} — mapped onto level.
                        $level = (string)($result['level'] ?? '');
                        if (!in_array($level, ['success','warning','danger','info'], true)) {
                            $level = (($result['status'] ?? '') === 'ok') ? 'success' : 'danger';
                        }
                        $message = (string)($result['message'] ?? ($body ?: 'no response'));
                        $info = $calls[$call_id] ?? null;
                        // position in the response — for bistable webhook objects.
                        // If present and different from last_state: update and broadcast.
                        $whPosition = $result['position'] ?? null;
                        if ($whPosition !== null && in_array($whPosition, ['open','closed','unknown'], true)) {
                            try {
                                applyObjectState($hostId, $number_id, $whPosition, $hosts, $guests);
                            } catch (\Throwable $e) { whlog("applyObjectState err: ".$e->getMessage()); }
                        }
                        // To the guest it goes as device_status, the same semantics a controller uses.
                        // number_id lets the client attach the status to the card as an inline
                        // status; without it the message lands in the global toast and vanishes.
                        try {
                            $guestConn->send(json_encode([
                                'type'      => 'device_status',
                                'call_id'   => $call_id,
                                'number_id' => $number_id,
                                'level'     => $level,
                                'message'   => $message,
                                'final'     => true,
                            ]));
                        } catch (\Throwable $e) {}
                        // The owner gets it silently: for the log, with no toast and no inline status.
                        // They should not see the interface response to someone else's
                        // webhook, but the line "guest X opened object Y: <result>" does
                        // belong in the log on their phone.
                        $host = $hosts[$hostId] ?? null;
                        if ($host) {
                            try {
                                $host->send(json_encode([
                                    'type'         => 'device_status',
                                    'call_id'      => $call_id,
                                    'number_id'    => $number_id,
                                    'user_key_id'  => $guestConn->user_key_id ?? 0,
                                    'level'        => $level,
                                    'message'      => $message,
                                    'final'        => true,
                                    'silent'       => true,
                                ]));
                            } catch (\Throwable $e) {}
                        }
                        if ($info && (int)($info['user_key_id'] ?? 0) > 0) {
                            $ins = db()->prepare('INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)');
                            $ins->execute([$info['user_key_id'], $info['number_id'], 'webhook_' . $level]);
                        }
                        unset($calls[$call_id]);
                    };
                    $http->onError = function ($conn, $code, $msg) use (
                        $guestConn, $call_id, &$calls, &$watchdog
                    ) {
                        if ($watchdog !== null) { Timer::del($watchdog); $watchdog = null; }
                        try {
                            $guestConn->send(json_encode([
                                'type'    => 'device_status',
                                'call_id' => $call_id,
                                'level'   => 'danger',
                                'message' => "connect error: $msg",
                                'final'   => true,
                            ]));
                        } catch (\Throwable $e) {}
                        unset($calls[$call_id]);
                    };
                    $http->connect();
                } catch (\Throwable $e) {
                    $c->send(json_encode([
                        'type'    => 'device_status',
                        'call_id' => $call_id,
                        'level'   => 'danger',
                        'message' => $e->getMessage(),
                        'final'   => true,
                    ]));
                    unset($calls[$call_id]);
                }
                // Tell the guest right away that the request is on its way
                $c->send(json_encode([
                    'type' => 'call_status', 'call_id' => $call_id, 'status' => 'sending',
                ]));
                break;
            }

            // ── Type: controller ──
            if ($obj_type === 'device' && $row['device_id']) {
                $dev = $devices[(int)$row['device_id']] ?? null;
                if (!$dev) {
                    $c->send(json_encode(['type' => 'error', 'reason' => 'device_offline']));
                    break;
                }
                // device_id goes into $calls so sock_fire can be routed back to the controller.
                $calls[$call_id]['device_id'] = (int)$row['device_id'];
                if (!empty($dev->sock_e2ee)) {
                    // End-to-end encryption: the controller is asked for a nonce. The guest then
                    // signs it with their guest key and sends sock_fire; the server relays
                    // the signature without understanding it and cannot forge one.
                    $dev->send(json_encode([
                        'type' => 'sock_challenge_req',
                        'command_id' => $call_id, 'number_id' => $number_id,
                    ]));
                    $c->send(json_encode(['type' => 'call_status', 'call_id' => $call_id, 'status' => 'challenge_pending']));
                } else {
                    // Older firmware without encryption takes a plain command, trusting the server.
                    $dev->send(json_encode([
                        'type' => 'device_command', 'action' => 'open',
                        'command_id' => $call_id, 'number_id' => $number_id,
                    ]));
                    $c->send(json_encode(['type' => 'call_status', 'call_id' => $call_id, 'status' => 'sent_to_device']));
                }
                // To the owner, for the log
                $host = $hosts[$c->host_id] ?? null;
                if ($host) {
                    $host->send(json_encode([
                        'type' => 'device_sent', 'call_id' => $call_id,
                        'number_id' => $number_id,
                        'user_key_id' => $c->user_key_id,
                    ]));
                }
                break;
            }

            // ── Type: webhook from the owner's phone ──
            if ($obj_type === 'webhook') {
                $host = $hosts[$c->host_id] ?? null;
                if (!$host) {
                    whlog("GUEST call=$call_id num=$number_id reject: host offline");
                    $c->send(json_encode(['type' => 'error', 'reason' => 'host_offline']));
                    break;
                }
                whlog("GUEST call=$call_id num=$number_id → forward do_webhook to host");
                $host->send(json_encode([
                    'type'         => 'do_webhook',
                    'call_id'      => $call_id,
                    'number_id'    => $number_id,
                    'user_key_id'  => $c->user_key_id,
                ]));
                $c->send(json_encode(['type' => 'call_status', 'call_id' => $call_id, 'status' => 'sent_to_host']));
                break;
            }

            // ── Type: a phone call, as before ──
            $host = $hosts[$c->host_id] ?? null;
            if (!$host) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'host_offline']));
                break;
            }

            if ($current_mode === 'confirm') {
                $host->send(json_encode([
                    'type'         => 'confirm_request',
                    'call_id'      => $call_id,
                    'number_id'    => $number_id,
                    'user_key_id'  => $c->user_key_id,
                ]));
                $c->send(json_encode(['type' => 'call_status', 'call_id' => $call_id, 'status' => 'awaiting_confirm']));
            } else {
                $host->send(json_encode([
                    'type'            => 'do_call',
                    'call_id'         => $call_id,
                    'number_id'       => $number_id,
                    'user_key_id'     => $c->user_key_id,
                    'notify'          => ($current_mode === 'notify'),
                    'force_when_busy' => $force_busy === 1,
                ]));
                $c->send(json_encode(['type' => 'call_status', 'call_id' => $call_id, 'status' => 'requested']));
            }
            break;
        }

        case 'host_self_webhook': {
            // The owner asks the server to fire the webhook for their own object.
            // The result goes back as device_status for the log on the phone.
            whlog("OWN host_id={$c->host_id} num=" . (int)($msg['number_id'] ?? 0) . " RECV");
            if ($c->role !== 'host') { whlog('OWN reject: not host'); return; }
            $number_id = (int)($msg['number_id'] ?? 0);
            if ($number_id <= 0) { whlog('OWN reject: bad number_id'); return; }
            $st = db()->prepare(
                'SELECT id, type, webhook_url, webhook_secret, webhook_mode
                 FROM numbers WHERE id = ? AND host_id = ?'
            );
            $st->execute([$number_id, $c->host_id]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                whlog("OWN num=$number_id reject: number not found for host {$c->host_id}");
                $c->send(json_encode(['type' => 'error', 'reason' => 'not_webhook']));
                break;
            }
            if ($row['type'] !== 'webhook') {
                whlog("OWN num=$number_id reject: type={$row['type']} (expected webhook)");
                $c->send(json_encode(['type' => 'error', 'reason' => 'not_webhook']));
                break;
            }
            if (!$row['webhook_url']) {
                whlog("OWN num=$number_id reject: webhook_url empty (mode={$row['webhook_mode']})");
                $c->send(json_encode(['type' => 'error', 'reason' => 'not_webhook']));
                break;
            }
            $whUrl = $row['webhook_url'];
            $whSecret = $row['webhook_secret'] ?: '';
            whlog("OWN num=$number_id url=$whUrl secret_len=" . strlen($whSecret));

            $call_id = bin2hex(random_bytes(8));
            $calls[$call_id] = [
                'guest_oid'   => null,
                'user_key_id' => 0,
                'number_id'   => $number_id,
            ];

            $payloadArr = ['action' => 'open', 'object_id' => $number_id];
            if ($whSecret !== '') {
                $payloadArr['timestamp'] = time();
                $payloadArr['nonce'] = bin2hex(random_bytes(8));
                // Signature = HMAC-SHA256("ts.nonce.action.object_id"). Spec: entrixy.com/webhook
                $signBase = $payloadArr['timestamp'] . '.' . $payloadArr['nonce'] . '.'
                          . $payloadArr['action'] . '.' . $payloadArr['object_id'];
                $payloadArr['signature'] = hash_hmac('sha256', $signBase, $whSecret);
            }
            $payload = json_encode($payloadArr);

            $parsed = parse_url($whUrl);
            if (ssrf_host_blocked($parsed['host'] ?? '')) {
                whlog("OWN webhook blocked (ssrf): " . ($parsed['host'] ?? ''));
                try { $c->send(json_encode(['type'=>'device_status','call_id'=>$call_id,'level'=>'danger','message'=>'webhook target not allowed','final'=>true])); } catch (\Throwable $e) {}
                unset($calls[$call_id]);
                return;
            }
            $scheme = ($parsed['scheme'] ?? 'http') === 'https' ? 'ssl' : 'tcp';
            $whHost = $parsed['host'] ?? '';
            $whPort = $parsed['port'] ?? ($scheme === 'ssl' ? 443 : 80);
            $whPath = ($parsed['path'] ?? '/') . (isset($parsed['query']) ? '?'.$parsed['query'] : '');

            $hostConn = $c;
            $hostId = $c->host_id;
            try {
                $http = new AsyncTcpConnection("$scheme://$whHost:$whPort");
                if ($scheme === 'ssl') $http->transport = 'ssl';
                // Watchdog of 15s: a hung webhook is closed so memory does not leak.
                $watchdog = Timer::add(15, function () use ($http, $call_id, $hostConn, $number_id, &$calls) {
                    try { $http->close(); } catch (\Throwable $e) {}
                    try {
                        $hostConn->send(json_encode([
                            'type' => 'device_status', 'call_id' => $call_id,
                            'number_id' => $number_id,
                            'level' => 'danger', 'message' => 'webhook timeout',
                            'final' => true,
                        ]));
                    } catch (\Throwable $e) {}
                    unset($calls[$call_id]);
                    whlog("OWN call=$call_id TIMEOUT");
                }, [], false);
                $httpBuffer = '';
                $http->onConnect = function ($conn) use ($whHost, $whPath, $payload, $call_id) {
                    whlog("OWN call=$call_id CONNECTED, sending POST");
                    $len = strlen($payload);
                    $conn->send(
                        "POST $whPath HTTP/1.1\r\n" .
                        "Host: $whHost\r\n" .
                        "Content-Type: application/json\r\n" .
                        "Content-Length: $len\r\n" .
                        "Connection: close\r\n\r\n" .
                        $payload
                    );
                };
                $http->onMessage = function ($conn, $data) use (&$httpBuffer, $call_id) {
                    $httpBuffer .= $data;
                };
                $http->onClose = function () use (
                    &$httpBuffer, $hostConn, $call_id, $number_id, &$calls, &$watchdog
                ) {
                    if ($watchdog !== null) { Timer::del($watchdog); $watchdog = null; }
                    whlog("OWN call=$call_id CLOSED, buffer_len=" . strlen($httpBuffer));
                    list($headers, $body) = parseHttpResponse($httpBuffer);
                    $chunked = stripos($headers, 'transfer-encoding: chunked') !== false;
                    if ($chunked) {
                        $body = decodeChunked($body);
                    }
                    $result = json_decode($body, true);
                    $level = (string)($result['level'] ?? '');
                    if (!in_array($level, ['success','warning','danger','info'], true)) {
                        $level = (($result['status'] ?? '') === 'ok') ? 'success' : 'danger';
                    }
                    $message = (string)($result['message'] ?? ($body ?: 'no response'));
                    whlog("OWN call=$call_id RESULT chunked=$chunked level=$level msg=" . substr($message, 0, 120));
                    try {
                        $hostConn->send(json_encode([
                            'type'         => 'device_status',
                            'call_id'      => $call_id,
                            'number_id'    => $number_id,
                            'level'        => $level,
                            'message'      => $message,
                            'final'        => true,
                        ]));
                    } catch (\Throwable $e) {}
                    $ins = db()->prepare('INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)');
                    $ins->execute([0, $number_id, 'webhook_' . $level]);
                    unset($calls[$call_id]);
                };
                $http->onError = function ($conn, $code, $msg) use ($hostConn, $call_id, &$watchdog) {
                    if ($watchdog !== null) { Timer::del($watchdog); $watchdog = null; }
                    whlog("OWN call=$call_id CONNECT_ERROR code=$code msg=$msg");
                    try {
                        $hostConn->send(json_encode([
                            'type'    => 'device_status',
                            'call_id' => $call_id,
                            'level'   => 'danger',
                            'message' => "connect failed: $msg",
                            'final'   => true,
                        ]));
                    } catch (\Throwable $e) {}
                };
                $http->connect();
            } catch (\Throwable $e) {
                $c->send(json_encode([
                    'type' => 'device_status',
                    'call_id' => $call_id,
                    'level' => 'danger',
                    'message' => 'webhook init: ' . $e->getMessage(),
                    'final' => true,
                ]));
            }
            $c->send(json_encode([
                'type' => 'device_sent', 'call_id' => $call_id,
                'number_id' => $number_id, 'number_label' => $number_label,
                'guest_label' => '',
            ]));
            break;
        }

        case 'host_self_call': {
            if ($c->role !== 'host') { return; }
            $number_id = (int)($msg['number_id'] ?? 0);
            if ($number_id <= 0) { return; }

            $st = db()->prepare(
                'SELECT id, type, device_id
                 FROM numbers
                 WHERE id = ? AND host_id = ?'
            );
            $st->execute([$number_id, $c->host_id]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'forbidden']));
                break;
            }
            $obj_type = $row['type'] ?: 'call';

            // Controllers only — the other types are handled on the owner's side locally:
            // an ordinary call through TelecomManager, a phone-mode webhook as a
            // direct HTTP request from the client.
            if ($obj_type !== 'device' || !$row['device_id']) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'not_device']));
                break;
            }

            $dev = $devices[(int)$row['device_id']] ?? null;
            if (!$dev) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'device_offline']));
                break;
            }

            $call_id = bin2hex(random_bytes(8));
            $calls[$call_id] = [
                'guest_oid'   => null,
                'host_oid'    => spl_object_id($c),   // owner fire: the challenge goes back to the owner
                'user_key_id' => 0,
                'number_id'   => $number_id,
                'device_id'   => (int)$row['device_id'],
            ];

            if (!empty($dev->sock_e2ee)) {
                // The owner opens through a signature as well. The controller is asked for a
                // nonce, which the owner signs with ownerSecret (proof=HMAC(ownerSecret,nonce)).
                $dev->send(json_encode([
                    'type' => 'sock_challenge_req',
                    'command_id' => $call_id, 'number_id' => $number_id,
                ]));
            } else {
                $dev->send(json_encode([
                    'type' => 'device_command', 'action' => 'open',
                    'command_id' => $call_id, 'number_id' => $number_id,
                ]));
            }
            $c->send(json_encode([
                'type' => 'device_sent', 'call_id' => $call_id,
                'number_id' => $number_id,
            ]));
            break;
        }

        case 'confirm_response': {
            if ($c->role !== 'host') { return; }
            $call_id = (string)($msg['call_id'] ?? '');
            $accept = (bool)($msg['accept'] ?? false);
            if (!isset($calls[$call_id])) { return; }
            $info = $calls[$call_id];
            /* Only the owner of this object confirms. Previously just the role was
               checked: any registered owner who guessed a call number would get
               someone else's do_call in reply, with the object and key numbers in
               it, while the guest saw a false "confirmed". Call numbers are random,
               but there is no need to lean on that — ownership is known exactly. */
            if ((int)($info['host_id'] ?? 0) !== (int)$c->host_id) { return; }
            $guest = null;
            foreach ($guests as $g) {
                if (spl_object_id($g) === $info['guest_oid']) { $guest = $g; break; }
            }
            if ($accept) {
                // The phone number and label are taken by the client locally from data_cipher.
                $c->send(json_encode([
                    'type'         => 'do_call',
                    'call_id'      => $call_id,
                    'number_id'    => $info['number_id'],
                    'user_key_id'  => (int)($info['user_key_id'] ?? 0),
                    'notify'       => false,
                ]));
                if ($guest) $guest->send(json_encode([
                    'type' => 'call_status', 'call_id' => $call_id, 'status' => 'accepted'
                ]));
            } else {
                if ($guest) $guest->send(json_encode([
                    'type' => 'call_status', 'call_id' => $call_id, 'status' => 'declined'
                ]));
                unset($calls[$call_id]);
            }
            break;
        }

        case 'call_status': {
            if ($c->role !== 'host') { return; }
            $call_id = (string)($msg['call_id'] ?? '');
            $status  = (string)($msg['status']  ?? '');
            if (!isset($calls[$call_id])) { return; }

            $ins = db()->prepare('INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)');
            $ins->execute([$calls[$call_id]['user_key_id'], $calls[$call_id]['number_id'], $status]);

            $g = $guests[$calls[$call_id]['guest_oid']] ?? null;
            if ($g) {
                $g->send(json_encode(['type' => 'call_status', 'call_id' => $call_id, 'status' => $status]));
            }
            if (in_array($status, ['ended', 'error'], true)) {
                unset($calls[$call_id]);
            }
            break;
        }

        // ── Encrypted socket: the server relays challenge and signature between the
        //    controller and the guest BLINDLY. It does not understand the crypto and
        //    cannot forge an opening: it holds neither guest_key nor ownerSecret.
        case 'sock_challenge': {
            if ($c->role !== 'device') { return; }
            $cid  = (string)($msg['command_id'] ?? '');
            $info = $calls[$cid] ?? null;
            if (!$info || (int)($info['device_id'] ?? 0) !== $c->device_id) { return; }
            // The challenge goes to whoever started the call: the guest or the owner.
            $target = null;
            if (!empty($info['guest_oid'])) $target = $guests[$info['guest_oid']] ?? null;
            elseif (!empty($info['host_oid'])) {
                foreach ($hosts as $h) { if (spl_object_id($h) === $info['host_oid']) { $target = $h; break; } }
            }
            if ($target) {
                try { $target->send(json_encode([
                    'type' => 'sock_challenge', 'command_id' => $cid,
                    'number_id' => $info['number_id'], 'nonce' => (string)($msg['nonce'] ?? ''),
                ])); } catch (\Throwable $e) {}
            }
            break;
        }
        case 'sock_fire': {
            if ($c->role !== 'guest' && $c->role !== 'host') { return; }
            $cid  = (string)($msg['command_id'] ?? '');
            $info = $calls[$cid] ?? null;
            // Only the author of the call (guest or owner), and only to the bound device.
            $mine = $info && (
                (int)($info['guest_oid'] ?? 0) === spl_object_id($c) ||
                (int)($info['host_oid'] ?? 0) === spl_object_id($c)
            );
            if (!$mine) { return; }
            $dev = $devices[(int)($info['device_id'] ?? 0)] ?? null;
            if (!$dev) { $c->send(json_encode(['type' => 'error', 'reason' => 'device_offline'])); break; }
            try { $dev->send(json_encode([
                'type' => 'sock_fire', 'command_id' => $cid,
                'number_id' => $info['number_id'],
                'token'     => (string)($msg['token'] ?? ''),
                'owner_sig' => (string)($msg['owner_sig'] ?? ''),
                'guest_id'  => (int)($msg['guest_id'] ?? 0),
                'nonce'     => (string)($msg['nonce'] ?? ''),
                'proof'     => (string)($msg['proof'] ?? ''),
            ])); } catch (\Throwable $e) {}
            break;
        }

        // The owner blocks or unblocks a guest on a particular controller, signed
        // with ownerSecret and versioned. The server only stores the latest state, to
        // hand it to a device that was offline when it reconnects, and relays it: it
        // can neither forge such a decision nor revive a revoked one.
        case 'sock_revoke': {
            if ($c->role !== 'host') { return; }
            $number_id = (int)($msg['number_id'] ?? 0);
            $guest_id  = (int)($msg['guest_id'] ?? 0);
            $version   = (int)($msg['version'] ?? 0);
            $revoked   = ((int)($msg['revoked'] ?? 1)) ? 1 : 0;
            $sig       = (string)($msg['sig'] ?? '');
            if ($number_id <= 0 || $guest_id <= 0 || $version <= 0 || $sig === '') { return; }
            $st = db()->prepare('SELECT device_id FROM numbers WHERE id = ? AND host_id = ? AND type = "device"');
            $st->execute([$number_id, $c->host_id]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row || !$row['device_id']) { return; }
            $device_id = (int)$row['device_id'];
            $ins = db()->prepare(
                'INSERT INTO device_revokes (device_id, guest_id, version, revoked, sig)
                 VALUES (?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                   revoked = IF(VALUES(version) > version, VALUES(revoked), revoked),
                   sig     = IF(VALUES(version) > version, VALUES(sig), sig),
                   version = GREATEST(version, VALUES(version))'
            );
            $ins->execute([$device_id, $guest_id, $version, $revoked, $sig]);
            $dev = $devices[$device_id] ?? null;
            if ($dev) {
                try { $dev->send(json_encode([
                    'type' => 'sock_revoke', 'guest_id' => $guest_id,
                    'version' => $version, 'revoked' => $revoked, 'sig' => $sig,
                ])); } catch (\Throwable $e) {}
            }
            break;
        }

        case 'device_hello': {
            $device_key    = (string)($msg['device_key'] ?? '');
            $device_secret = (string)($msg['device_secret'] ?? '');
            if ($device_key === '' || $device_secret === '') { $c->close(); return; }

            $st = db()->prepare('SELECT id, host_id, secret_hash FROM devices WHERE device_key = ?');
            $st->execute([$device_key]);
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!$row || !hash_equals($row['secret_hash'], hash('sha256', $device_secret))) {
                $c->send(json_encode(['type' => 'error', 'reason' => 'auth']));
                $c->close();
                return;
            }
            $c->role      = 'device';
            $c->device_id = (int)$row['id'];
            $c->host_id   = (int)$row['host_id'];
            // Whether the firmware supports encryption: if true, the server uses
            // challenge-response (sock_*) instead of a bare device_command. Older
            // firmware does not send the field and keeps working as before.
            $c->sock_e2ee = (bool)($msg['e2ee'] ?? false);
            $devices[$c->device_id] = $c;

            db()->prepare('UPDATE devices SET last_seen = NOW() WHERE id = ?')->execute([$c->device_id]);
            // hb_interval — how often the firmware should send device_status heartbeats.
            // Fixed at 300s for now. Once there are many devices this becomes adaptive
            // by count($devices).
            $c->send(json_encode([
                'type' => 'device_ok',
                'hb_interval' => 300,
            ]));

            // Catch up on guest revocations accumulated while the device was offline.
            // The controller applies them idempotently by version and ignores stale ones.
            try {
                $rv = db()->prepare('SELECT guest_id, version, revoked, sig FROM device_revokes WHERE device_id = ?');
                $rv->execute([$c->device_id]);
                foreach ($rv->fetchAll(PDO::FETCH_ASSOC) as $r) {
                    $c->send(json_encode([
                        'type' => 'sock_revoke', 'guest_id' => (int)$r['guest_id'],
                        'version' => (int)$r['version'], 'revoked' => (int)$r['revoked'], 'sig' => $r['sig'],
                    ]));
                }
            } catch (\Throwable $e) {}

            // Pushed to the owner AND to every guest of this host: they have the dot too.
            $devOnlineMsg = json_encode([
                'type' => 'device_online',
                'device_id' => $c->device_id,
                'online' => true,
            ]);
            $host = $hosts[$c->host_id] ?? null;
            if ($host) try { $host->send($devOnlineMsg); } catch (\Throwable $e) {}
            foreach ($guests as $g) {
                if (isset($g->host_id) && $g->host_id === $c->host_id) {
                    try { $g->send($devOnlineMsg); } catch (\Throwable $e) {}
                }
            }
            break;
        }

        case 'device_response':
        case 'device_status': {
            if ($c->role !== 'device') { return; }
            $command_id = (string)($msg['command_id'] ?? '');
            $message    = (string)($msg['message'] ?? '');

            // New format (device_status): level + final
            // Old format (device_response): status=ok|error, an alias
            if ($msg['type'] === 'device_status') {
                $level = (string)($msg['level'] ?? 'info');
                if (!in_array($level, ['success','warning','danger','info'], true)) $level = 'info';
                $final = (bool)($msg['final'] ?? true);
            } else {
                $oldStatus = (string)($msg['status'] ?? 'ok');
                $level = $oldStatus === 'ok' ? 'success' : 'danger';
                $final = true;
            }

            // "spontaneous" — an event with no command behind it, a button pressed inside and such
            $info = $calls[$command_id] ?? null;
            /* A reply is accepted only for the command it belongs to. Without this check
               a controller naming someone else's command number would send an
               unrelated guest an "opened" with its own text and litter a log that is
               not theirs. Command numbers are random, but there is no need to lean
               on that. */
            if ($info && (int)($info['device_id'] ?? 0) !== (int)$c->device_id) { $info = null; }

            // To the guest, if a command of theirs is active
            if ($info) {
                $guest = $guests[$info['guest_oid']] ?? null;
                if ($guest) {
                    $guest->send(json_encode([
                        'type'       => 'device_status',
                        'call_id'    => $command_id,
                        'number_id'  => $info['number_id'] ?? null,
                        'level'      => $level,
                        'message'    => $message,
                        'final'      => $final,
                    ]));
                }
            }
            // To the owner, always, for the log: both bound commands and spontaneous events.
            // An opening BY A GUEST is silent: the owner writes "Guest: X → …" into the
            // log but hears nothing, since sound belongs to their own actions only.
            $isGuestInit = $info && !empty($info['guest_oid']);
            $host = $hosts[$c->host_id] ?? null;
            if ($host) {
                $host->send(json_encode([
                    'type'        => 'device_status',
                    'call_id'     => $command_id,
                    'device_id'   => $c->device_id,
                    'number_id'   => $info['number_id'] ?? null,
                    'level'       => $level,
                    'message'     => $message,
                    'final'       => $final,
                    'silent'      => $isGuestInit,
                    'user_key_id' => $isGuestInit ? (int)($info['user_key_id'] ?? 0) : 0,
                ]));
            }
            // Logged only for commands, not for spontaneous events, and only when the
            // request came from a guest (user_key_id > 0). An owner's own call is not
            // logged: call_log.user_key_id has no foreign key, but a 0 there skews
            // the statistics.
            if ($info && (int)$info['user_key_id'] > 0) {
                $ins = db()->prepare('INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)');
                $ins->execute([$info['user_key_id'], $info['number_id'], 'dev_' . $level]);
            }

            // === Lock state for bistable objects ===
            // Firmware with BISTABLE=true puts position into device_status.
            // applyObjectState() does the diff, the rate limit, the update and the
            // broadcast by itself.
            $position = $msg['position'] ?? null;
            if ($position !== null && in_array($position, ['open','closed','unknown'], true)) {
                $sf = db()->prepare('SELECT id, host_id FROM numbers WHERE device_id = ? AND type = ?');
                $sf->execute([$c->device_id, 'device']);
                $nrow = $sf->fetch(PDO::FETCH_ASSOC);
                if ($nrow) {
                    applyObjectState((int)$nrow['host_id'], (int)$nrow['id'], $position, $hosts, $guests);
                }
            }

            // The command leaves $calls only on a final status
            if ($final && $info) {
                unset($calls[$command_id]);
            }
            break;
        }

        case 'webhook_result': {
            if ($c->role !== 'host') { return; }
            $call_id = (string)($msg['call_id'] ?? '');
            $message = (string)($msg['message'] ?? '');
            whlog("HOST webhook_result call=$call_id level=" . ($msg['level'] ?? 'none') . " msg=" . substr($message, 0, 120));
            // New format: level. Legacy: status=ok|error, mapped onto it.
            $level = (string)($msg['level'] ?? '');
            if (!in_array($level, ['success','warning','danger','info'], true)) {
                $level = (($msg['status'] ?? '') === 'ok') ? 'success' : 'danger';
            }
            if (!isset($calls[$call_id])) { return; }

            $info = $calls[$call_id];
            $guest = $guests[$info['guest_oid']] ?? null;
            if ($guest) {
                $guest->send(json_encode([
                    'type'    => 'device_status',
                    'call_id' => $call_id,
                    'level'   => $level,
                    'message' => $message,
                    'final'   => true,
                ]));
            }
            if ((int)($info['user_key_id'] ?? 0) > 0) {
                $ins = db()->prepare('INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)');
                $ins->execute([$info['user_key_id'], $info['number_id'], 'webhook_' . $level]);
            }

            // position inside webhook_result (phone-mode webhook): the owner's phone parsed
            // response.position and passes it on to the server.
            $position = $msg['position'] ?? null;
            if ($position !== null && in_array($position, ['open','closed','unknown'], true)) {
                applyObjectState((int)$c->host_id, (int)$info['number_id'], $position, $hosts, $guests);
            }

            unset($calls[$call_id]);
            break;
        }

        // obj_state_push — the owner reports a position by hand, after a background
        // check of a webhook for instance. Same as webhook_result but with no
        // command_id attached. Kept for future features; today the main channel is
        // position inside webhook_result.
        case 'obj_state_push': {
            if ($c->role !== 'host') { return; }
            $num_id = (int)($msg['num_id'] ?? 0);
            $position = (string)($msg['position'] ?? '');
            if ($num_id > 0 && in_array($position, ['open','closed','unknown'], true)) {
                applyObjectState((int)$c->host_id, $num_id, $position, $hosts, $guests);
            }
            break;
        }

        case 'avatar_request': {
            if ($c->role !== 'guest') { return; }
            $number_id = (int)($msg['number_id'] ?? 0);
            if (!$number_id) { return; }
            $host = $hosts[$c->host_id] ?? null;
            if (!$host) {
                $c->send(json_encode(['type' => 'avatar_data', 'number_id' => $number_id, 'data' => null]));
                return;
            }
            $host->send(json_encode([
                'type' => 'avatar_request', 'number_id' => $number_id,
                'guest_oid' => spl_object_id($c),
            ]));
            break;
        }

        case 'avatar_data': {
            if ($c->role !== 'host') { return; }
            $number_id = (int)($msg['number_id'] ?? 0);
            $guest_oid = (int)($msg['guest_oid'] ?? 0);
            $data         = (string)($msg['data'] ?? '');
            $avatarCipher = isset($msg['avatar_cipher']) ? (string)$msg['avatar_cipher'] : '';
            if (!$number_id) { return; }
            $guest = $guests[$guest_oid] ?? null;
            if ($guest) {
                $payload = ['type' => 'avatar_data', 'number_id' => $number_id];
                if ($avatarCipher !== '') {
                    $payload['avatar_cipher'] = $avatarCipher;
                } else {
                    $payload['data'] = $data;
                }
                $guest->send(json_encode($payload));
            }
            break;
        }

        // Bluetooth token renewal: the guest asks the owner to re-sign the token for a
        // Bluetooth object because its lifetime is running out. The server merely
        // routes; the meaningful payload (token, signature, guest key) travels the
        // other way. The server knows nothing about Bluetooth.
        //
        // If the owner is offline when the request arrives, we used to answer
        // "host_offline"; the guest ignored it silently and the token ripened until it
        // expired. Now the request goes into pendingRenews[host_id] and the whole
        // queue is delivered on the next host_hello. It lives in the worker's memory
        // only: it survives a websocket flap but not a restart of the PHP worker —
        // a rare event, and the guest retries on every attempt to fire anyway.
        case 'ble_token_renew': {
            if ($c->role !== 'guest') { return; }
            $ble_id = (int)($msg['ble_id'] ?? 0);
            if (!$ble_id) { return; }
            $hostId = (int)$c->host_id;
            $req = [
                'type'         => 'ble_token_renew',
                'ble_id'       => $ble_id,
                'user_key_id'  => (int)$c->user_key_id,
                'guest_oid'    => spl_object_id($c),
            ];
            $host = $hosts[$hostId] ?? null;
            if (!$host) {
                enqueueHostMsg($hostId, $req);
                $c->send(json_encode(['type' => 'ble_token_response',
                    'ble_id' => $ble_id, 'error' => 'host_offline_queued']));
                return;
            }
            $host->send(json_encode($req));
            break;
        }
        case 'ble_token_response': {
            if ($c->role !== 'host') { return; }
            $ble_id = (int)($msg['ble_id'] ?? 0);
            $guest_oid = (int)($msg['guest_oid'] ?? 0);
            $guest = $guests[$guest_oid] ?? null;
            if (!$guest) { return; }
            // The token, signatures and key are copied back into the guest message. The
            // server does not parse them: they are binary signatures made with
            // owner_secret, whose value only the owner and the controller know.
            $payload = ['type' => 'ble_token_response', 'ble_id' => $ble_id];
            foreach (['token', 'sig', 'gkey', 'valid_until', 'did', 'label', 'rssi', 'error'] as $k) {
                if (isset($msg[$k])) $payload[$k] = $msg[$k];
            }
            $guest->send(json_encode($payload));
            break;
        }

        // Bluetooth openings by a guest go into the owner's log. While offline the guest
        // stores them locally and flushes the batch on the next connection. The server
        // forwards it to the owner if they are online, otherwise it queues it in
        // pendingFireEvents[host_id], which is emptied on host_hello. The guest is
        // acknowledged only once the owner really received the batch, or once it is
        // safely queued.
        case 'ble_fire_event': {
            if ($c->role !== 'guest') { return; }
            $items = $msg['items'] ?? null;
            if (!is_array($items) || empty($items)) { return; }
            $payload = [
                'type'        => 'ble_fire_event',
                'user_key_id' => (int)($c->user_key_id ?? 0),
                'items'       => $items,
            ];
            $hostId = (int)($c->host_id ?? 0);
            $host = $hosts[$hostId] ?? null;
            if ($host) {
                $host->send(json_encode($payload));
            } else {
                enqueueHostMsg($hostId, $payload);
            }
            // Either way the guest is acknowledged for those timestamps: they were
            // delivered, or they are safely in the server's queue.
            $ackedTs = [];
            foreach ($items as $it) {
                if (isset($it['ts'])) $ackedTs[] = (int)$it['ts'];
            }
            $c->send(json_encode([
                'type'      => 'ble_fire_event_ack',
                'acked_ts'  => $ackedTs,
            ]));
            break;
        }

        case 'ping':
            $c->lastPong = time();
            $c->send(json_encode(['type' => 'pong']));
            break;
    }
};

$worker->onClose = function (TcpConnection $c) use (&$hosts, &$guests, &$devices) {
    if ($c->role === 'host' && isset($hosts[$c->host_id]) && $hosts[$c->host_id] === $c) {
        // Update last_seen on disconnect
        db()->prepare('UPDATE hosts SET last_seen = NOW() WHERE id = ?')->execute([$c->host_id]);
        $now = date('Y-m-d H:i:s');
        unset($hosts[$c->host_id]);
        foreach ($guests as $g) {
            if (isset($g->host_id) && $g->host_id === $c->host_id) {
                $g->send(json_encode(['type' => 'host_status', 'online' => false, 'last_seen' => $now]));
            }
        }
    } elseif ($c->role === 'guest') {
        unset($guests[spl_object_id($c)]);
    } elseif ($c->role === 'device' && isset($c->device_id)) {
        db()->prepare('UPDATE devices SET last_seen = NOW() WHERE id = ?')->execute([$c->device_id]);
        unset($devices[$c->device_id]);
        // Tell the owner AND the guests that the device dropped off: the dot turns red.
        if (isset($c->host_id)) {
            $devOffMsg = json_encode([
                'type' => 'device_online',
                'device_id' => $c->device_id,
                'online' => false,
            ]);
            $host = $hosts[$c->host_id] ?? null;
            if ($host) try { $host->send($devOffMsg); } catch (\Throwable $e) {}
            foreach ($guests as $g) {
                if (isset($g->host_id) && $g->host_id === $c->host_id) {
                    try { $g->send($devOffMsg); } catch (\Throwable $e) {}
                }
            }
        }
    }
};

Worker::runAll();
