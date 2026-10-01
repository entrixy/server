<?php
/**
 * Access settings of each object in a key.
 *
 *   native_only     the object opens in the app only, not in a browser
 *   delegate_depth  how many levels below this key it may be passed on
 *   pass_pool       how many keys with it may be issued in all, down the
 *                   whole chain below this key
 *
 * The key row keeps a summary for the checks that look at the key as a whole:
 * its delegate_depth is the largest of its objects', and it is "app only" when
 * every object is. Bluetooth locks are objects like any other: they sit in
 * key_numbers too, but the live connection does not list them — a lock travels
 * inside the bundle.
 */

const KEY_OBJ_DEPTH_MAX = 5;
const KEY_OBJ_POOL_MAX  = 50;
const KEY_OBJ_DEFAULTS  = ['n' => 0, 'd' => 0, 'p' => 3];   // passing on is allowed on purpose, not by default

/** Settings per object id out of the request's "objects" list, with defaults. */
function key_obj_settings_in(array $j, array $ids, array $defaults = KEY_OBJ_DEFAULTS): array {
    $given = [];
    foreach ((array)($j['objects'] ?? []) as $o) {
        if (!is_array($o) || (int)($o['id'] ?? 0) <= 0) continue;
        $given[(int)$o['id']] = $o;
    }
    $out = [];
    foreach ($ids as $id) {
        $o = $given[$id] ?? [];
        $out[$id] = [
            'n' => array_key_exists('native_only', $o) ? (int)(bool)$o['native_only'] : $defaults['n'],
            'd' => max(0, min(KEY_OBJ_DEPTH_MAX, (int)($o['depth'] ?? $defaults['d']))),
            'p' => max(1, min(KEY_OBJ_POOL_MAX, (int)($o['pool'] ?? $defaults['p']))),
        ];
    }
    return $out;
}

/** The objects of a key with their settings: id → [type, n, d, p]. */
function key_obj_read(int $keyId): array {
    $st = db()->prepare('SELECT kn.number_id, n.type, kn.native_only, kn.delegate_depth, kn.pass_pool, kn.org_label
                           FROM key_numbers kn JOIN numbers n ON n.id = kn.number_id
                          WHERE kn.user_key_id = ?');
    $st->execute([$keyId]);
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $out[(int)$r['number_id']] = ['type' => $r['type'], 'n' => (int)$r['native_only'],
            'd' => (int)$r['delegate_depth'], 'p' => (int)$r['pass_pool'], 'org_label' => $r['org_label']];
    }
    return $out;
}

/** Replace the objects of a key, then bring the key's summary up to date. */
function key_obj_write(int $keyId, array $settings, array $orgLabels = []): void {
    db()->prepare('DELETE FROM key_numbers WHERE user_key_id = ?')->execute([$keyId]);
    $ins = db()->prepare('INSERT INTO key_numbers (user_key_id, number_id, org_label, native_only, delegate_depth, pass_pool)
                          VALUES (?,?,?,?,?,?)');
    foreach ($settings as $id => $s) {
        $ins->execute([$keyId, (int)$id, $orgLabels[$id] ?? null, $s['n'], $s['d'], $s['p']]);
    }
    key_obj_summary($keyId);
}

function key_obj_summary(int $keyId): void {
    $st = db()->prepare('SELECT MAX(delegate_depth), MIN(native_only), COUNT(*) FROM key_numbers WHERE user_key_id = ?');
    $st->execute([$keyId]);
    [$d, $n, $c] = $st->fetch(PDO::FETCH_NUM);
    db()->prepare('UPDATE user_keys SET delegate_depth = ?, native_only = ? WHERE id = ?')
        ->execute([(int)$d, $c ? (int)$n : 0, $keyId]);
}

/** The key and the keys above it, nearest first. */
function key_ancestors(int $keyId): array {
    $out = [];
    $p = db()->prepare('SELECT parent_key_id FROM user_keys WHERE id = ?');
    for ($id = $keyId, $i = 0; $id && $i < 50; $i++) {
        $out[] = $id;
        $p->execute([$id]);
        $id = (int)$p->fetchColumn();
    }
    return $out;
}

/**
 * How many more keys with object $numberId may be issued below $keyId: the
 * tightest of the allowances of $keyId and every key above it. Live keys and
 * links nobody has opened yet both count.
 */
function key_pool_left(int $keyId, int $numberId, ?int $skipChild = null, ?int $skipInvite = null): int {
    require_once __DIR__ . '/key_tree.php';
    $pool = db()->prepare('SELECT pass_pool FROM key_numbers WHERE user_key_id = ? AND number_id = ?');
    $has  = db()->prepare('SELECT 1 FROM key_numbers WHERE user_key_id = ? AND number_id = ?');
    $left = PHP_INT_MAX;
    foreach (key_ancestors($keyId) as $a) {
        $pool->execute([$a, $numberId]);
        $p = $pool->fetchColumn();
        if ($p === false) continue;
        $used = 0;
        $tree = key_subtree($a);
        foreach ($tree as $k) {
            if ($k === $a || $k === $skipChild) continue;
            $has->execute([$k, $numberId]);
            if ($has->fetchColumn()) $used++;
        }
        // Links nobody has opened yet hold their place too.
        $in = implode(',', array_map('intval', $tree));
        $inv = db()->query("SELECT number_ids, ble_ids FROM key_invites
                             WHERE status = 'new' AND expires_at > NOW() AND parent_key_id IN ($in)
                               AND id <> " . (int)$skipInvite)->fetchAll(PDO::FETCH_ASSOC);
        foreach ($inv as $i) {
            $ids = array_map('intval', array_filter(explode(',', $i['number_ids'] . ',' . $i['ble_ids'])));
            if (in_array($numberId, $ids, true)) $used++;
        }
        $left = min($left, (int)$p - $used);
    }
    return $left === PHP_INT_MAX ? 0 : max(0, $left);
}

/**
 * Bring everything passed on below $keyId within its settings, object by
 * object, after the settings got tighter:
 *   - fewer levels: keys deeper than allowed lose the object;
 *   - fewer keys in all: the newest keys over the limit lose it (links nobody
 *     has opened go first);
 *   - passing on turned off: every key below loses it.
 * "App only" is not a limit but a copy: every key below holds the object with
 * the same flag as $keyId, turned on or off.
 * A key that loses an object passes the loss down its own branch. A key left
 * with no objects is revoked with everything below it; one that keeps some
 * waits for its owner to assemble the bundle anew.
 * Returns the ids of keys revoked.
 */
function key_obj_enforce(int $keyId): array {
    require_once __DIR__ . '/key_tree.php';
    $revoked = [];
    $touched = [];
    // Children of a key, with their objects.
    $kids = db()->prepare('SELECT id FROM user_keys WHERE parent_key_id = ? ORDER BY id');
    $drop = db()->prepare('DELETE FROM key_numbers WHERE user_key_id = ? AND number_id = ?');
    $clamp = db()->prepare('UPDATE key_numbers SET delegate_depth = LEAST(delegate_depth, ?) WHERE user_key_id = ? AND number_id = ?');

    // Remove object $nid from key $k and from its whole branch.
    $strip = function (int $k, int $nid) use (&$strip, $kids, $drop, &$touched) {
        $has = db()->prepare('SELECT 1 FROM key_numbers WHERE user_key_id = ? AND number_id = ?');
        $has->execute([$k, $nid]);
        if (!$has->fetchColumn()) return;   // this branch never had it
        $drop->execute([$k, $nid]);
        $touched[$k] = true;
        db()->prepare('UPDATE key_invites SET status = "cancelled" WHERE parent_key_id = ? AND status = "new"
                         AND FIND_IN_SET(?, CONCAT(number_ids, ",", ble_ids))')->execute([$k, $nid]);
        $kids->execute([$k]);
        foreach ($kids->fetchAll(PDO::FETCH_COLUMN) as $c) $strip((int)$c, $nid);
    };

    foreach (key_obj_read($keyId) as $nid => $s) {
        // Levels: walk the branch level by level; below the allowed depth the
        // object goes, above it each key's own levels are clamped.
        $level = [[$keyId, 0]];
        $holders = [];   // live keys below holding the object, in order of issue
        while ($level) {
            $next = [];
            foreach ($level as [$k, $l]) {
                $kids->execute([$k]);
                foreach ($kids->fetchAll(PDO::FETCH_COLUMN) as $c) {
                    $c = (int)$c;
                    $has = db()->prepare('SELECT 1 FROM key_numbers WHERE user_key_id = ? AND number_id = ?');
                    $has->execute([$c, $nid]);
                    if (!$has->fetchColumn()) continue;
                    if ($l + 1 > $s['d']) { $strip($c, $nid); continue; }
                    $clamp->execute([max(0, $s['d'] - ($l + 1)), $c, $nid]);
                    $holders[] = $c;
                    $next[] = [$c, $l + 1];
                }
            }
            $level = $next;
        }
        // Keys in all: unopened links go first, then the newest keys.
        $tree = key_subtree($keyId);
        $in = implode(',', array_map('intval', $tree));
        $pending = db()->query("SELECT id, number_ids, ble_ids FROM key_invites
                                 WHERE status = 'new' AND expires_at > NOW() AND parent_key_id IN ($in)
                                 ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC);
        $pending = array_values(array_filter($pending, fn($i) =>
            in_array($nid, array_map('intval', array_filter(explode(',', $i['number_ids'] . ',' . $i['ble_ids']))), true)));
        sort($holders);
        $over = count($holders) + count($pending) - ($s['d'] >= 1 ? $s['p'] : 0);
        foreach ($pending as $i) {
            if ($over <= 0) break;
            db()->prepare('UPDATE key_invites SET status = "cancelled" WHERE id = ?')->execute([(int)$i['id']]);
            $over--;
        }
        while ($over > 0 && $holders) {
            $k = array_pop($holders);
            $has = db()->prepare('SELECT 1 FROM key_numbers WHERE user_key_id = ? AND number_id = ?');
            $has->execute([$k, $nid]);
            if ($has->fetchColumn()) { $strip($k, $nid); $over--; }
        }
    }

    // "App only" goes down the branch as it is set here: keys below copy it.
    $flagged = [];
    $below = array_values(array_filter(key_subtree($keyId), fn($k) => (int)$k !== $keyId));
    if ($below) {
        $in = implode(',', array_map('intval', $below));
        $set = db()->prepare("UPDATE key_numbers SET native_only = ?
                               WHERE number_id = ? AND native_only <> ? AND user_key_id IN ($in)");
        $who = db()->prepare("SELECT user_key_id FROM key_numbers
                               WHERE number_id = ? AND native_only <> ? AND user_key_id IN ($in)");
        foreach (key_obj_read($keyId) as $nid => $s) {
            $who->execute([$nid, $s['n']]);
            foreach ($who->fetchAll(PDO::FETCH_COLUMN) as $k) $flagged[(int)$k] = true;
            $set->execute([$s['n'], $nid, $s['n']]);
        }
    }
    foreach (array_keys($flagged) as $k) {
        if (isset($touched[$k])) continue;   // told below with its other changes
        key_obj_summary($k);
        db()->prepare('INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?,?,NOW())')
            ->execute(['key_updated', $k]);
    }

    // What the keys that lost objects become.
    foreach (array_keys($touched) as $k) {
        $left = db()->prepare('SELECT COUNT(*) FROM key_numbers WHERE user_key_id = ?');
        $left->execute([$k]);
        $alive = db()->prepare('SELECT id, host_id, parent_key_id FROM user_keys WHERE id = ?');
        $alive->execute([$k]);
        $row = $alive->fetch(PDO::FETCH_ASSOC);
        if (!$row) continue;
        if ((int)$left->fetchColumn() === 0) {
            $revoked = array_merge($revoked, key_revoke_tree($k));
            continue;
        }
        key_obj_summary($k);
        db()->prepare('UPDATE user_keys SET bundle_dirty = 1 WHERE id = ?')->execute([$k]);
        db()->prepare('INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?,?,NOW())')
            ->execute(['key_updated', $k]);
        // The owner reassembles the bundle without the object.
        db()->prepare('INSERT INTO pending_host_msgs (host_id, payload, created_at, dedup_key) VALUES (?,?,NOW(),?)
                       ON DUPLICATE KEY UPDATE payload = VALUES(payload), created_at = NOW()')
            ->execute([(int)$row['host_id'], json_encode(['type' => 'bundle_request', 'key_id' => $k,
                       'parent_key_id' => (int)$row['parent_key_id']]), 'bundle_req_' . $k]);
    }
    return $revoked;
}
