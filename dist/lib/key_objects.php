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
const KEY_OBJ_DEFAULTS  = ['n' => 0, 'd' => 1, 'p' => 3];

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
                             WHERE status = 'new' AND parent_key_id IN ($in)
                               AND id <> " . (int)$skipInvite)->fetchAll(PDO::FETCH_ASSOC);
        foreach ($inv as $i) {
            $ids = array_map('intval', array_filter(explode(',', $i['number_ids'] . ',' . $i['ble_ids'])));
            if (in_array($numberId, $ids, true)) $used++;
        }
        $left = min($left, (int)$p - $used);
    }
    return $left === PHP_INT_MAX ? 0 : max(0, $left);
}
