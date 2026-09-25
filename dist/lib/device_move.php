<?php
/**
 * Moving access to a new phone.
 *
 * One rule holds everywhere: at any moment a key and a host live on EXACTLY one
 * device. When a new one arrives the previous is evicted — on its next request it
 * receives 'evicted' and wipes everything it holds.
 *
 * Repeat moves are limited: no more often than once per MOVE_COOLDOWN. A first
 * move after a long quiet period is always allowed — otherwise someone whose new
 * phone turned out faulty would be locked out for three days.
 *
 * Why the limit: a copy of the keys travels as a file, and without a delay it
 * could be passed around in a circle. With one, passing it around becomes
 * noticeable.

const MOVE_COOLDOWN = 3 * 24 * 3600;   // three days between moves

/**
 * The verdict on a presented device fingerprint.
 *
 * @return array{action:string, retry_after:int}
 *   action: 'bind'    — nothing was bound, so we record it
 *           'same'    — the same device, let it through
 *           'move'    — a new device, the move is allowed
 *           'wait'    — a new device, but too soon (retry_after seconds)
 *           'evicted' — the handset that was moved away from: let it wipe itself
 */
function device_move_decide(?string $current, ?string $fp, ?string $lastMoveSql, ?string $prev = null): array
{
    if ($fp === null || $fp === '') return ['action' => 'same', 'retry_after' => 0];
    if ($current === null || $current === '') return ['action' => 'bind', 'retry_after' => 0];
    if (hash_equals($current, $fp)) return ['action' => 'same', 'retry_after' => 0];

    // This is the very handset that was just moved away from. It hears not "wait"
    // but "you are gone": on this answer the app wipes everything it holds.
    if ($prev !== null && $prev !== '' && hash_equals($prev, $fp)) {
        return ['action' => 'evicted', 'retry_after' => 0];
    }

    $last = $lastMoveSql ? strtotime($lastMoveSql) : 0;
    $since = time() - $last;
    if ($last > 0 && $since < MOVE_COOLDOWN) {
        return ['action' => 'wait', 'retry_after' => MOVE_COOLDOWN - $since];
    }
    return ['action' => 'move', 'retry_after' => 0];
}

/** Record a move: the new device becomes current, the previous one evicted. */
function device_move_apply(string $table, int $id, string $fp, ?string $prev): void
{
    $sql = "UPDATE $table SET bound_device_fp = ?, bound_at = NOW(), moved_at = NOW(), prev_device_fp = ? WHERE id = ?";
    db()->prepare($sql)->execute([$fp, $prev, $id]);
}

/** A first binding, with no move recorded, so the cooldown is not spent. */
function device_move_bind(string $table, int $id, string $fp): void
{
    db()->prepare("UPDATE $table SET bound_device_fp = ?, bound_at = NOW() WHERE id = ?")
        ->execute([$fp, $id]);
}

/**
 * Whether this device has been evicted. The old phone learns of it here and
 * wipes itself. An empty fingerprint, from older versions of the app, is never
 * evicted.
 */
function device_is_evicted(?string $current, ?string $fp): bool
{
    return $fp !== null && $fp !== '' && $current !== null && $current !== ''
        && !hash_equals($current, $fp);
}
