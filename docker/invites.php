<?php
/**
 * Invitations to the server: issue, list, revoke.
 *
 *   docker compose exec web entrixy-invites list
 *   docker compose exec web entrixy-invites add --count 5 --days 30 --note "Ivanov"
 *   docker compose exec web entrixy-invites revoke CODE
 *   docker compose exec web entrixy-invites revoke CODE --with-devices
 *
 * Revoking without the flag closes the invitation for the future, while
 * devices already created on it keep working. With the flag it removes those
 * devices too, along with everything they created. That is irreversible, so
 * we ask for confirmation.
 */
require_once '/var/www/html/_config.php';

$argv0 = array_shift($argv);
$cmd   = array_shift($argv) ?: 'list';

/** Parse "--key value" and a bare "--key". */
$opt = [];
$rest = [];
for ($i = 0; $i < count($argv); $i++) {
    $a = $argv[$i];
    if (str_starts_with($a, '--')) {
        $k = substr($a, 2);
        $next = $argv[$i + 1] ?? null;
        if ($next !== null && !str_starts_with($next, '--')) { $opt[$k] = $next; $i++; }
        else $opt[$k] = true;
    } else $rest[] = $a;
}

/** Pad by characters, not bytes: printf counts a non-ASCII letter twice. */
function pad(string $s, int $w): string
{
    $n = mb_strlen($s);
    return $s . str_repeat(' ', max(1, $w - $n));
}

function tbl(): void
{
    $rows = db()->query(
        'SELECT i.*, (SELECT COUNT(*) FROM access_invite_uses u WHERE u.invite_id = i.id) AS devices
           FROM access_invites i ORDER BY i.id DESC'
    )->fetchAll(PDO::FETCH_ASSOC);

    if (!$rows) { echo "No invitations. The server admits by shared code, or is open.\n"; return; }

    echo pad('CODE', 16) . pad('LEFT', 13) . pad('EXPIRES', 13) . pad('DEVICES', 9) . "NOTE\n";
    foreach ($rows as $r) {
        $state = $r['revoked_at'] ? 'revoked'
               : ($r['uses_left'] <= 0 ? 'used up'
               : (($r['expires_at'] && strtotime($r['expires_at']) < time()) ? 'expired'
               : (string)$r['uses_left']));
        echo pad($r['code'], 16) . pad($state, 13)
           . pad($r['expires_at'] ? substr($r['expires_at'], 0, 10) : 'never', 13)
           . pad((string)$r['devices'], 9) . $r['note'] . "\n";
    }
}

switch ($cmd) {

case 'add':
    $count = max(1, (int)($opt['count'] ?? 1));
    $uses  = max(1, (int)($opt['uses']  ?? 1));
    $days  = (int)($opt['days'] ?? 0);
    $note  = (string)($opt['note'] ?? '');
    $exp   = $days > 0 ? date('Y-m-d H:i:s', time() + $days * 86400) : null;

    $st = db()->prepare(
        'INSERT INTO access_invites (code, note, uses_left, expires_at) VALUES (?, ?, ?, ?)'
    );
    $host = parse_url((string)getenv('SITE_URL'), PHP_URL_HOST) ?: 'your.server';
    for ($i = 0; $i < $count; $i++) {
        // No look-alike characters: codes get dictated aloud and retyped by hand.
        $abc = '23456789abcdefghijkmnpqrstuvwxyz';
        $code = '';
        for ($k = 0; $k < 12; $k++) $code .= $abc[random_int(0, strlen($abc) - 1)];
        $st->execute([$code, $note, $uses, $exp]);
        echo $code . '@' . $host . "\n";
    }
    echo "\nHand over the whole string: it goes into the server address field.\n";
    break;

case 'revoke':
    $code = $rest[0] ?? '';
    if ($code === '') { echo "Name the code: revoke CODE\n"; exit(1); }

    $inv = db()->prepare('SELECT * FROM access_invites WHERE code = ?');
    $inv->execute([$code]);
    $inv = $inv->fetch(PDO::FETCH_ASSOC);
    if (!$inv) { echo "No such invitation.\n"; exit(1); }

    db()->prepare('UPDATE access_invites SET revoked_at = NOW(), uses_left = 0 WHERE id = ?')
        ->execute([$inv['id']]);
    echo "Invitation $code is closed: no new device can be created with it.\n";

    if (!isset($opt['with-devices'])) {
        echo "Devices already created with it keep working.\n";
        echo "To remove those as well: revoke $code --with-devices\n";
        break;
    }

    $hosts = db()->prepare('SELECT host_id FROM access_invite_uses WHERE invite_id = ?');
    $hosts->execute([$inv['id']]);
    $ids = $hosts->fetchAll(PDO::FETCH_COLUMN);
    if (!$ids) { echo "No devices were created with it.\n"; break; }

    echo "Devices to delete: " . count($ids) . ", along with their objects and keys.\n";
    echo "This cannot be undone. Type \"yes\" to confirm: ";
    if (trim((string)fgets(STDIN)) !== 'yes') { echo "Cancelled, the devices are untouched.\n"; break; }

    // Nine tables point at a device, and only messages have a cascade.
    $tables = ['audit_log', 'guest_messages', 'user_keys', 'pending_actions', 'numbers',
               'pending_host_msgs', 'key_invites', 'org_requests', 'devices'];
    $in = implode(',', array_fill(0, count($ids), '?'));
    foreach ($tables as $t) {
        try { db()->prepare("DELETE FROM `$t` WHERE host_id IN ($in)")->execute($ids); }
        catch (Throwable $e) { echo "  skipped: $t ({$e->getMessage()})\n"; }
    }
    db()->prepare("DELETE FROM hosts WHERE id IN ($in)")->execute($ids);
    echo "Devices deleted.\n";
    break;

default:
    tbl();
}
