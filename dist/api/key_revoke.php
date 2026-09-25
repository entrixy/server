<?php
require __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../lib/org.php';   // company requests and the callback
[$host_id, $j] = host_auth();

$id = (int)($j['id'] ?? 0);
$st = db()->prepare('SELECT id FROM user_keys WHERE id = ? AND host_id = ?');
$st->execute([$id, $host_id]);
if (!$st->fetchColumn()) jout(['error' => 'not_found'], 404);

// Revocation cascades: keys issued down a chain live only while their parent
// does. The subtree is collected breadth-first and put out entirely.
$tree = [$id];
$frontier = [$id];
$child = db()->prepare('SELECT id FROM user_keys WHERE parent_key_id = ? AND host_id = ?');
while ($frontier) {
    $next = [];
    foreach ($frontier as $pid) {
        $child->execute([$pid, $host_id]);
        foreach ($child->fetchAll(PDO::FETCH_COLUMN) as $cid) {
            $cid = (int)$cid;
            if (in_array($cid, $tree, true)) continue;
            $tree[] = $cid; $next[] = $cid;
        }
    }
    $frontier = $next;
    if (count($tree) > 500) break;   // a guard against a loop
}

// Revoking a company's access: its requests stop working, and it should be told
// so rather than left guessing why opening suddenly fails.
$orgKeys = [];
if ($tree) {
    $in = implode(',', array_fill(0, count($tree), '?'));
    $q = db()->prepare("SELECT id, org_id FROM user_keys WHERE id IN ($in) AND org_id IS NOT NULL");
    $q->execute($tree);
    $orgKeys = $q->fetchAll(PDO::FETCH_ASSOC);
}

$note = db()->prepare('INSERT INTO pending_notifications (kind, user_key_id, created_at) VALUES (?, ?, NOW())');
$dn   = db()->prepare('DELETE FROM key_numbers WHERE user_key_id = ?');
$dk   = db()->prepare('DELETE FROM user_keys WHERE id = ?');
$di   = db()->prepare('UPDATE key_invites SET status = "cancelled" WHERE parent_key_id = ? AND status = "new"');
foreach ($tree as $kid) {
    $note->execute(['key_revoked', $kid]);
    $di->execute([$kid]);
    $dn->execute([$kid]);
    $dk->execute([$kid]);
}
foreach ($orgKeys as $ok) {
    $codes = db()->prepare('SELECT code FROM org_requests WHERE user_key_id = ?');
    $codes->execute([(int)$ok['id']]);
    $list = $codes->fetchAll(PDO::FETCH_COLUMN);
    db()->prepare('UPDATE org_requests SET status = "revoked" WHERE user_key_id = ?')
        ->execute([(int)$ok['id']]);
    if (function_exists('org_callback')) {
        foreach ($list as $code) {
            org_callback((int)$ok['org_id'], 'revoked', ['code' => $code, 'key_ref' => (int)$ok['id']]);
        }
    }
}

audit_log($host_id, 'key_revoke', 'user_key', $id, ['cascade' => $tree]);
jout(['ok' => 1, 'revoked' => $tree]);
