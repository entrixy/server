<?php
/**
 * Who may create a device on this server.
 *
 * There are two doors, and the owner closes either at will.
 *
 * A shared code (`ACCESS_CODE` in the settings) is the simple case: one
 * string for everybody entitled to use the server. It keeps out the street
 * but tells nobody apart: whoever learns the code is in.
 *
 * Invitations are the serious case: a code for a single device, with an
 * expiry date and a note saying who it went to. Registration burns it, so a
 * code someone peeked at is worthless — it has already been used. Once the
 * first invitation exists, the server is closed: entry is by the shared code
 * or by a valid invitation.
 */

/** The code from the request: the app puts it in the body, a header also works. */
function access_code_given(array $j): string
{
    $v = (string)($j['access_code'] ?? '');
    if ($v === '') $v = (string)($_SERVER['HTTP_X_ENTRIXY_ACCESS'] ?? '');
    return trim($v);
}

/** Whether a single live invitation exists on this server. */
function access_invites_live(): bool
{
    try {
        return (bool)db()->query(
            'SELECT 1 FROM access_invites
              WHERE revoked_at IS NULL AND uses_left > 0
                AND (expires_at IS NULL OR expires_at > NOW())
              LIMIT 1'
        )->fetchColumn();
    } catch (Throwable $e) {
        return false;                       // tables not there yet — server is open
    }
}

/**
 * Whether to admit the request. Returns the id of the invitation used, or
 * null if entry was by the shared code or the server is open. Uninvited
 * callers do not return at all: the request is refused and cut short.
 */
function access_gate(array $j): ?int
{
    $shared = (string)($GLOBALS['access_code'] ?? '');
    $live   = access_invites_live();
    if ($shared === '' && !$live) return null;          // the server is open

    $given = access_code_given($j);
    if ($given === '') access_deny();

    if ($shared !== '' && hash_equals($shared, $given)) return null;

    // The invitation is burned by the same statement that checks it:
    // otherwise two phones pressing at once would both enter on one code.
    $st = db()->prepare(
        'UPDATE access_invites
            SET uses_left = uses_left - 1, used_count = used_count + 1
          WHERE code = ? AND revoked_at IS NULL AND uses_left > 0
            AND (expires_at IS NULL OR expires_at > NOW())'
    );
    $st->execute([$given]);
    if ($st->rowCount() !== 1) access_deny();

    return (int)db()->query(
        'SELECT id FROM access_invites WHERE code = ' . db()->quote($given)
    )->fetchColumn();
}

/** Remember which invitation created which device: this is what revoke uses. */
function access_note_use(?int $invite_id, int $host_id): void
{
    if (!$invite_id) return;
    db()->prepare('INSERT INTO access_invite_uses (invite_id, host_id) VALUES (?, ?)')
        ->execute([$invite_id, $host_id]);
}

function access_deny(): void
{
    http_response_code(403);
    jout(['error' => 'access_denied']);
}
