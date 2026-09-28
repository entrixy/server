# What changed

By date, not by version number: the server is installed from this repository,
and what matters is what a running one has to do to catch up.

## 2026-09-28

**The service that holds the live connections is a single binary.** Its source
is in `ws/`, its dependencies are in `ws/vendor`, and the image carries nothing
else. This is what makes an installation without Docker possible: the web half
goes on ordinary hosting, the binary runs beside it under systemd. See
"Installing without Docker" in the README; `tools/install-native.sh` does it
in one go, and `docs/entrixy-ws.service` is the unit.

**A key settles on the handset that first uses it.** The handset derives a
second signing pair from the key and its own fingerprint and hands over the
public half; from then on only that pair is accepted, and the pair derived
from the link is refused everywhere. A key does not move to another handset —
the owner issues a new one.

**Object keys are counted by generation.** Revoking a guest changes the key of
every object that was open to them: the record is re-encrypted and the
remaining keys get the new one. The previous generation travels alongside for
one step, so nothing goes dark while bundles catch up.

**The crypto suite is named.** `v1` is carried inside every signature, every
ciphertext and a header; a server states which suites it speaks at
`/api/meta.php`, and a key is bound to the suite it was issued under.

**Settings for an installation without Docker live in their own file.**
`dist/_config.local.php` is read after `_config.php` and wins over it. It is
ignored by git, an update never touches it, and
`dist/_config.local.example.php` shows what goes in.

**`GET /healthz`** answers with the version of the installation and whether
the database is reachable.

**A server with no access code says so at start.** Anyone who knows the
address can register a device on such a server; set `ACCESS_CODE` or hand out
invitations to close it.

**Fixes.** Issuing a key returned 500. The browser client read a page address
as a key when the link carried the server after the blob. Used one-time
numbers stayed in the database for ever. The systemd unit and the settings
file it reads now agree on ownership, and a service that fails to start keeps
trying.

### To update a running server

    git pull
    docker compose up -d --build

The build is required: the websocket image is a different program now. The
database catches up by itself at start — new columns are added, nothing is
dropped. Guests and owners reconnect on their own; keys already issued keep
working.
