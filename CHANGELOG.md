# What changed

By date, not by version number: the server is installed from this repository,
and what matters is what a running one has to do to catch up.

## 2026-09-30

**A guest passes a key on with one link, even from several owners.** A link
is a group of parts, one per key the guest passes from; each part is an
ordinary key on its owner's object, confirmed by that owner. The recipient
sees one key. The guest can later change the objects of what they passed on,
revoke it with everything below, and write to the recipient; the message is
sealed with the recipient's public key. `api/key_delegate.php` gains
`edit`, `revoke` and `message`, and `create`/`info`/`redeem` work on the
group. Bluetooth locks travel in a pass-on too: the owner packs a pass only to
a lock the parent key holds.

**The owner can change "app only" and the pass-on depth of an issued key**
through `key_edit.php`. Keys already passed on below keep what they had.

**A controller that works over the internet** holds its own connection to the
server, so the server sees its IP address and the time of each command; the
content stays encrypted. Said in `spec/THREAT-MODEL.md`.

A running server applies this to its database:

```sql
ALTER TABLE key_invites
  ADD COLUMN grp CHAR(22) DEFAULT NULL AFTER code,
  ADD COLUMN creator_fp VARCHAR(64) DEFAULT NULL AFTER grp,
  ADD COLUMN ble_ids VARCHAR(255) NOT NULL DEFAULT '' AFTER number_ids,
  ADD COLUMN welcome_cipher TEXT DEFAULT NULL AFTER ble_ids,
  ADD KEY grp (grp);
ALTER TABLE user_keys
  ADD COLUMN share_grp CHAR(22) DEFAULT NULL AFTER parent_key_id,
  ADD COLUMN ble_ids VARCHAR(255) DEFAULT NULL AFTER share_grp,
  ADD COLUMN confirmed_ids VARCHAR(512) DEFAULT NULL AFTER ble_ids,
  ADD COLUMN bundle_dirty TINYINT(1) NOT NULL DEFAULT 0 AFTER confirmed_ids,
  ADD KEY share_grp (share_grp);
```

The service binary does not change for this.

**Only the current connection reports an owner or a controller as gone.** A
phone that reconnects has two sockets for a moment, and the old one closes
after the new one has said hello. That close is no longer passed on to guests:
the owner stays online for them. The same holds for controllers.

**A guest can ask whether the owner is online.** `host_status_req` answers
with the same `host_status` a guest receives on connecting. The app asks once
a minute while the owner shows as offline, so one lost message does not leave
a card paused for good. Rebuild the service binary to pick this up; nothing
changes in the database.

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

With Docker:

    git pull
    docker compose up -d --build

Without Docker, where the worker runs as a service and the web half is just
files:

    git pull
    cd ws && CGO_ENABLED=0 go build -mod=vendor -trimpath -o /usr/local/bin/entrixy-ws .
    systemctl restart entrixy-ws
    # then copy dist/ over your web root, keeping _config.local.php as it is

Either way the database catches up by itself at start — new columns are added,
nothing is dropped. Guests and owners reconnect on their own; keys already
issued keep working. Do not run the Docker command on a machine where the
service already holds the port: the two workers would fight over it.
