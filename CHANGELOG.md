# What changed

By date, not by version number: the server is installed from this repository,
and what matters is what a running one has to do to catch up.

## 2026-10-06

**A bound controller can close.** A bistable controller that is bound to the
app used to open on every signed press: `sock_fire` carried no action. Now a
close travels as `"action":"close"` and is signed over `nonce || "close"`;
an open is signed over the bare nonce, as before. The server passes the action
on as the signer sent it — changing it only makes the controller refuse. Who
presses decides, by the position the controller reported. A plain
`device_command` carries the action the caller asked for, too.

**The controller tells what happened on it by itself.** The exit button, the
limit switch and auto-close arrive as `device_status` with an empty
`command_id` and an `event` field (`button`, `limit`, `auto`); the server finds
the object by the controller and hands the event to the owner quietly, for the
log.

**A real movement is never throttled.** The position from a reply to a command
or from such an event goes out at once; only the periodic heartbeat keeps the
five-second limit. Before, a close two seconds after an open never reached the
phones, and the next press closed again.

**A guest learns the positions on connect.** Right after `guest_ok` the server
sends `obj_state_update` for every object of the key that has a position;
before, a guest learnt it only from the next change.

**The owner sets how quickly a silent controller goes offline.** New setting
`DEVICE_PING_S` (default 30, 5..300): the server tells it to the controller in
`device_ok.ping_s` and drops the controller after three missed signals, checking
every five seconds. Firmware that follows it says `"ping_ctl":true` in
`device_hello`; older firmware keeps its own 30 seconds. See "Controller
presence" in the README. Rebuild the service binary and add the setting to
`.env` if you want a value other than 30.

## 2026-10-05

**A greeting that comes too soon waits instead of losing the link.** One
greeting per phone or key is still accepted every five seconds, but the next
one no longer has its connection closed: it waits for the end of the interval
and is then answered. An app restarted a few seconds after it connected — the
system does this after an update — used to be left without a link until its
own ping gave up. Only a third greeting, arriving while one already waits, is
treated as a storm and closed. Rebuild the service binary.

## 2026-10-02

**A webhook object can open and close.** A guest's or the owner's call may
carry `"action":"toggle"`: the server sends `close` if the object's last
position is open, otherwise `open`, and signs whichever it sends
(`timestamp.nonce.action.object_id`). A phone-mode call passes the action on
to the owner's phone in `do_webhook`.

**The position follows the answer, and only for a while.** The receiver's
`"position"` is applied at once, without the five-second limit that guards
against a flapping controller. For an open/close object whose receiver keeps
silent, the position follows the command. With `"close_in"` the object shows
closed once the seconds run out; without it the position turns unknown after
two seconds — a webhook reports nothing between presses. A newer press
cancels the pending change. Rebuild the service binary.

## 2026-10-01

**"App only" covers the whole branch.** When the owner (or a guest, for what
they passed on) turns "app only" on or off for an object, every key below
holding it gets the same flag at once and is told over its connection: a
browser below loses the object without a reload. `key_obj_enforce()` in
`lib/key_objects.php`.

**Messages arrive over the live connection.** A message to a guest — from the
owner, or from whoever passed the key on — is handed over the guest's open
connection as soon as it is written, and again at each connect until it is
read. Browsers and servers without push now get messages too. Rebuild the
service binary.

**Whoever passed a key on sees its opens.** The list of passed-on keys
(`key_delegate.php?a=list`) returns the opens made with keys below the holder
for the last 30 days, each tied to the link it went through — one entry per
open (the request row), not one per answer.
When a passed-on key is used, everyone up the chain who passed it on gets a
`pass_open` signal over their live connection, and the app fetches the open
at once. Rebuild the service binary.

**Tighter settings take effect below at once.** When the owner (or a guest,
for what they passed on) lowers an object's levels or number of keys, or turns
passing on off, keys passed on beyond the new limits lose the object — the
newest first, unopened links before keys. A key left with no objects is
revoked with its branch. `key_obj_enforce()` in `lib/key_objects.php`.

**A browser accepts a passed-on key.** The page of a link offers "Open in
the browser": the browser makes a key per part and its own encryption pair,
and opens the bundle once each owner confirms. **Fix:** the server refused the
recipient's public key as too long (a P-256 public half is 122 characters), so
no passed-on key could be accepted at all.

**A link nobody has opened lives a week.** An opened one still reopens on the
handset it was bound to for as long as the key lives. **Passing on is off by
default:** an object goes into a key with zero levels unless the owner allows
more. **A moved key takes its links along:** the new handset can add to links
the old one made. **A guest cannot ask the server to open a Bluetooth lock** —
it opens only next to it. Rebuild the service binary;
`ALTER TABLE key_numbers ALTER COLUMN delegate_depth SET DEFAULT 0;`

**A day between moves instead of three.** `MOVE_COOLDOWN` in
`lib/device_move.php`.

**The app identifies an installation, not the phone.** The fingerprint it
sends is derived from a random seed made at install and differs for every
server, so two servers cannot tell they see the same phone. Phones switch by
moving to the new fingerprint as an ordinary move, once. A server that wants
the switch to pass at once clears its move timestamps:
`UPDATE hosts SET moved_at = NULL; UPDATE user_keys SET moved_at = NULL;`

**A received key moves with a backup.** `key_bind.php` with `move: 1`,
signed with the pair of the handset the key sat on, moves the key to the new
handset (same window between moves as for an owner); the previous handset is
told the key is gone. Nothing changes in the database.

**Access is set per object in a key.** Each object carries three settings:
"app only", how many levels it may be passed on, and how many keys with it
may be issued in all down the chain below (3 by default). A guest passing a
key on sets levels and the number of keys for the recipient within what came
from above; "app only" is inherited. A browser client sees and opens only the
objects without "app only"; a key whose every object is "app only" does not
let a browser in at all. Bluetooth locks now sit in a key's list of objects
like the rest; the live connection does not list them, a lock travels inside
the bundle. The per-key limit of five passes is gone — the allowance per
object replaces it.

A running server applies this to its database and rebuilds the service binary:

```sql
ALTER TABLE key_numbers
  ADD COLUMN native_only TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN delegate_depth TINYINT(3) UNSIGNED NOT NULL DEFAULT 1,
  ADD COLUMN pass_pool SMALLINT(5) UNSIGNED NOT NULL DEFAULT 3;
UPDATE key_numbers kn JOIN user_keys uk ON uk.id = kn.user_key_id
   SET kn.native_only = uk.native_only, kn.delegate_depth = uk.delegate_depth;
ALTER TABLE key_invites ADD COLUMN objects TEXT DEFAULT NULL AFTER ble_ids;
```

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

**A passed-on link lives until the one who passed it deletes it.** A
recipient who removed the key opens the same link again, on the same handset
only: the part takes the new key and waits for the owner to seal the bundle
once more. Another handset is refused as "already bound".

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
