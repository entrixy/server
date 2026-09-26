# Entrixy Server — run your own

Everything needed to stand up your own Entrixy server: the web part, the
websocket worker, the database and TLS. This is not a trimmed build and not a
demo — it is the whole thing: objects, guest keys, passing a key down a chain,
revocation, the log, network controllers, limits. Run it for yourself or for
your clients; the app is pointed at your server in its settings.

Exactly one channel stays outside your server: the app talks to entrixy.com
for its own updates, crash reports and announcements. Openings, keys and
objects never go there.

## Links

* Project site — <https://entrixy.com>
* How the open model works — <https://entrixy.com/open>
* Documentation — <https://entrixy.com/docs>
* The app for Android — <https://entrixy.com/download/android>
* Browser client — <https://entrixy.com/app>
* Controller protocols: Bluetooth — <https://entrixy.com/ble>,
  network — <https://entrixy.com/socket>

Russian version of this file: [README.ru.md](README.ru.md).

## What you need

Any machine with Docker and git, and a domain whose A record points at it. The
certificate is issued automatically; nothing has to be set up by hand.

## Installation

    git clone https://github.com/entrixy/server.git entrixy-server
    cd entrixy-server
    cp .env.example .env
    nano .env                      # domain, database passwords, secrets
    docker compose up -d --build

The first start takes a few minutes: images are built and the database schema
is loaded. The containers listen on the loopback address only — the web part
on `127.0.0.1:8082`, the websocket on `127.0.0.1:8095`.

Two values in `.env` have to be generated rather than invented:

    openssl rand -hex 32           # JWT_SECRET

The database passwords can be anything: they never leave the machine.
`APP_ATTEST_SECRET` already carries the value that matches the app from the
store — leave it as it is unless you build the app yourself.

### After the first start

Three checks, in this order. The first says the web part is up and the
database is in place:

    curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8082/key

A `200` is what you want. Then, once the domain is proxied, the page should
come up with its styling and its tab icon — if it is bare, the panel is
serving the static files instead, and the section below says what to do. And
the websocket, which has a trap of its own:

    python3 tools/ws_check.py wss://your-domain/ws     # expect 101 and pong

Out of the box the door is open: any app told your address will create a
device. That is deliberate — a server for yourself usually needs nothing more.
If it is meant for a circle of people, close it with a code or with
invitations before you hand the address out; see "A server for your own people
only".

## Exposing the server

**If nginx already runs on the machine** — which is usually the case on a
server hosting other sites — ports 80 and 443 stay with it. Create a subdomain,
issue a certificate the way your panel normally does, then add the proxying.
There are two samples, and the choice between them matters:

* `nginx-entrixy.conf.example` — for an nginx you edit by hand: a whole
  `server` block with its own certificate;
* `nginx-entrixy-panel.conf.example` — for a control panel (Hestia,
  ISPmanager). There the include is inserted into an existing `server` block
  where `location /` already belongs to the panel, so the root is declared as
  the regex `location ~ ^/` and `/ws` as the prefix `location ^~ /ws`, which
  beats that regex. A whole `server {}` must not go into such a file: nginx
  refuses with `duplicate location`.

Your existing configs are left untouched either way.

**If the machine is clean**, the server can hold TLS itself:

    docker compose --profile tls up -d --build

Caddy comes up, takes 80 and 443 and issues a certificate for the domain from
`DOMAIN` with no manual setup.

### When a panel serves the static files instead

This is the trap that costs the most time. A panel's own config usually ends
with a regex for static extensions — css, js, png, ico and the rest — that
serves such files from its own document root. Yours are not there, they are
inside the container, so the pages come up while the stylesheet and the icons
answer 404: a bare page with no design and an empty tab icon.

The prefix blocks in the sample cover the directories, and the exact `location
= ` blocks cover the files that lie in the root: `assets.css`, the three
favicons, `apple-touch-icon.png` and `robots.txt`. Both kinds are there for
this reason. An exact match beats any regex in nginx whatever the order of the
includes, while a prefix with `^~` beats it as well — that is what makes the
sample work without touching the panel's own config.

If you build the config yourself and a file still answers 404, check it with

    curl -I https://your-domain/assets.css

A 404 with the panel's own server header means the request never reached the
container: add a `location = ` for that file the way the sample does.

### Errors and what the visitor sees

PHP errors go to the container log, never into the answer: a warning shown to
a visitor prints absolute paths and the shape of the code. The version is kept
out of the response headers for the same reason. Both are set in the image, so
there is nothing to configure.

The websocket worker's sources are removed from the web container at build
time — it runs in its own container and has nothing to say over HTTP. The URL
rules refuse `/w/` as well, which covers an image built by hand.

If you see a PHP error in a browser, you are looking at an image built before
this was fixed: rebuild with `git pull && docker compose up -d --build`.

### About the firewall

Docker is known for writing its own iptables rules and stepping around
existing ones. That does not happen here: ports are published on `127.0.0.1`
rather than on every address, so the containers are invisible from outside and
the machine's own protection does not apply to them. Do not change `HTTP_BIND`
to `0.0.0.0` without a reason — the server is already reachable through the
proxy.

## Pointing the app at your server

In the app: Settings → server address → your domain. Guest links issued by
this server lead back to it: a guest who opens such a link is connected to
your server automatically.

The app works with several servers at once. Keys issued to you from other
servers — by neighbours, by a management company — keep working, while new
objects are created on the server selected in settings.

One setting matters here. Keys the owner marked as "app only" are signed by
the app with a secret baked into its build, and the server checks that
signature with the same secret. So the value in `.env` has to match the build
you connect from. For the app from the store it is

    APP_ATTEST_SECRET=eNtR1xy_App_Att3st_2026_9f4Kq2Lm7Xb!

The value is not a secret in any real sense: it sits inside the installable
file and can be extracted from it. If you build the app yourself, use your own
on both sides. Use mismatched values and those keys stop opening, while
ordinary keys keep working.

## What is inside

| Service | What it does |
|---|---|
| `caddy` | certificate, ports 80 and 443, `/ws` goes to the worker |
| `web` | Apache and PHP: app requests, the guest key page |
| `ws` | websocket worker: live connections with phones and boards |
| `db` | MariaDB, data lives in the `db_data` volume |

The web part and the worker talk only through the database, so either one
survives a restart of the other.

## Updating

    git pull
    docker compose up -d --build

Your `.env` stays where it is — it is not tracked. The database schema catches
up on its own: on start the web part compares the database with the schema
that came with the code and adds whatever is missing — tables, columns,
indexes. The log says exactly what was added:

    docker compose logs web | tail

It only adds and never removes or reshapes anything: a column left over from a
previous version does no harm, while data from a dropped one cannot be
recovered. If a release ever needs an existing column reworked, that is stated
in the release notes separately.

Your data stays where it is: it lives in the `db_data` volume, while the
images are rebuilt beside it.

## What this server does not do

It sends no mail: there is no mail part here at all — see "Accounts and mail".

It does not build firmware in a browser. That needs build machines of ours and
stays on entrixy.com; controllers themselves work with your server normally.

It sends push notifications only once you supply a Firebase project and an app
build of your own — the next section explains why and how.

It has nothing to do with opening over Bluetooth. That works phone to
controller, whether your server is up or not.

Two things reach us rather than you, and neither carries openings, keys or
objects: the app updates from the store, and it sends crash reports and
announcements to entrixy.com. For the same reason the guest key page points at
our address for installing the app and for the browser client — `dist/key.php`
carries comments right next to those links saying what to replace if you would
rather host them yourself.

## Push notifications

The server works without them: while the app holds a connection, a guest's
call arrives immediately. A push is for the case when that connection is gone
— the phone was asleep, the network blinked, the system unloaded the app.

Any server can send a push, but only the one whose Firebase project is baked
into that particular app build can deliver it to that phone. The app from the
store carries our project, and your key cannot reach it. So push on your own
server is a pair of things: your Firebase project and your build of the app
carrying its `google-services.json`. The app sources are published separately.

Once the project exists, take a service account key from its settings
(Project settings → Service accounts → Generate new private key) and put the
file here:

    secrets/fcm-service-account.json

then bring the server up again. The `secrets/` directory is already mounted
into the containers read-only, nothing else needs changing. If the file is not
picked up the log will say so, and notifications simply stay the way they were
without it.

## Accounts and mail

The server sends no mail at all, and carries no sign-in page or registration
form: how people get accounts is left entirely to you.

A device needs no account: the app registers itself and works without any
sign-in, with limits taken from the `default` row of the `plans` table. If you
want to tie devices to people — so that limits survive a reinstall, say —
create rows in the `users` table any way that suits you and attach the device
through `host_account`. How you confirm an address or reset a password is
entirely yours to decide; nothing here forces a particular scheme.

## Companies on your server

The companies feature works here too: an organisation registers, publishes
`/.well-known/entrixy.json` with its public key on its own domain and signs
every request with it. Your server verifies and stores those signatures.

How trust is arranged matters. The domain is verified by the server, not by
the app, and that is done for the client's sake: if the phone fetched the key,
the company would see its address and the exact moment of the check — that is,
"this person is deciding right now whether to let me in". The server goes
instead, and the company sees only the server.

The price is that the authenticity badge reads as "verified by Entrixy": the
app draws the logo and the highlighted domain only for records from
entrixy.com. On your server companies work fully — registration, requests,
keys, revocation — but appear in the app by name, without marks of
authenticity. Otherwise any server could pass itself off as a well-known
company, and a person would have no way to check.

## A server for your own people only

By default the server is open: any app that is told your address will create a
device on it. That gives away no data — objects and keys are encrypted, and a
stranger's device sees precisely nothing — but it does take up room in your
database. There are two ways to close the door, and the choice depends on who
the server is for.

### A server for yourself: a shared code

    ACCESS_CODE=any_reasonably_long_string

A device is created only if the app sent the same code. The code is one for
everybody and travels together with the address, so it keeps out the street,
not acquaintances: whoever learns the code is in. For a home server that is
enough.

### A server for clients: invitations

An invitation is a code for a single device, with an expiry date and a note
saying who it was issued to. Registration burns it, so a code someone peeked
at is useless — it has already been used. Filling the server with devices on
one code does not work either: each one needs its own.

    docker compose exec web entrixy-invites add --count 5 --days 30 --note "Ivanov"

The command prints ready strings like `5wvv7qbu6cdx@gate.example.com`. That
whole string is what you hand over: the person pastes it into the server
address field and the app separates the code from the address itself. There
are no extra fields to fill in.

    docker compose exec web entrixy-invites list

shows the invitations you issued: how many entries are left, until when, and
how many devices came in on each.

    docker compose exec web entrixy-invites revoke 5wvv7qbu6cdx

closes an invitation for the future. Devices created on it earlier keep
working, and that is deliberate: a code is usually revoked because it spread,
not because a person became unwelcome. If it is the person, add
`--with-devices` — their devices are then deleted along with everything they
managed to create. The command first says how many there are and asks for
confirmation, because this cannot be undone.

The very first invitation closes the server: from then on a device is created
either with the shared code or with a valid invitation. Revoke every
invitation and leave the shared code empty, and the server is open again.

### What a code does not do

It decides who gets in, and nothing more. Inside, everything works as usual:
limits come from `plans`, and a guest holding an issued key is not asked for a
code at all — the key itself is their access. It does not touch anyone's data
either: even someone who got in sees only their own, and neighbouring records
are unreadable to them.

## Limits and plans

Out of the box a phone registers anonymously: the server issues the device a
pair of credentials and counts limits against the device itself. The default
is **20 objects and 20 guest keys** per device, the `default` row in the
`plans` table. They are changed right there:

    UPDATE plans SET max_numbers = 50, max_keys = 100 WHERE name = 'default';

The numbers are baked neither into the app nor into the firmware: the server
sends them on sync, and the app both displays them and refuses additions by
them.

### Where your own plans plug in

Room for accounting by person rather than by device is left in the server.

* the app can send a sign-in token at registration — the `account_token` field
  in `api/register_host.php`;
* a device attaches to a person through the `hosts.user_id` column;
* limits are then taken from that person's plan — `users.plan_id` → `plans`,
  with all of the logic in `lib/account.php`, function `account_limits()`;
* attaching or detaching an already registered phone — `api/host_account.php`.

An example of a second plan sits in the same table as the `account` row.
Create your own rows and hand them out through `users.plan_id` — that alone is
enough for different people to get different limits.

Beyond that it is your territory. Who your users are, how they pay, what the
cabinet shows, how a subscription is renewed: that is your server and your
rules. The mechanism is complete and working; the billing scheme and the
interface on top of it are not dictated here.

Accounts do not affect keys in any way: keys are encrypted on the phone, and
the server does not see them with or without an account.

## The server address inside controllers

A controller goes to the address baked into its program at build time. By
default the builder inserts the address of the server it is built on, so
firmware built on yours connects back to yours. The address is set explicitly
by the `ws_host` field (and `ws_port`) in the request to
`api/esp_compile.php`; the configurator interface deliberately has no such
field, so that an ordinary person cannot send their controller to someone
else's machine with a stray click.

In the firmware the address is the `WS_HOST` constant; in the Raspberry and
Node scripts it is the `WS_URL` string. If you build firmware your own way,
change them there.

## Building without internet access

The apcu sources sit in the repository itself (`vendor/`), and the build queries
no external hosts beyond the Debian repositories and the image registry. On a
machine that may only reach mirrors, that is enough.

## If the build fails

**`apt-get update` cannot resolve names.** This happens on Ubuntu 24.04 and
other systems with systemd-resolved: containers cannot be handed the address
`127.0.0.53`, so Docker substitutes the gateway, which serves no queries. Fix
it with explicit name servers:

    cat > /etc/docker/daemon.json <<'JSON'
    { "dns": ["1.1.1.1", "8.8.8.8"] }
    JSON
    systemctl restart docker

**Ordinary containers resolve names, but the build still fails.** The new
builder has a network of its own and does not read the daemon settings. Build
with the old one:

    DOCKER_BUILDKIT=0 docker compose up -d --build

## Checking the websocket

With an HTTP/1.1 client only — this matters. Through nginx the domain is
served over HTTP/2, where the `Upgrade` and `Connection` headers are
forbidden, so the upgrade is impossible by definition. Both `curl` and
`websocat` negotiate HTTP/2 over TLS on their own, and a perfectly configured
server looks broken. A client free of that trap is included:

    python3 tools/ws_check.py wss://your-domain/ws     # expect 101 and pong
    python3 tools/ws_check.py ws://127.0.0.1:8095/ws   # the same without the proxy

The same check with curl is fine, but pass `--http1.1` explicitly.

## Why image sizes differ

Almost all of the weight is the PHP base image; our part adds about thirty
megabytes to it. The same `php:8.3-apache` tag points at different builds at
different times, and the difference between them reaches two hundred
megabytes. Comparing sizes with another machine is therefore meaningless until
the base digest matches:

    docker image inspect php:8.3-apache --format '{{index .RepoDigests 0}}'
    docker history <image>     # layer by layer: our layers cost next to nothing

The tag is deliberately not pinned to a digest: security updates in the base
image matter more than reproducing a size down to the byte.

## Backup

    docker compose exec db mariadb-dump -u root -p"$DB_ROOT_PASS" entrixy > backup.sql

Keys are stored encrypted: the server does not read them, and nothing needs
decrypting when moving to another machine.

## License

The server is distributed under the GNU AGPL 3.0 — the full text is in
`LICENSE`. In short: use it however you like, including for your clients and
for money, but if you modify the server and people work with your modified
version over a network, the source of those modifications has to be available
to them. Terms for those to whom that does not suit are a separate
conversation with the author.

The protocol with its test vectors and the reference application are published
separately and under Apache 2.0: their job is to let other implementations
appear freely.

The name Entrixy and the logo are not granted by the license. Your own build
gets its own name.
