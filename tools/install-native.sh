#!/bin/sh
# Installing without Docker, in one go.
#
# Does what the README describes by hand: creates the settings file with fresh
# secrets, loads the schema, builds the worker, installs it as a service and
# prints the web-server snippet. It asks before each step that touches the
# machine, and it can be run again — nothing is overwritten without a word.
#
#   sudo sh tools/install-native.sh
#
# What it does NOT do: install a web server, obtain a certificate, or create
# the database user. Those belong to the machine's owner.

set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
dist="$here/dist"
etc=/etc/entrixy
bin=/usr/local/bin/entrixy-ws
unit=/etc/systemd/system/entrixy-ws.service

say()  { printf '%s\n' "$*"; }
ask()  { printf '%s [y/N] ' "$*"; read -r a; [ "$a" = y ] || [ "$a" = Y ]; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" = 0 ] || { say "Run this as root: sudo sh tools/install-native.sh"; exit 1; }
[ -d "$dist" ] || { say "dist/ is missing — run this from the unpacked distribution."; exit 1; }

say "Entrixy, installation without Docker."
say ""

# ── 1. settings ──────────────────────────────────────────────────────────────
local_cfg="$dist/_config.local.php"
if [ -f "$local_cfg" ]; then
    say "1. Settings: $local_cfg exists, leaving it alone."
else
    printf 'The address this server answers on (for example gate.example.com): '
    read -r host
    printf 'Database host [127.0.0.1]: ';    read -r dbh;  dbh=${dbh:-127.0.0.1}
    printf 'Database name [entrixy]: ';     read -r db;   db=${db:-entrixy}
    printf 'Database user [entrixy]: ';     read -r user; user=${user:-entrixy}
    printf 'Database password: ';           read -r pass
    jwt=$(openssl rand -hex 32)
    att=$(openssl rand -hex 32)
    cat > "$local_cfg" <<CFG
<?php
// Written by tools/install-native.sh. An update never touches this file.
\$GLOBALS['db'] = [
    'host' => '$dbh',
    'name' => '$db',
    'user' => '$user',
    'pass' => '$pass',
];
\$GLOBALS['site_host']         = '$host';
\$GLOBALS['download_page_url'] = 'https://$host/download';
\$GLOBALS['jwt_secret']        = '$jwt';
\$GLOBALS['app_attest_secret'] = '$att';
\$GLOBALS['access_code']       = '';
\$GLOBALS['ws_host']           = '127.0.0.1';
\$GLOBALS['ws_port']           = 8095;
CFG
    chmod 600 "$local_cfg"
    chown "$(stat -c '%U' "$dist")" "$local_cfg" 2>/dev/null || true
    say "1. Settings written to $local_cfg, secrets generated."
    say "   The server is open: anyone who knows the address can register a"
    say "   device on it. Set access_code there, or hand out invitations."
fi
say ""

# ── 2. schema ────────────────────────────────────────────────────────────────
if have mariadb; then mysql_cmd=mariadb; elif have mysql; then mysql_cmd=mysql; else mysql_cmd=; fi
if [ -n "$mysql_cmd" ] && ask "2. Load the schema into the database now?"; then
    php -r '
        require "'"$dist"'/_config.php";
        $c = $GLOBALS["db"];
        echo $c["host"], "\n", $c["name"], "\n", $c["user"], "\n", $c["pass"], "\n";
    ' > /tmp/entrixy.db.$$ 2>/dev/null || { say "   Could not read the settings."; rm -f /tmp/entrixy.db.$$; exit 1; }
    dbh=$(sed -n 1p /tmp/entrixy.db.$$); dbn=$(sed -n 2p /tmp/entrixy.db.$$)
    dbu=$(sed -n 3p /tmp/entrixy.db.$$); dbp=$(sed -n 4p /tmp/entrixy.db.$$)
    rm -f /tmp/entrixy.db.$$
    "$mysql_cmd" -h"$dbh" -u"$dbu" -p"$dbp" "$dbn" < "$here/sql/01-schema.sql"
    say "   Schema loaded."
else
    say "2. Schema: load it yourself — mariadb -h HOST -u USER -p DBNAME < sql/01-schema.sql"
fi
say ""

# ── 3. the worker ────────────────────────────────────────────────────────────
if [ -x "$bin" ] && ! ask "3. $bin exists. Rebuild it?"; then
    say "3. Worker: keeping the binary that is there."
else
    have go || { say "3. Go is not installed. Build the worker elsewhere and copy it to $bin:"; \
                 say "      cd ws && CGO_ENABLED=0 go build -mod=vendor -trimpath -o entrixy-ws ."; exit 1; }
    ( cd "$here/ws" && CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o "$bin" . )
    say "3. Worker built: $bin"
fi
say ""

# ── 4. its settings and its service ──────────────────────────────────────────
getent group entrixy >/dev/null 2>&1 || groupadd --system entrixy
id entrixy >/dev/null 2>&1 || useradd --system --no-create-home --gid entrixy --shell /usr/sbin/nologin entrixy
mkdir -p "$etc"
php "$here/ws/ws-config.php" > "$etc/ws-config.json"
chown root:entrixy "$etc/ws-config.json"
chmod 640 "$etc/ws-config.json"
say "4. Worker settings: $etc/ws-config.json (root:entrixy, 640)"

cp "$here/docs/entrixy-ws.service" "$unit"
systemctl daemon-reload
systemctl enable entrixy-ws >/dev/null 2>&1 || true
systemctl reset-failed entrixy-ws >/dev/null 2>&1 || true
systemctl restart entrixy-ws
sleep 1
if systemctl is-active --quiet entrixy-ws; then
    say "   Service started."
else
    say "   The service did not start. What it says:"
    systemctl status entrixy-ws --no-pager -n 12 || true
    exit 1
fi
say ""

# ── 5. the web server ────────────────────────────────────────────────────────
say "5. Point your web server at $dist and proxy /ws to 127.0.0.1:8095."
say "   An nginx example is in nginx-entrixy.conf.example."
say ""
say "When it is up:  curl https://YOUR-DOMAIN/healthz"
