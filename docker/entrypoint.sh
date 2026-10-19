#!/bin/sh
# Before the web part starts, bring the database up to the schema that came in
# the archive: after an update it may be missing tables or columns.
set -e
php /usr/local/bin/entrixy-migrate.php || echo "SCHEMA INCOMPLETE — see the lines above; the site runs, but some features may fail until fixed" >&2
exec "$@"
