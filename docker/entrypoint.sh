#!/bin/sh
# Before the web part starts, bring the database up to the schema that came in
# the archive: after an update it may be missing tables or columns.
set -e
php /usr/local/bin/entrixy-migrate.php || echo "could not check the schema, continuing"
exec "$@"
