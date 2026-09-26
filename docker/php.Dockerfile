# The web part: Apache + PHP. Apache on purpose — it reads the same .htaccess
# as the production server, so the URL rules need no rewriting.
FROM php:8.3-apache

# The apcu sources sit in the archive next to this file: the PECL channel
# periodically serves broken metadata, and is sometimes simply unreachable,
# while installing a server must not depend on someone else's host.
COPY vendor/apcu-5.1.28.tgz /tmp/apcu.tgz

# Header files are needed only while extensions are built. They are removed
# the same way the official PHP image does it: remember what was installed on
# purpose, mark everything else as temporary after the build, then bring back
# the libraries the built extensions actually link against, found via ldd. A
# hand-written package list gets this wrong — the names change release to
# release.
RUN set -eux; \
    savedAptMark="$(apt-mark showmanual)"; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" pdo_mysql gd zip opcache; \
    mkdir -p /tmp/apcu && tar xzf /tmp/apcu.tgz -C /tmp/apcu --strip-components=1; \
    cd /tmp/apcu && phpize && ./configure --silent && make -s -j"$(nproc)" && make install; \
    docker-php-ext-enable apcu; \
    cd /; rm -rf /tmp/apcu /tmp/apcu.tgz; \
    apt-mark auto '.*' > /dev/null; \
    apt-mark manual $savedAptMark > /dev/null; \
    find /usr/local -type f -executable -exec ldd '{}' ';' 2>/dev/null \
      | awk '/=>/ { print $(NF-1) }' | sed 's|^/lib/|/usr/lib/|' | sort -u \
      | xargs -r dpkg-query --search 2>/dev/null \
      | cut -d: -f1 | sort -u | xargs -r apt-mark manual > /dev/null; \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
    a2enmod rewrite headers expires remoteip; \
    rm -rf /var/lib/apt/lists/*

# .htaccess has to work: without AllowOverride the rewrite rules stay silent
RUN printf '<Directory /var/www/html>\n  AllowOverride All\n  Require all granted\n</Directory>\n' \
      > /etc/apache2/conf-available/entrixy.conf && a2enconf entrixy

# Behind an external nginx the real client address arrives in a header —
# otherwise the rate limiter and the log see the proxy's address for everyone.
RUN printf 'RemoteIPHeader X-Forwarded-For\nRemoteIPTrustedProxy 127.0.0.1\nRemoteIPTrustedProxy 172.16.0.0/12\n' \
      > /etc/apache2/conf-available/remoteip.conf && a2enconf remoteip

# Errors go to the log, never to the visitor: a PHP warning otherwise prints
# absolute paths and the shape of the code to whoever asked for the page.
# expose_php hides the version from the response headers for the same reason.
RUN printf 'apc.enable_cli=1\nopcache.enable=1\nupload_max_filesize=16M\npost_max_size=16M\n\
display_errors=Off\nlog_errors=On\nerror_log=/dev/stderr\nexpose_php=Off\n' \
      > /usr/local/etc/php/conf.d/entrixy.ini

COPY docker/entrypoint.sh /usr/local/bin/entrixy-entrypoint
COPY docker/migrate.php /usr/local/bin/entrixy-migrate.php
COPY docker/invites.php /usr/local/bin/entrixy-invites.php
COPY sql/ /app/sql/
RUN chmod +x /usr/local/bin/entrixy-entrypoint \
 && printf '#!/bin/sh\nexec php /usr/local/bin/entrixy-invites.php "$@"\n' > /usr/local/bin/entrixy-invites \
 && chmod +x /usr/local/bin/entrixy-invites
ENTRYPOINT ["entrixy-entrypoint"]
CMD ["apache2-foreground"]

COPY --chown=www-data:www-data dist/ /var/www/html/

# The websocket worker runs in its own container and has no business in the web
# root: over HTTP its source only ever answers with an error and a path.
RUN rm -rf /var/www/html/w
