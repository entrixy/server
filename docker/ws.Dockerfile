# The websocket worker. Two-stage build, the runtime image is alpine-based: it
# carries neither composer nor a compiler, only PHP, the extensions and vendor.
FROM composer:2 AS deps
WORKDIR /w
COPY dist/w/composer.json dist/w/composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist --ignore-platform-reqs

FROM php:8.3-cli-alpine
RUN apk add --no-cache --virtual .build $PHPIZE_DEPS linux-headers \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql sockets pcntl \
    && apk del .build

COPY dist/ /app/
COPY --from=deps /w/vendor /app/w/vendor
WORKDIR /app/w
CMD ["php", "server.php", "start"]
