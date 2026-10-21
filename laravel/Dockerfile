# Real Laravel app on the same PHP/Apache base as the lab target, so libphp
# offsets are identical and the published exploit works unmodified.
FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

RUN apt-get update && apt-get install -y --no-install-recommends \
      git unzip libzip-dev libpng-dev libonig-dev libxml2-dev \
 && docker-php-ext-install zip pdo pdo_mysql mbstring exif pcntl bcmath gd \
 && rm -rf /var/lib/apt/lists/*

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

# Laravel 11 skeleton (default "fresh install" look).
# Composer's advisory gate is disabled because this image is pinned to an
# intentionally unpatched PHP; the Laravel advisory block is unrelated noise
# for a demo target and would otherwise abort the build.
RUN composer config --global policy.advisories.block false \
 && composer create-project laravel/laravel:^11.0 /tmp/lv --no-interaction --prefer-dist \
 && cp -a /tmp/lv/. /var/www/html/ \
 && rm -rf /tmp/lv

RUN chown -R www-data:www-data storage bootstrap/cache database \
 && chmod -R ug+rwX storage bootstrap/cache database

# Laravel compiles a service manifest on first boot; the web user must be able
# to write it or every request 500s after a container restart.
RUN mkdir -p bootstrap/cache \
 && chown -R www-data:www-data bootstrap/cache \
 && chmod -R ug+rwX bootstrap/cache

# Scope: code execution as www-data only. No sudo rule and no escalation
# helper are installed.

# --- lab convenience: the reverse-shell trigger copied into place by /out/r ---
# The docroot must be writable by the web user for the payload to land where
# Apache serves it. The official image leaves it root-owned because composer
# ran as root; the WordPress image ships it www-data-owned, so this is parity.
RUN chown -R www-data:www-data /var/www/html
COPY assets/rev.php /usr/local/share/lab/rev.php
