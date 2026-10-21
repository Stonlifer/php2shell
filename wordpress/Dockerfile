# Vulnerable-by-design WordPress lab target.
#
# The upstream wordpress:php8.4-apache tag now ships PHP 8.4.27, which contains
# the fix for CVE-2026-109618 / CVE-2026-109619 (see PHP NEWS: "Avoid state
# corruption via bailout"). Pinning PHP to 8.4.26 keeps the lab on an unpatched
# build and keeps libphp offsets identical to the other lab targets.
#
# WordPress core itself is taken unmodified from the official image, so this is
# a stock install -- nothing is hand-written in the app to make the demo work.
#
# Scope: this lab demonstrates code execution as the web user (www-data). No
# privilege-escalation helper and no sudo rule are installed -- the CVE gets
# you www-data, and that is the whole demonstration.

# Pinned by digest: this tag floats (its PHP moved 8.4.26 -> 8.4.27), so an
# unpinned rebuild could silently change the core files shipped below.
FROM wordpress:php8.4-apache@sha256:41815427d043bc629359121b347e2f1e4b7aba502062c369c2922f1d666ebf2a AS wp-core

FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

RUN apt-get update && apt-get install -y --no-install-recommends \
      libfreetype6-dev libjpeg62-turbo-dev libpng-dev libzip-dev \
      libicu-dev libonig-dev libxml2-dev libsodium-dev \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" gd mysqli zip intl exif bcmath opcache \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod rewrite

# Stock WordPress core from the official image.
COPY --from=wp-core /usr/src/wordpress /usr/src/wordpress
RUN chown -R www-data:www-data /usr/src/wordpress

# --- lab conveniences: the interactive shell + reverse-shell trigger ---
COPY assets/shell.php /usr/local/share/lab/shell.php
COPY assets/rev.php   /usr/local/share/lab/rev.php

WORKDIR /var/www/html
