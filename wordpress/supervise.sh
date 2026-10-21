#!/bin/sh
# ACME WordPress supervisor — lab only.
#
# Apache runs a single prefork worker because the exploit needs "the same
# worker" for the producer and consumer requests. That worker is expected to
# die during exploitation (SIGSEGV / SIGABRT / heap corruption), which also
# takes down the parent. Restarting it automatically keeps the site alive so
# the lab can be exercised repeatedly without manual intervention.
#
# In a real deployment this is exactly the kind of "it just restarts, nobody
# noticed" behaviour that hides active exploitation.

set -e

# The upstream image populates /var/www/html and writes wp-config.php from its
# own entrypoint. Overriding the entrypoint skips that, so do it here.
if [ ! -f /var/www/html/index.php ]; then
    echo "[supervisor] seeding WordPress core into /var/www/html" >&2
    cp -a /usr/src/wordpress/. /var/www/html/
    chown -R www-data:www-data /var/www/html
fi

if [ ! -f /var/www/html/wp-config.php ]; then
    echo "[supervisor] writing wp-config.php" >&2
    cat > /var/www/html/wp-config.php <<'PHPEOF'
<?php
define( 'DB_NAME',     getenv('WORDPRESS_DB_NAME')     ?: 'wordpress' );
define( 'DB_USER',     getenv('WORDPRESS_DB_USER')     ?: 'wp' );
define( 'DB_PASSWORD', getenv('WORDPRESS_DB_PASSWORD') ?: 'wp' );
define( 'DB_HOST',     getenv('WORDPRESS_DB_HOST')     ?: 'db:3306' );
define( 'DB_CHARSET',  'utf8mb4' );
define( 'DB_COLLATE',  '' );

define( 'AUTH_KEY',         getenv('WP_AUTH_KEY') ?: 'lab-auth-key' );
define( 'SECURE_AUTH_KEY',  'lab-secure-auth-key' );
define( 'LOGGED_IN_KEY',    'lab-logged-in-key' );
define( 'NONCE_KEY',        'lab-nonce-key' );
define( 'AUTH_SALT',        'lab-auth-salt' );
define( 'SECURE_AUTH_SALT', 'lab-secure-auth-salt' );
define( 'LOGGED_IN_SALT',   'lab-logged-in-salt' );
define( 'NONCE_SALT',       'lab-nonce-salt' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );
define( 'DISALLOW_FILE_EDIT', true );

if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
PHPEOF
    chown www-data:www-data /var/www/html/wp-config.php
fi

while true; do
    apache2-foreground || true
    echo "[supervisor] apache exited, restarting in 1s" >&2
    sleep 1
done
