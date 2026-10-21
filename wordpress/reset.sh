#!/usr/bin/env bash
# Reset the ACME WordPress lab to a clean, vulnerable state.
cd "$(dirname "$0")" || exit 1

echo "[*] stopping containers..."
docker compose down >/dev/null 2>&1 || true

echo "[*] clearing artifacts..."
rm -rf out && mkdir -p out
chmod 777 out 2>/dev/null

echo "[*] staging chain + escalation + interactive shell..."
./stage.sh

echo "[*] starting containers..."
docker compose up -d >/dev/null 2>&1
for i in $(seq 1 60); do
  curl -fsS -o /dev/null http://127.0.0.1:8091/ 2>/dev/null && break
  sleep 1
done

echo "[*] waiting for the one-time WordPress install..."
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8091/ 2>/dev/null)
  [ "$code" = "200" ] && break
  sleep 1
done

# Finish the install if the wizard is still showing.
if curl -s http://127.0.0.1:8091/ 2>/dev/null | grep -qi "setup-config\|install.php"; then
  echo "[*] installing WordPress..."
  docker exec acme-wordpress sh -c 'php /tmp/install.php' >/dev/null 2>&1 || true
fi

docker exec acme-wordpress rm -f /var/www/html/s.php 2>/dev/null

echo "[+] lab reset. blog: http://127.0.0.1:8091/"
