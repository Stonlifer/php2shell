#!/usr/bin/env bash
# =============================================================================
# php2shell-audit.sh -- on-host audit for PHP2Shell
#   CVE-2026-109618 (RCE via OOM corruption)
#   CVE-2026-109619 (RCE via stale global state)
#
#   sudo ./audit-host.sh                # human readable
#   sudo ./audit-host.sh --json         # machine readable
#   sudo ./audit-host.sh --no-docker    # skip container inspection
#
# READ-ONLY. Starts nothing, writes nothing, changes no configuration.
#
# WHAT THIS ANSWERS
#   1. Is the PHP runtime that serves requests patched?
#   2. Was it RESTARTED after the patch?      <- the #1 real-world failure
#   3. Are the documented interim mitigations actually in force?
#   4. What else on this box speaks PHP? (containers, panels, alt-PHP)
#
# WHAT THIS CANNOT ANSWER
#   Hosts you do not run: appliances, network gear, SaaS, other people's
#   servers. If PHP is not on this filesystem, this script says so -- that is
#   not the same as "safe".
#
# VERDICT BUCKETS
#   PATCHED                upstream version >= the fixed release
#   PATCHED-VIA-BACKPORT   distro package, changelog cites the CVE
#   BACKPORT-NEEDED        distro package below upstream fix, no backport evidence
#   VULNERABLE             source/upstream build below the fixed release
#   LEGACY                 < 5.4 -- INI mitigation cannot apply at all
#   EOL-NO-FIX             7.x / 8.0 / 8.1 -- no upstream fix exists
#   UNKNOWN                could not determine (report it as such)
# =============================================================================

set -uo pipefail

JSON=0
DO_DOCKER=1
for arg in "$@"; do
  case "$arg" in
    --json)      JSON=1 ;;
    --no-docker) DO_DOCKER=0 ;;
    -h|--help)   sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

# ---- colour (only when tty and not json) ------------------------------------
if [[ -t 1 && $JSON -eq 0 ]]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; B=$'\033[1m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; C=""; B=""; N=""
fi

# ---- version helpers (pure bash: no sort -V dependency) --------------------
vcore() {
  local v="${1#PHP }"
  if [[ "$v" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]]; then printf '%s' "${BASH_REMATCH[1]}"; fi
}

# ver_ge A B -> true when A >= B
ver_ge() {
  local IFS=.
  local -a a b
  read -r -a a <<< "$1"
  read -r -a b <<< "$2"
  local i x y
  for i in 0 1 2; do
    x="${a[$i]:-0}"; y="${b[$i]:-0}"
    x="${x//[^0-9]/}"; y="${y//[^0-9]/}"
    x="${x:-0}"; y="${y:-0}"
    if (( 10#$x > 10#$y )); then return 0; fi
    if (( 10#$x < 10#$y )); then return 1; fi
  done
  return 0
}

fixed_for() {
  case "$1" in
    8.2) echo "8.2.35" ;;
    8.3) echo "8.3.36" ;;
    8.4) echo "8.4.27" ;;
    8.5) echo "8.5.12" ;;
    *)   echo "" ;;
  esac
}

# ---- binary discovery ------------------------------------------------------
find_binaries() {
  local -a cands=()
  local p

  # PATH
  for p in php php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 \
           php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 \
           php-cgi php-cgi8.5 php-cgi8.4 php-cgi8.3 php-cgi8.2 lsphp; do
    if have "$p"; then cands+=("$(command -v "$p")"); fi
  done

  # distro / source installs
  for p in /usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-fpm[0-9]* \
           /usr/sbin/php-fpm[0-9]* /usr/sbin/php-fpm \
           /usr/local/bin/php /usr/local/sbin/php-fpm \
           /usr/local/php/*/bin/php /opt/php/*/bin/php; do
    [[ -x "$p" ]] && cands+=("$p")
  done

  # control panels & alternative stacks (CERT-EU: appliances/embedded count)
  for p in /opt/cpanel/ea-php*/root/usr/bin/php \
           /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
           /opt/plesk/php/*/bin/php \
           /opt/alt/php*/usr/bin/php \
           /opt/remi/php*/root/usr/bin/php \
           /usr/local/lsws/lsphp*/bin/php \
           /usr/local/lsws/lsphp*/bin/lsphp \
           /usr/local/directadmin/custombuild/php*/bin/php \
           /usr/local/directadmin/custombuild/bin/php \
           /Applications/MAMP/bin/php/php*/bin/php \
           /opt/homebrew/bin/php /usr/local/bin/php; do
    [[ -x "$p" ]] && cands+=("$p")
  done

  # dedupe, drop version-less stubs and obvious non-binaries
  if ((${#cands[@]})); then
    printf '%s\n' "${cands[@]}" | sort -u 2>/dev/null || printf '%s\n' "${cands[@]}"
  fi
}

sapi_of() {
  local bin="$1" s
  case "$bin" in
    *php-fpm*) printf 'fpm-fcgi'; return ;;
    *php-cgi*) printf 'cgi-fcgi'; return ;;
    *lsphp*)   printf 'litespeed'; return ;;
  esac
  s="$("$bin" -r 'echo PHP_SAPI;' 2>/dev/null)"
  case "$s" in
    apache2handler|fpm-fcgi|cgi-fcgi|litespeed|cli-server|cli|frankenphp|embed)
      printf '%s' "$s" ;;
    *) printf 'unknown' ;;
  esac
}

# Read an ini value from a binary's own view. '-i' works for php-fpm where
# '-r' does not exist -- that was a bug in the previous version.
ini_of() {
  local bin="$1" key="$2" val=""
  if have "$bin"; then
    val="$("$bin" -i 2>/dev/null | awk -v k="$key" '
      index($0, k " => ") == 1 { sub("^" k " => ", ""); sub(/ => .*/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); print; exit }
    ')"
  fi
  printf '%s' "$val"
}

# Fallback: read the ini FILE the web SAPI actually loads.
ini_from_files() {
  local key="$1" f val=""
  local -a files=(
    /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cgi/php.ini
    /etc/php.ini /etc/php5/fpm/php.ini /etc/php5/apache2/php.ini
    /usr/local/etc/php/php.ini /usr/local/lib/php.ini
    /opt/plesk/php/*/etc/php.ini /opt/cpanel/ea-php*/root/etc/php.ini
  )
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    val="$(awk -v k="$key" '
      /^[ \t]*;/ { next }
      $0 ~ "^[ \t]*" k "[ \t]*=" { split($0, a, "="); v=a[2];
        sub(/;.*/, "", v); gsub(/^[ \t]+|[ \t]+$/, "", v); last=v }
      END { print last }
    ' "$f" 2>/dev/null)"
    [[ -n "$val" ]] && { printf '%s' "$val"; return; }
  done
  printf ''
}

# ---- backport detection ----------------------------------------------------
# Distro packages backport fixes WITHOUT changing the upstream version string.
# Ubuntu's 8.3.6 can be fixed while still reading "8.3.6".
# Returns: backported | no-evidence | not-a-package
backport_state() {
  local ver="$1" pkg="$2"

  # Not a distro package if the version has no distro suffix and no pkg known.
  if [[ -z "$pkg" ]]; then printf 'not-a-package'; return; fi

  if have dpkg-query; then
    local pv cl
    pv="$(dpkg-query -W -f='\${Version}' "$pkg" 2>/dev/null)"
    if [[ -n "$pv" ]]; then
      # Changelog first: it is the authoritative evidence.
      if have zgrep; then
        for f in /usr/share/doc/"$pkg"/changelog.Debian.gz \
                 /usr/share/doc/"$pkg"/changelog.gz; do
          [[ -f "$f" ]] || continue
          if zcat "$f" 2>/dev/null | head -400 \
             | grep -qiE 'CVE-2026-10961[89]|php2shell'; then
            printf 'backported'; return
          fi
        done
      fi
      if have apt-get && have timeout; then
        cl="$(timeout 12 apt-get changelog "$pkg" 2>/dev/null | head -400)"
        if printf '%s' "$cl" | grep -qiE 'CVE-2026-10961[89]|php2shell'; then
          printf 'backported'; return
        fi
      fi
      printf 'no-evidence'; return
    fi
  fi

  if have rpm; then
    local rv
    rv="$(rpm -q "$pkg" 2>/dev/null)" && [[ -n "$rv" ]] || { printf 'not-a-package'; return; }
    if rpm -q --changelog "$pkg" 2>/dev/null | head -400 \
       | grep -qiE 'CVE-2026-10961[89]|php2shell'; then
      printf 'backported'; return
    fi
    printf 'no-evidence'; return
  fi

  printf 'not-a-package'
}

# Find the owning package for a binary path.
package_of() {
  local bin="$1" p=""
  if have dpkg-query; then
    p="$(dpkg-query -S "$bin" 2>/dev/null | head -1 | cut -d: -f1)"
    [[ -n "$p" ]] && { printf '%s' "$p"; return; }
  fi
  if have rpm; then
    p="$(rpm -qf "$bin" 2>/dev/null | head -1)"
    [[ -n "$p" && "$p" != "file "* ]] && { printf '%s' "$p"; return; }
  fi
  printf ''
}

# ---- restart evidence ------------------------------------------------------
# A patched package does nothing until workers are replaced. Compare the
# service start time against the binary's mtime.
restart_state() {
  local bin="$1" sapi="$2" btime svc stime
  btime="$(stat -c %Y "$bin" 2>/dev/null || stat -f %m "$bin" 2>/dev/null || echo 0)"
  [[ "$btime" =~ ^[0-9]+$ ]] || btime=0

  local -a svcs=()
  case "$sapi" in
    apache2handler) svcs=(apache2 httpd) ;;
    fpm-fcgi)       svcs=(php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2) ;;
    litespeed)      svcs=(lsws lshttpd) ;;
    *)              svcs=() ;;
  esac

  if ! have systemctl; then printf 'unknown:no-systemd'; return; fi

  for svc in "${svcs[@]}"; do
    systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || continue
    stime="$(systemctl show "$svc" -p ActiveEnterTimestamp --value 2>/dev/null)"
    [[ -z "$stime" || "$stime" == "n/a" ]] && continue
    local epoch
    epoch="$(date -d "$stime" +%s 2>/dev/null || echo "")"
    if [[ -z "$epoch" ]]; then
      printf 'unknown:%s-running' "$svc"; return
    fi
    if (( epoch < btime )); then
      printf 'stale:%s started before binary mtime' "$svc"; return
    fi
    printf 'restarted:%s started after binary mtime' "$svc"; return
  done

  printf 'unknown:service-not-found'
}

# ---- docker ---------------------------------------------------------------
# Previously this only LISTED image names. On a container host that produced
# "No PHP binary found" -- which reads as clean. That was the worst bug.
docker_scan() {
  have docker || return 0
  docker info >/dev/null 2>&1 || return 0

  local line id image name raw ver sapi
  while IFS='|' read -r id image name; do
    [[ -z "$id" ]] && continue
    raw=""
    # Prefer the SAPI that actually serves requests. In php:*-apache the CLI
    # binary and mod_php share a version, but the SAPI decides the risk, so ask
    # for both and keep only what we can parse.
    raw="$(docker exec "$id" sh -c '
      for c in "php -v" "php-fpm -v" "php-cgi -v" "lsphp -v" \
               "frankenphp php-cli -v" "apache2ctl -M 2>/dev/null"; do
        command -v "${c%% *}" >/dev/null 2>&1 && { $c 2>/dev/null | head -1; }
      done' 2>/dev/null)"
    # mod_php/apache images: the module line names the version even when the
    # CLI is absent (alpine variants strip it).
    if [[ -z "$raw" ]]; then
      raw="$(docker exec "$id" sh -c '. /etc/apache2/envvars 2>/dev/null; apache2 -v 2>/dev/null | head -1' 2>/dev/null)"
    fi
    ver="$(printf '%s\n' "$raw" | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+[^ )]*' | head -1)"
    [[ -z "$ver" ]] && ver="$(printf '%s\n' "$raw" | grep -oE 'Apache/[0-9.]+' | head -1)"
    [[ -z "$ver" ]] && continue
    # PHP_SAPI of the CLI binary says nothing about the serving path. If the
    # image runs Apache with mod_php, that is the SAPI that matters.
    sapi="$(docker exec "$id" sh -c 'php -r "echo PHP_SAPI;" 2>/dev/null' 2>/dev/null)"
    if docker exec "$id" sh -c 'ls /etc/apache2/mods-enabled/php*.load >/dev/null 2>&1' 2>/dev/null; then
      sapi="apache2handler"
    elif docker exec "$id" sh -c 'command -v php-fpm >/dev/null 2>&1' 2>/dev/null; then
      case "$sapi" in *fpm*) ;; *) sapi="fpm-fcgi" ;; esac
    fi
    DOCKER_HITS+=("${name}|${image}|${ver}|${sapi:-unknown}|${raw}")
  done < <(docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}' 2>/dev/null)
}

# Classify a container. The old code printed the version and said "compare
# each against the fixed releases above" -- which meant a container running
# 8.4.26 still produced "NO AFFECTED INSTALL DETECTED" overall. Never leave
# judgement to the reader.
docker_verdict() {
  local ver="$1" core branch fixed
  core="$(vcore "$ver")"
  [[ -z "$core" ]] && { printf 'UNKNOWN'; return; }
  branch="${core%.*}"
  fixed="$(fixed_for "$branch")"
  if [[ -z "$fixed" ]]; then
    case "$branch" in
      3.*|4.*|5.0|5.1|5.2|5.3) printf 'LEGACY' ;;
      5.*|7.*|8.0|8.1)         printf 'EOL-NO-FIX' ;;
      *)                       printf 'UNKNOWN' ;;
    esac
    return
  fi
  if ver_ge "$core" "$fixed"; then printf 'PATCHED|%s' "$fixed"
  else printf 'VULNERABLE|%s' "$fixed"; fi
}

# ---- replaced-binary detection (Linux only) --------------------------------
# THE definitive restart check. When a package upgrade replaces libphp/php-fpm
# on disk, already-running workers keep the OLD inode mapped. `php -v` then
# reports the NEW version while the live process still executes patched-out
# code. The kernel marks such mappings "(deleted)" in /proc/PID/maps.
# Credit: this technique appears in ersinkoc/php-fix; it is the strongest
# signal available and beats comparing timestamps.
deleted_php_procs() {
  [[ -d /proc ]] || return 0
  local maps
  for maps in /proc/[0-9]*/maps; do
    [[ -r "$maps" ]] || continue
    if grep -qE ' /[^ ]*php[^ ]* \(deleted\)$' "$maps" 2>/dev/null; then
      local pid="${maps#/proc/}"; pid="${pid%/maps}"
      local cmd
      cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-80)"
      [[ -z "$cmd" ]] && cmd="$(cat "/proc/$pid/comm" 2>/dev/null)"
      printf '%s pid=%s cmd=%s\n' "$maps" "$pid" "$cmd"
    fi
  done
}

# Apache and LiteSpeed too: they embed PHP and are replaced on upgrade.
deleted_any_procs() {
  [[ -d /proc ]] || return 0
  local maps
  for maps in /proc/[0-9]*/maps; do
    [[ -r "$maps" ]] || continue
    if grep -qE ' /[^ ]*(php|libphp|lsphp)[^ ]* \(deleted\)$' "$maps" 2>/dev/null; then
      local pid="${maps#/proc/}"; pid="${pid%/maps}"
      printf '%s\n' "$pid"
    fi
  done | sort -u
}

# ---- held / version-locked packages ---------------------------------------
# A held package silently skips security updates -- the host looks patched
# forever. Worth checking before you tell anyone they are fine.
held_packages() {
  local out=""
  if have apt-mark; then
    out="$(apt-mark showhold 2>/dev/null | grep -iE '^php' || true)"
  fi
  if [[ -z "$out" ]] && have dnf; then
    out="$(dnf versionlock list 2>/dev/null | grep -iE 'php' || true)"
  fi
  [[ -n "$out" ]] && printf '%s' "$out"
}

# ---- Ubuntu USN build table -------------------------------------------------
# Ubuntu backports the fix into its own build numbers WITHOUT changing the
# upstream version: noble's 8.3.6-0ubuntu0.24.04.13 IS patched. Comparing
# upstream versions alone gets this wrong in both directions. This table maps
# release codename + branch to the first fixed Ubuntu build.
# Source: USN-8948-1 / USN-8948-2.
UBUNTU_FIXED="${PHPFIX_UBUNTU_FIXED:-trusty:5.5:5.5.9+dfsg-1ubuntu4.29+esm18 xenial:7.0:7.0.33-0ubuntu0.16.04.16+esm22 bionic:7.2:7.2.24-0ubuntu0.18.04.17+esm14 focal:7.4:7.4.3-4ubuntu2.29+esm5 jammy:8.1:8.1.2-1ubuntu2.28 noble:8.3:8.3.6-0ubuntu0.24.04.13 resolute:8.5:8.5.4-0ubuntu1.5 stonking:8.5:8.5.9-0ubuntu2.1}"
UBUNTU_USN="USN-8948-1 / USN-8948-2"

ubuntu_codename() {
  [[ -r /etc/os-release ]] || return 0
  ( . /etc/os-release; [[ "${ID:-}" = ubuntu ]] && printf '%s' "${VERSION_CODENAME:-}" )
}

# Echoes "fixed|<installed>" or "old|<installed>|<needed>"; nothing if N/A.
ubuntu_build() {
  local bin="$1" branch="$2" cn pkg inst e f
  cn="$(ubuntu_codename)"; [[ -n "$cn" ]] || return 0
  have dpkg-query || return 0
  pkg="$(dpkg-query -S "$bin" 2>/dev/null | head -1 | cut -d: -f1)"
  [[ -n "$pkg" ]] || return 0
  inst="$(dpkg-query -W -f='\${Version}' "$pkg" 2>/dev/null)"
  # Only Ubuntu's own archive builds; sury/ondrej PPA has different numbering.
  case "$inst" in *sury*) return 0 ;; *ubuntu*) ;; *) return 0 ;; esac
  for e in $UBUNTU_FIXED; do
    [[ "${e%%:*}" == "$cn" ]] || continue
    [[ "$(printf '%s' "$e" | cut -d: -f2)" == "$branch" ]] || continue
    f="${e#*:*:}"
    if have dpkg && dpkg --compare-versions "$inst" ge "$f" 2>/dev/null; then
      printf 'fixed|%s' "$inst"
    else
      printf 'old|%s|%s' "$inst" "$f"
    fi
    return 0
  done
}

# ---- DirectAdmin CustomBuild ----------------------------------------------
# DA patches EOL branches (7.4/8.0/8.1) without changing the version string,
# so a version comparison reports them vulnerable when they are fixed.
# Compare the binary's mtime against the CVE patch file instead.
# Prefixes are overridable so relocated DA installs and test harnesses work.
DA_ROOT="${PHP2SHELL_DA_ROOT:-/usr/local/directadmin/custombuild}"
DA_PHP_PREFIX="${PHP2SHELL_DA_PHP_PREFIX:-/usr/local/php}"
da_build() {
  local bin="$1" branch="$2" pf
  case "$bin" in
    "$DA_PHP_PREFIX"*) ;;
    # /usr/local/php74/sbin/php-fpm as well as /usr/local/php/74/... layouts
    /usr/local/php*) [[ "$DA_PHP_PREFIX" == /usr/local/php ]] || return 0 ;;
    *) return 0 ;;
  esac
  pf="$(ls -t "$DA_ROOT/patches/php-$branch/"*[Cc][Vv][Ee]-2026-10961[89]*.patch 2>/dev/null | head -1)"
  [[ -n "$pf" ]] || return 0
  if [[ "$bin" -nt "$pf" ]]; then printf 'built'; else printf 'pending'; fi
}

# ---- FastCGI pool probe ----------------------------------------------------
# THE accurate config check. Instead of inferring which php.ini the worker
# loads, connect to the live FPM socket and ask the running worker directly.
# This sees php_admin_value overrides from the pool file, which an ini-file
# grep cannot. Requires root + a running pool; purely read-only (executes one
# tiny probe script that echoes PHP_VERSION and one directive).
FCGI_CLIENT='<?php
$a = $argv[1]; $script = $argv[2];
$s = @stream_socket_client($a[0] === "/" ? "unix://$a" : "tcp://$a", $en, $es, 3);
if (!$s) { echo "ERR:connect"; exit(1); }
stream_set_timeout($s, 5);
function rec($t, $c) { return chr(1).chr($t).pack("n", 1).pack("n", strlen($c))."\0\0".$c; }
function len($n) { return $n < 128 ? chr($n) : pack("N", $n | 0x80000000); }
$p = "";
foreach (array("SCRIPT_FILENAME" => $script, "SCRIPT_NAME" => "/".basename($script),
  "REQUEST_URI" => "/".basename($script), "DOCUMENT_ROOT" => dirname($script),
  "REQUEST_METHOD" => "GET", "QUERY_STRING" => "", "SERVER_PROTOCOL" => "HTTP/1.1",
  "GATEWAY_INTERFACE" => "CGI/1.1", "SERVER_SOFTWARE" => "php2shell-audit") as $k => $v)
  $p .= len(strlen($k)).len(strlen($v)).$k.$v;
fwrite($s, rec(1, pack("nC", 1, 0)."\0\0\0\0\0").rec(4, $p).rec(4, "").rec(5, ""));
$out = "";
while (strlen($h = (string)stream_get_contents($s, 8)) === 8) {
  $r = unpack("Cv/Ct/nid/nlen/Cpad", $h);
  $c = $r["len"] ? (string)stream_get_contents($s, $r["len"]) : "";
  if ($r["pad"]) stream_get_contents($s, $r["pad"]);
  if ($r["t"] == 6) $out .= $c;
  if ($r["t"] == 3) break;
}
echo preg_match("/PHPFIX:[^\r\n]*/", $out, $m) ? $m[0] : "ERR:no-answer";'

find_pool_files() {
  local -a roots=(/etc /usr/local /opt)
  local r f
  for r in "${roots[@]}"; do
    [[ -d "$r" ]] || continue
    # One find per root, filtered in-shell. No xargs -d (GNU-only) and no
    # assumption about filenames, so this is safe on BSD/macOS and in slim
    # containers where findutils is absent.
    while IFS= read -r f; do
      [[ -f "$f" && -r "$f" ]] || continue
      grep -qE '^[[:space:]]*listen[[:space:]]*=' "$f" 2>/dev/null || continue
      grep -qE '^[[:space:]]*pm[[:space:]]*=' "$f" 2>/dev/null || continue
      printf '%s\n' "$f"
    done < <(find "$r" -xdev -type f -name '*.conf' 2>/dev/null)
  done | sort -u
}

# Echoes "<pool>|<addr>|<version>|<upload_progress>|<memory_limit>"
fcgi_pools() {
  [[ "$(id -u)" -eq 0 ]] || return 0
  local cli dir pool addr out f
  cli="$(find_binaries | head -1)"
  [[ -n "$cli" ]] || return 0
  dir="/run/php2shell-audit.$$"
  mkdir -m 755 "$dir" 2>/dev/null || return 0
  printf '%s' "$FCGI_CLIENT" > "$dir/client.php"
  cat > "$dir/check.php" <<'PHPEOF'
<?php
echo 'PHPFIX:' . PHP_VERSION . '|'
   . ini_get('session.upload_progress.enabled') . '|'
   . ini_get('memory_limit');
PHPEOF
  chmod 644 "$dir/check.php"

  while read -r f; do
    [[ -n "$f" ]] || continue
    awk -F'=' '/^[[:space:]]*\[[^]]+\][[:space:]]*$/ { gsub(/[][[:space:]]/, ""); pool=$0 }
               /^[[:space:]]*listen[[:space:]]*=/ && pool != "global" { v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); print pool "|" v }' "$f"
  done < <(find_pool_files) | sort -u | while IFS='|' read -r pool addr; do
    case "$addr" in
      /*)          [[ -S "$addr" ]] || { printf '%s|%s|ERR|not running\n' "$pool" "$addr"; continue; } ;;
      *[!0-9]*:*)  addr="$(printf '%s' "$addr" | sed -E 's/^(\*|0\.0\.0\.0|\[::\]):/127.0.0.1:/')" ;;
      *[!0-9]*)    printf '%s|%s|ERR|unsupported listen\n' "$pool" "$addr"; continue ;;
      *)           addr="127.0.0.1:$addr" ;;
    esac
    # `timeout` is GNU coreutils and missing on macOS/BSD and minimal images.
    # Fall back to perl's alarm-free approach: use the PHP client's own 3s
    # connect + 5s read timeouts, which already bound the operation.
    if have timeout; then
      out="$(timeout 15 "$cli" -n "$dir/client.php" "$addr" "$dir/check.php" 2>/dev/null)"
    else
      out="$("$cli" -n "$dir/client.php" "$addr" "$dir/check.php" 2>/dev/null)"
    fi
    case "$out" in
      PHPFIX:*) printf '%s|%s|%s\n' "$pool" "$addr" "${out#PHPFIX:}" ;;
      *)        printf '%s|%s|ERR|no answer (stopped/chroot/open_basedir?)\n' "$pool" "$addr" ;;
    esac
  done
  rm -rf "$dir"
}

# ---- Litellm supply chain (1.107.0 compromise) ----------------------------
litellm_scan() {
  local py="" v ioc=""
  for c in python3 python; do
    have "$c" && { py="$c"; break; }
  done
  [[ -z "$py" ]] && return 0

  v="$("$py" -m pip show litellm 2>/dev/null | awk '/^Version:/{print $2; exit}')"
  LITELLM_VER="$v"
  if [[ "$v" == "1.107.0" ]]; then
    LITELLM_NOTE="COMPROMISED: litellm 1.107.0 is the malware release"
    OVERALL_BAD=1
  elif [[ -n "$v" ]]; then
    LITELLM_NOTE="litellm $v installed (1.107.0 is the only known-bad release)"
  else
    LITELLM_NOTE=""
  fi

  for f in cook.pth cook.py sitecustomize.py; do
    local hit
    hit="$("$py" - "$f" <<'PY' 2>/dev/null
import sysconfig, os, sys
name = sys.argv[1]
p = sysconfig.get_paths().get("purelib", "")
f = os.path.join(p, name)
print(f if os.path.exists(f) else "")
PY
)"
    [[ -n "$hit" ]] && ioc="$ioc $hit"
  done
  [[ -f /tmp/remote_code_loader.lock ]] && ioc="$ioc /tmp/remote_code_loader.lock"
  for m in /tmp/.pc_once_*; do [[ -e "$m" ]] && ioc="$ioc $m"; done
  LITELLM_IOC="$ioc"
  [[ -n "$ioc" ]] && OVERALL_BAD=1
}

# =============================================================================
# MAIN
# =============================================================================

declare -a ROWS=()
declare -a DOCKER_HITS=()
declare -a USERINI_HITS=()
OVERALL_BAD=0
FOUND_ANY=0
LITELLM_VER=""; LITELLM_NOTE=""; LITELLM_IOC=""

# Portable array fill that works on bash 3.2 (macOS) and 4+, under set -u.
fill_array() {
  local arrname="$1"
  local line i=0
  eval "$arrname=()"
  while IFS= read -r line; do
    eval "$arrname[$i]=\$line"
    i=$((i + 1))
  done
}

fill_array BINS < <(find_binaries 2>/dev/null)

for bin in "${BINS[@]:-}"; do
  [[ -z "$bin" || ! -x "$bin" ]] && continue
  [[ "$bin" == *".dSYM"* ]] && continue

  rawv="$("$bin" -v 2>/dev/null | head -1)"
  [[ -z "$rawv" ]] && continue
  core="$(vcore "$rawv")"
  [[ -z "$core" ]] && continue

  FOUND_ANY=1
  branch="${core%.*}"
  fixed="$(fixed_for "$branch")"
  sapi="$(sapi_of "$bin")"
  pkg="$(package_of "$bin")"
  bp_state="not-a-package"
  [[ -n "$pkg" ]] && bp_state="$(backport_state "$core" "$pkg")"

  verdict=""; detail=""

  # Computed before the branch: the EOL path needs these too, and `set -u`
  # aborts the whole script on an unbound reference.
  ub="$(ubuntu_build "$bin" "$branch" 2>/dev/null)"
  da="$(da_build "$bin" "$branch" 2>/dev/null)"
  ub="${ub:-}"; da="${da:-}"

  if [[ -n "$fixed" ]]; then
    # Order matters. Ubuntu's own build numbers and DirectAdmin's build-time
    # patches can make an "old-looking" version actually fixed. Test those
    # BEFORE the plain version comparison, or patched hosts get reported
    # vulnerable -- the exact false alarm that makes owners stop trusting you.
    if ver_ge "$core" "$fixed"; then
      verdict="PATCHED"; detail="$core >= $fixed"
    elif [[ "${ub%%|*}" == "fixed" ]]; then
      verdict="PATCHED-VIA-BACKPORT"
      detail="Ubuntu build ${ub#fixed|} is the fixed build ($UBUNTU_USN)"
    elif [[ -n "$ub" && "${ub%%|*}" == "old" ]]; then
      verdict="BACKPORT-NEEDED"
      detail="Ubuntu's fixed build is ${ub##*|} ($UBUNTU_USN) -- apt-get upgrade"
    elif [[ "$da" == "built" ]]; then
      verdict="PATCHED-VIA-BACKPORT"
      detail="DirectAdmin CustomBuild backport (binary newer than the CVE patch)"
    elif [[ "$da" == "pending" ]]; then
      verdict="BACKPORT-NEEDED"
      detail="DirectAdmin has the CVE patch but this binary predates it -- da build php"
    elif [[ "$bp_state" == "backported" ]]; then
      verdict="PATCHED-VIA-BACKPORT"
      detail="$core < $fixed, but $pkg changelog cites the CVE"
    elif [[ "$rawv" =~ ^[0-9]+\.[0-9]+\.[0-9]+[-+~] ]] \
      || [[ "$rawv" =~ \.el[0-9] ]] \
      || [[ "$rawv" =~ (ubuntu|debian|sury|remi|plesk|alt-php|amzn) ]]; then
      # Packaged build below the upstream fix. The version string alone does
      # NOT say whether the fix was backported -- only the vendor changelog
      # does. Never report this as plainly VULNERABLE or plainly PATCHED.
      verdict="BACKPORT-NEEDED"
      detail="$core < $fixed; packaged build (${pkg:-unknown package}) -- confirm backport with vendor changelog"
    else
      verdict="VULNERABLE"; detail="$core < $fixed -- update to $fixed or later"
    fi
  else
    case "$branch" in
      # session.upload_progress landed in PHP 5.4 (RFC1867 progress support).
      # On 5.3 and older the directive does not exist, so "set it to 0" is not
      # a weak mitigation -- it is meaningless advice that an owner will apply
      # and then believe they are safe. Say so explicitly.
      3.*|4.*|5.0|5.1|5.2|5.3)
        verdict="LEGACY"
        detail="PHP $branch predates session.upload_progress (5.4+): the INI mitigation cannot apply. Upgrade is the only option."
        ;;
      8.0|8.1|7.*|5.*)
        if [[ "$da" == "built" ]]; then
          verdict="PATCHED-VIA-BACKPORT"
          detail="DirectAdmin CustomBuild backport covers EOL branch $branch"
        elif [[ "${ub%%|*}" == "fixed" ]]; then
          verdict="PATCHED-VIA-BACKPORT"
          detail="Ubuntu ESM build ${ub#fixed|} covers EOL branch $branch ($UBUNTU_USN)"
        elif [[ "$branch" == "8.1" && -n "${ub:-}" ]]; then
          verdict="BACKPORT-NEEDED"
          detail="Ubuntu's fixed build is ${ub##*|} -- apt-get upgrade (older releases: Ubuntu Pro ESM)"
        else
          verdict="EOL-NO-FIX"
          detail="PHP $branch is end-of-life: no upstream fix. Need distro/LTS backport or upgrade."
        fi
        ;;
      *)
        verdict="UNKNOWN"; detail="branch $branch outside the advisory table; verify manually"
        ;;
    esac
  fi

  case "$verdict" in
    VULNERABLE|EOL-NO-FIX|BACKPORT-NEEDED|LEGACY) OVERALL_BAD=1 ;;
  esac

  # SAPI risk. FPM text corrected: GHSA-6wmf-4rv5-p3rp documents a VLIDATED
  # FPM path (app-dependent), not "no complete exploit".
  risk=""
  case "$sapi" in
    apache2handler) risk="CRITICAL: mod_php, pre-auth RCE before app code runs" ;;
    frankenphp)     risk="HIGH: models mod_php; app-independent path likely" ;;
    fpm-fcgi)       risk="HIGH: validated path exists (needs an app-level fatal error + later request on same worker)" ;;
    litespeed)      risk="MEDIUM: models FPM; app-specific exploit likely, unvalidated" ;;
    cgi-fcgi)       risk="HIGH: php-cgi is in advisory scope" ;;
    cli-server)     risk="MEDIUM: do not expose the built-in dev server" ;;
  esac

  # Web-SAPI config: try the binary first, fall back to ini files.
  mem="$(ini_of "$bin" memory_limit)"; [[ -z "$mem" ]] && mem="$(ini_from_files memory_limit)"
  sup="$(ini_of "$bin" session.upload_progress.enabled)"; [[ -z "$sup" ]] && sup="$(ini_from_files session.upload_progress.enabled)"
  feb="$(ini_of "$bin" fatal_error_backtraces)"; [[ -z "$feb" ]] && feb="$(ini_from_files fatal_error_backtraces)"
  uoc="$(ini_of "$bin" session.use_only_cookies)"; [[ -z "$uoc" ]] && uoc="$(ini_from_files session.use_only_cookies)"
  usm="$(ini_of "$bin" session.use_strict_mode)"; [[ -z "$usm" ]] && usm="$(ini_from_files session.use_strict_mode)"
  cln="$(ini_of "$bin" session.upload_progress.cleanup)"; [[ -z "$cln" ]] && cln="$(ini_from_files session.upload_progress.cleanup)"
  seh="$(ini_of "$bin" session.serialize_handler)"; [[ -z "$seh" ]] && seh="$(ini_from_files session.serialize_handler)"

  rstate="$(restart_state "$bin" "$sapi")"

  ROWS+=("${verdict}|${bin}|${core}|${sapi}|${risk}|${mem}|${sup}|${feb}|${uoc}|${usm}|${cln}|${seh}|${rstate}|${detail}|${pkg}")
done

# --- replaced (deleted) PHP mappings -> workers STILL running old code ------
DELETED_PROCS=()
fill_array DELETED_PROCS < <(deleted_php_procs 2>/dev/null)
# A live worker mapping a replaced binary invalidates every PATCHED verdict.
if (( ${#DELETED_PROCS[@]} > 0 )); then
  OVERALL_BAD=1
fi

HELD_PKGS="$(held_packages 2>/dev/null)"
HELD_PKGS="${HELD_PKGS//$'\n'/ }"
[[ -n "$HELD_PKGS" ]] && OVERALL_BAD=1

# --- LIVE FastCGI pool probe (what the running worker actually sees) -------
# This is the only check that reads pool-level php_admin_value overrides.
# Skipped automatically when not root or when no pool is running.
POOL_ROWS=()
if [[ "$(id -u)" -eq 0 ]]; then
  fill_array POOL_ROWS < <(fcgi_pools 2>/dev/null)
fi
# A pool reporting an upload-progress-capable PHP below the fix is actionable.
for pr in "${POOL_ROWS[@]:-}"; do
  [[ -z "$pr" ]] && continue
  IFS='|' read -r _pn _pa _pv _pup _pml <<< "$pr"
  [[ "$_pv" == "ERR" ]] && continue
  _pc="$(vcore "$_pv")"; _pb="${_pc%.*}"; _pf="$(fixed_for "$_pb")"
  if [[ -n "$_pf" ]] && ! ver_ge "$_pc" "$_pf"; then
    OVERALL_BAD=1
  fi
done

# .user.ini can change session.serialize_handler per directory -> Chain C.
for root in /var/www /srv /home /usr/local/lsws/DEFAULT /var/lib/nginx "$PWD"; do
  [[ -d "$root" ]] || continue
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if grep -qiE 'session\.(serialize_handler|upload_progress)' "$f" 2>/dev/null; then
      USERINI_HITS+=("$f")
    fi
  done < <(find "$root" -maxdepth 6 -name ".user.ini" 2>/dev/null)
done

((DO_DOCKER)) && docker_scan

# A container running a vulnerable PHP is a finding on this host, full stop.
# Judgement happens here so the summary can never contradict the detail.
DOCKER_BAD=0
for r in "${DOCKER_HITS[@]:-}"; do
  [[ -z "$r" ]] && continue
  IFS='|' read -r _dn _di _dv _ds _draw <<< "$r"
  _dvd="$(docker_verdict "$_dv")"
  case "${_dvd%%|*}" in
    VULNERABLE|LEGACY|EOL-NO-FIX) DOCKER_BAD=1; OVERALL_BAD=1 ;;
  esac
done

litellm_scan

# =============================================================================
# JSON OUTPUT
# =============================================================================
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'; }

if [[ $JSON -eq 1 ]]; then
  printf '{"host":"%s","generated":"%s","overall":"%s","php":[' \
    "$(jesc "$(hostname 2>/dev/null)")" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" \
    "$( ((OVERALL_BAD)) && echo ACTION_REQUIRED || echo NO_FINDING )"
  first=1
  for r in "${ROWS[@]:-}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r v b c s rk m sp fe uo us cu sh rs d pk <<< "$r"
    ((first)) || printf ','
    first=0
    printf '{"verdict":"%s","binary":"%s","version":"%s","sapi":"%s","memory_limit":"%s","session_upload_progress":"%s","fatal_error_backtraces":"%s","use_only_cookies":"%s","use_strict_mode":"%s","upload_progress_cleanup":"%s","serialize_handler":"%s","restart":"%s","package":"%s","detail":"%s"}' \
      "$(jesc "$v")" "$(jesc "$b")" "$(jesc "$c")" "$(jesc "$s")" "$(jesc "$m")" \
      "$(jesc "$sp")" "$(jesc "$fe")" "$(jesc "$uo")" "$(jesc "$us")" \
      "$(jesc "$cu")" "$(jesc "$sh")" "$(jesc "$rs")" "$(jesc "$pk")" "$(jesc "$d")"
  done
  printf '],"containers":['
  first=1
  for r in "${DOCKER_HITS[@]:-}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r nm im vr ds _draw <<< "$r"
    ((first)) || printf ','
    first=0
    _dv="$(docker_verdict "$vr")"
    printf '{"name":"%s","image":"%s","php":"%s","sapi":"%s","verdict":"%s","detail":"%s"}' \
      "$(jesc "$nm")" "$(jesc "$im")" "$(jesc "$vr")" "$(jesc "$ds")" \
      "$(jesc "${_dv%%|*}")" "$(jesc "${_dv#*|}")"
  done
  printf '],"user_ini":['
  first=1
  for r in "${USERINI_HITS[@]:-}"; do
    [[ -z "$r" ]] && continue
    ((first)) || printf ','
    first=0
    printf '"%s"' "$(jesc "$r")"
  done
  printf '],"deleted_workers":['
  first=1
  for r in "${DELETED_PROCS[@]:-}"; do
    [[ -z "$r" ]] && continue
    ((first)) || printf ','
    first=0
    printf '"%s"' "$(jesc "$r")"
  done
  printf '],"pools":['
  first=1
  for r in "${POOL_ROWS[@]:-}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r pn pa pv pup pml <<< "$r"
    ((first)) || printf ','
    first=0
    printf '{"pool":"%s","listen":"%s","version":"%s","upload_progress":"%s","memory_limit":"%s"}' \
      "$(jesc "$pn")" "$(jesc "$pa")" "$(jesc "$pv")" "$(jesc "$pup")" "$(jesc "$pml")"
  done
  printf '],"held_packages":"%s"' "$(jesc "$HELD_PKGS")"
  printf ',"litellm":{"version":"%s","note":"%s","ioc":"%s"}}\n' \
    "$(jesc "$LITELLM_VER")" "$(jesc "$LITELLM_NOTE")" "$(jesc "$LITELLM_IOC")"
  exit 0
fi

# =============================================================================
# HUMAN OUTPUT
# =============================================================================
echo
echo "${B}PHP2Shell on-host audit${N}"
echo "  host: $(hostname 2>/dev/null)   $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
echo "  CVE-2026-109618 (OOM corruption) / CVE-2026-109619 (stale global state)"
echo "  fixed: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
echo

if [[ $FOUND_ANY -eq 0 ]]; then
  echo "${Y}No PHP binary found on this filesystem.${N}"
  echo "  This is NOT a clean bill of health. If this host serves PHP, the"
  echo "  runtime is elsewhere: a container image, an appliance, or another"
  echo "  machine. Audit the image, not the base OS."
  ((DO_DOCKER)) || echo "  (--no-docker was passed: container inspection was skipped)"
  echo
else
  echo "-------------------------------------------------------------"
  echo " ${B}PHP runtimes found${N}"
  echo "-------------------------------------------------------------"
  for r in "${ROWS[@]:-}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r v b c s rk m sp fe uo us cu sh rs d pk <<< "$r"

    case "$v" in
      PATCHED|PATCHED-VIA-BACKPORT) col="$G" ;;
      VULNERABLE|EOL-NO-FIX|BACKPORT-NEEDED|LEGACY) col="$R" ;;
      *) col="$Y" ;;
    esac

    echo
    echo "  ${col}${B}${v}${N}"
    echo "    binary      : $b"
    echo "    version     : $c${pk:+   (package: $pk)}"
    echo "    sapi        : $s${rk:+  [$rk]}"
    echo "    ${d}"
    echo "    memory_limit: ${m:-UNKNOWN}"
    echo "    session.upload_progress.enabled : ${sp:-UNKNOWN}"
    echo "    session.upload_progress.cleanup : ${cu:-UNKNOWN}"
    echo "    session.use_only_cookies        : ${uo:-UNKNOWN}"
    echo "    session.use_strict_mode         : ${us:-UNKNOWN}"
    echo "    session.serialize_handler       : ${sh:-UNKNOWN}"
    echo "    fatal_error_backtraces          : ${fe:-UNKNOWN}"

    case "${rs%%:*}" in
      restarted) echo "    restart     : ${G}workers restarted after update${N}  (${rs#*:})" ;;
      stale)     echo "    restart     : ${R}STALE WORKERS${N}  (${rs#*:} -- patch is on disk, not in RAM)" ;;
      *)         echo "    restart     : ${Y}cannot confirm${N}  (${rs#*:})" ;;
    esac
  done
  echo
fi

# ---- replaced-binary workers (the strongest signal) ------------------------
echo "-------------------------------------------------------------"
echo " ${B}Workers still running a REPLACED binary${N}"
echo "-------------------------------------------------------------"
if (( ${#DELETED_PROCS[@]} > 0 )); then
  echo "  ${R}${B}STALE WORKERS FOUND${N}"
  echo
  for r in "${DELETED_PROCS[@]}"; do echo "    $r"; done
  echo
  echo "  These processes still map the OLD PHP library, which the kernel has"
  echo "  marked '(deleted)'. The package on disk is new, so php -v reports the"
  echo "  new version -- but the running code is still the vulnerable one."
  echo
  echo "  Fix: restart the service. Nothing else helps."
  echo "    systemctl restart php-fpm || systemctl restart apache2"
  echo "  Then re-run this script until this section is empty."
else
  if [[ -d /proc ]]; then
    echo "  ${G}none${N} -- no PHP process is mapping a replaced binary"
  else
    echo "  not applicable (no /proc on this platform; Linux-only check)"
  fi
fi
echo

# ---- held packages ---------------------------------------------------------
if [[ -n "$HELD_PKGS" ]]; then
  echo "-------------------------------------------------------------"
  echo " ${B}${R}HELD / VERSION-LOCKED PACKAGES${N}"
  echo "-------------------------------------------------------------"
  echo "  $HELD_PKGS"
  echo
  echo "  A held package skips security updates silently. This host will keep"
  echo "  reporting an old version no matter how often you run apt/dnf upgrade."
  echo "    Debian/Ubuntu:  apt-mark unhold <pkg>"
  echo "    RHEL family  :  dnf versionlock delete <pkg>"
  echo
fi

echo "-------------------------------------------------------------"
echo " ${B}PHP inside running containers${N}"
echo "-------------------------------------------------------------"
if ((${#DOCKER_HITS[@]})); then
  for r in "${DOCKER_HITS[@]}"; do
    IFS='|' read -r nm im vr ds _draw <<< "$r"
    dv="$(docker_verdict "$vr")"
    # dv may carry a "|<fixed>" suffix; match on the verdict word only.
    case "${dv%%|*}" in
      VULNERABLE)
        echo "  ${R}${B}VULNERABLE${N}  ${nm}  (${im})"
        echo "     ${vr}  -- below ${dv#VULNERABLE|}, rebuild the image" ;;
      PATCHED)
        echo "  ${G}PATCHED${N}     ${nm}  (${im})"
        echo "     ${vr}" ;;
      LEGACY)
        echo "  ${R}${B}LEGACY${N}    ${nm}  (${im})"
        echo "     ${vr}  -- predates the INI mitigation; upgrade" ;;
      EOL-NO-FIX)
        echo "  ${R}${B}EOL${N}       ${nm}  (${im})"
        echo "     ${vr}  -- end-of-life, no upstream fix" ;;
      *)
        echo "  ${Y}UNKNOWN${N}   ${nm}  (${im})"
        echo "     ${vr}" ;;
    esac
  done
  echo "  ^ a patched image on this host does not mean other hosts are patched."
else
  if ((DO_DOCKER == 0)); then
    echo "  skipped (--no-docker)"
  elif have docker && docker info >/dev/null 2>&1; then
    echo "  no running container exposed a PHP binary"
  else
    echo "  docker not available on this host (nothing checked)"
  fi
fi
echo

# ---- user.ini --------------------------------------------------------------
echo "-------------------------------------------------------------"
echo " ${B}.user.ini files that touch session settings${N}"
echo "-------------------------------------------------------------"
if ((${#USERINI_HITS[@]})); then
  for f in "${USERINI_HITS[@]}"; do echo "  $f"; done
  echo
  echo "  Different session.serialize_handler values across directories that"
  echo "  share a save_path enable the handler-mismatch chain. Keep it uniform."
else
  echo "  none found under /var/www /srv /home /usr/local/lsws/DEFAULT"
fi
echo

# ---- live FastCGI pools ----------------------------------------------------
echo "-------------------------------------------------------------"
echo " ${B}Live PHP-FPM pools (read from the running worker)${N}"
echo "-------------------------------------------------------------"
if ((${#POOL_ROWS[@]})); then
  for r in "${POOL_ROWS[@]}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r pn pa pv pup pml <<< "$r"
    if [[ "$pv" == "ERR" ]]; then
      echo "  ${Y}${pn}${N}  (${pa})  ${pml}"
      continue
    fi
    pc="$(vcore "$pv")"; pb="${pc%.*}"; pf="$(fixed_for "$pb")"
    if [[ -n "$pf" ]] && ! ver_ge "$pc" "$pf"; then
      echo "  ${R}${B}${pn}${N}  (${pa})"
      echo "     PHP $pv  -- BELOW $pf for this branch"
    else
      echo "  ${G}${pn}${N}  (${pa})"
      echo "     PHP $pv"
    fi
    echo "     upload_progress.enabled: ${pup:-?}   memory_limit: ${pml:-?}"
  done
  echo
  echo "  These values are what the RUNNING worker reports, including pool-level"
  echo "  php_admin_value overrides. They beat any php.ini file grep."
else
  # Order matters for an honest message: on macOS there is no /run at all, so
  # "needs root" would send the reader chasing a permission problem that does
  # not exist.
  if [[ ! -d /run ]]; then
    echo "  skipped -- no /run: this is not a Linux PHP-FPM host"
  elif [[ "$(id -u)" -ne 0 ]]; then
    echo "  skipped -- needs root to talk to the FPM socket"
  else
    echo "  no running PHP-FPM pool found (or none reachable)"
  fi
fi
echo

# ---- mitigations -----------------------------------------------------------
echo "-------------------------------------------------------------"
echo " ${B}Interim mitigations in force${N}"
echo "-------------------------------------------------------------"
mit=0
for r in "${ROWS[@]:-}"; do
  [[ -z "$r" ]] && continue
  IFS='|' read -r v b c s rk m sp fe uo us cu sh rs d pk <<< "$r"

  # 109618 mitigation
  if [[ "$m" == "-1" ]]; then
    echo "  ${G}[OK]${N}   memory_limit=-1  (109618 OOM path defanged)  $b"
    mit=1
  fi
  # 109619 mitigation
  if [[ "$sp" =~ ^(Off|0|)$ ]]; then :; else
    if [[ "$sp" =~ ^(On|1)$ ]]; then
      echo "  ${Y}[--]${N}   session.upload_progress.enabled=$sp  (109619 producer/consumer reachable)  $b"
    fi
  fi
  # Never use (( ver_ge ... )) here: under `set -u` bash parses that as an
  # arithmetic expression, treats the function name as a variable named
  # ver_ge, and aborts the whole script with "unbound variable".
  if ver_ge "${c:-0.0.0}" "8.5.0"; then
    if [[ "$fe" =~ ^(On|1)$ ]]; then
      echo "  ${Y}[--]${N}   fatal_error_backtraces=$fe  (8.5 producer)  $b"
    fi
  fi
done
((mit)) || echo "  memory_limit=-1 not set anywhere (that is fine if already patched)"
echo
echo "  Reminder: no configuration is a complete mitigation. Patching is."
echo "  Never apply RLIMIT_AS / RLIMIT_DATA -- they force the vulnerable longjmp path."
echo

# ---- litellm ---------------------------------------------------------------
if [[ -n "$LITELLM_NOTE" || -n "$LITELLM_IOC" ]]; then
  echo "-------------------------------------------------------------"
  echo " ${B}LiteLLM supply chain (1.107.0 was malware, 2026-10-21)${N}"
  echo "-------------------------------------------------------------"
  [[ -n "$LITELLM_NOTE" ]] && echo "  $LITELLM_NOTE"
  if [[ -n "$LITELLM_IOC" ]]; then
    echo "  ${R}IOC FILES PRESENT:${N}$LITELLM_IOC"
    echo "  Treat this host as COMPROMISED. Rotate every reachable credential,"
    echo "  then rebuild from a clean image. Removing litellm is not enough:"
    echo "  cook.pth runs on every Python start and survives pip uninstall."
  else
    echo "  IOC files: none in the default site-packages"
  fi
  echo
fi

# ---- verdict ---------------------------------------------------------------
echo "============================================================="
if ((OVERALL_BAD)); then
  echo " ${R}${B}ACTION REQUIRED${N}"
  echo "============================================================="
  echo
  echo "  1. Update PHP to the first fixed release for each branch."
  echo "  2. Restart Apache / php-fpm. Files on disk do nothing until workers"
  echo "     are replaced. Then rebuild and redeploy every container image."
  echo "  3. Re-run this script. You are not done until it says PATCHED and"
  echo "     restart says 'workers restarted after update'."
  # Only offer the INI mitigations if at least one runtime is new enough for
  # them to mean anything. On a 5.3-only host, step 4 as written is false
  # comfort: session.upload_progress does not exist there.
  # ROWS elements are joined by spaces, so an anchored grep over ${ROWS[*]}
  # cannot see per-row starts. Inspect the verdict field properly.
  has_legacy=0; has_actionable=0
  for _r in "${ROWS[@]:-}"; do
    [[ -z "$_r" ]] && continue
    case "${_r%%|*}" in
      LEGACY) has_legacy=1 ;;
      VULNERABLE|EOL-NO-FIX|BACKPORT-NEEDED) has_actionable=1 ;;
    esac
  done
  if ((has_legacy)); then
    echo "  4. At least one runtime is OLDER than PHP 5.4. The INI mitigations"
    echo "     DO NOT EXIST on those versions -- session.upload_progress was added"
    echo "     in 5.4. For those hosts, upgrade or isolate them; there is no"
    echo "     configuration workaround."
    if ((has_actionable)); then
      echo "     Other runtimes on this host CAN be mitigated today:"
      echo "       memory_limit=-1                    (109618 OOM path)"
      echo "       session.upload_progress.enabled=0  (109619 producer)"
      echo "     Both must be enforced administratively, then restart every worker."
    fi
  else
    echo "  4. Cannot patch today? memory_limit=-1 for 109618 and"
    echo "     session.upload_progress.enabled=0 for 109619, both enforced"
    echo "     administratively, then restart every worker."
  fi
else
  echo " ${G}${B}NO AFFECTED INSTALL DETECTED BY THIS CHECK${N}"
  echo "============================================================="
  echo
  echo "  Every PHP runtime inspected on THIS host is at or above the fixed"
  echo "  release, or the distro changelog confirms a backport."
  echo
  echo "  Scope caveat, read before reporting this as 'safe':"
  echo "    - Only this host. Other servers, containers on other hosts,"
  echo "      appliances and SaaS are not covered."
  echo "    - Run it on every host and in every image build, then aggregate."
fi
echo "============================================================="
