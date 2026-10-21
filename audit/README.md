# audit-host.sh — read-only on-host detection

Answers one question per host: **is the PHP that actually serves requests
running code with the fix in it?**

Read-only. Starts nothing, writes nothing, changes no configuration. No
exploit payloads are sent and OOM is never triggered, so it is safe to run on
production.

```bash
sudo ./audit-host.sh              # human-readable report
sudo ./audit-host.sh --json       # machine-readable, for aggregation
sudo ./audit-host.sh --no-docker  # skip container inspection
```

Root is recommended but not required. Without it you lose the live FastCGI
pool probe and other processes' `/proc/*/maps`; the report says so explicitly
rather than guessing.

Fixed releases:

| Branch | Fixed in |
|---|---|
| PHP 8.5 | **8.5.12** |
| PHP 8.4 | **8.4.27** |
| PHP 8.3 | **8.3.36** |
| PHP 8.2 | **8.2.35** |
| PHP 8.1 / 8.0 / 7.x | **no upstream fix** (EOL) |

## Why `php -v` is not enough

Three things defeat a naive version comparison:

1. **Backports.** A distro package can keep an old upstream number while
   carrying the fix — Ubuntu's `8.3.6-0ubuntu0.24.04.13` is fully patched.
   Comparing upstream version strings gets this wrong in both directions.
2. **Panel patches.** DirectAdmin patches EOL branches without changing the
   version string at all.
3. **Un-restarted workers.** After an upgrade the file on disk is patched, but
   already-running workers keep the old inode mapped. `php -v` reports the new
   version while the live process still executes vulnerable code. This is the
   most common real-world failure.

So the script checks four independent things: the binary, the package
changelog, the live FastCGI worker, and `/proc/*/maps`.

## What it detects

- **Binaries** across `PATH` and standard prefixes, including cPanel EA-PHP,
  Plesk, CloudLinux `alt-php`, LiteSpeed `lsphp`, DirectAdmin, Remi, MAMP.
- **Distro backports** by reading the package changelog for the CVE id —
  Debian, Ubuntu, RHEL and Sury/PPA builds that retain the old version number.
- **Ubuntu USN builds** via `dpkg --compare-versions` against the fixed build
  for each release codename.
- **DirectAdmin CustomBuild** backports, by comparing the binary's mtime to the
  CVE patch file.
- **Live FastCGI pools** — connects to the FPM socket and asks the *running*
  worker for `PHP_VERSION`, `session.upload_progress.enabled` and
  `memory_limit`. This is the only check that sees pool-level
  `php_admin_value` overrides, which no file grep can resolve.
- **Stale workers** still mapping a `(deleted)` PHP library.
- **Containers** — asks each running container's PHP for its version and SAPI,
  distinguishing `mod_php` (the CRITICAL tier) from FPM. A vulnerable image
  makes the overall verdict `ACTION_REQUIRED`.
- **Held packages** (`apt-mark showhold`, `dnf versionlock`) that would silently
  block an upgrade.
- **`.user.ini`** files that change session settings, which enable the
  handler-mismatch exploit chain.
- **LiteLLM 1.107.0** supply-chain artifacts (`cook.pth`, `cook.py`,
  `sitecustomize.py`, `/tmp/remote_code_loader.lock`).

## Verdicts

| Verdict | Meaning |
|---|---|
| `PATCHED` | At or above the fixed release for that branch. |
| `PATCHED-VIA-BACKPORT` | Old version number, but the vendor backported the fix. The evidence is named in the note. |
| `VULNERABLE` | Below the fixed release, no backport evidence. |
| `BACKPORT-NEEDED` | Packaged build below the fix and the changelog does not confirm one. Upgrade and re-check; do **not** report this as patched. |
| `EOL-NO-FIX` | 7.x / 8.0 / 8.1. No upstream fix exists. Not "fine because EOL". |
| `LEGACY` | Older than 5.4. `session.upload_progress` does not exist there, so the INI mitigation **cannot** apply. Upgrade is the only option. |
| `UNKNOWN` | Could not determine. Report it as unknown. |

`--json` reports `overall` as `ACTION_REQUIRED` or `NO_FINDING`, with per-binary
and per-container verdicts, so results from every host can be aggregated.

## Verified against the lab

```
 PHP inside running containers
-------------------------------------------------------------
  VULNERABLE  acme-laravel    (laravel-blog)
     PHP 8.4.26  -- below 8.4.27, rebuild the image
  VULNERABLE  acme-wordpress  (wordpress-wordpress)
     PHP 8.4.26  -- below 8.4.27, rebuild the image

=============================================================
 ACTION REQUIRED
=============================================================
```

A `php:8.4.27` image reports `PATCHED` and does not trip the summary.

## If you cannot patch today

The advisory mitigation is `memory_limit=-1` and
`session.upload_progress.enabled=0`, enforced administratively, then **every**
worker restarted. Check pool configs, `.user.ini` and `.htaccess` for anything
that reintroduces a finite limit.

- **Do not** use `RLIMIT_AS` / `RLIMIT_DATA`. They make `mmap()` fail at the
  limit, which is exactly the `longjmp()` path the exploit needs.
- Blocking `multipart/form-data` at the frontend covers one OOM strategy, not
  all of them.
- A cgroup `memory.max` is imperfect: killing the cgroup can take the master
  and all workers with it.
- On PHP below 5.4 none of this applies — the directive does not exist.

No configuration is a complete mitigation. Patching is.

## Things that are NOT fixes

- WAF rules. Vendors call them temporary.
- Upgrading PHP while leaving old workers running.
- Treating `UNKNOWN` as safe.
- Bumping LiteLLM to `1.107.0`. That is the compromised release.

## Scope

One host per run. Run it on every server and in every image build, then
aggregate the `--json` output. A clean result covers only the host it ran on:
a container image, appliance or untracked host elsewhere is not covered.

Requirements: bash 3.2+ (macOS works), plus whichever of `docker`,
`dpkg`/`rpm`/`apk`, `apt-mark`/`dnf` exist on the host. Each missing tool is
reported as skipped, never as a pass.
