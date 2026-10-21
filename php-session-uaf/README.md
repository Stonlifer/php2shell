# php-session-uaf — one-command RCE for CVE-2026-109618 / CVE-2026-109619

A single script, `sessionshell.py`, achieves unauthenticated RCE against PHP
8.4.26 + Apache prefork + mod_php. Constraints that make this interesting:

- fully remote, HTTP-only — the only traffic is ordinary multipart POST
- the target page needs no `session_start()`
- no PHP is written to the target
- no upload form, login, or vulnerable application code is required

The bug fires in `php_session_rfc1867_callback` inside `php_hash_environment`,
**before** `zend_activate_modules` and therefore before any application code
runs. Any PHP page that returns a response is a valid target.

## Provenance

The core ASLR-bypass chain is **9bie's**
([php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)).
The two-stage `Set-Cookie` leak and the `HashTable` forgery with
`pDestructor = zif_system` are theirs. This copy is extended with:

- URL → container auto-resolution and `/out` mount discovery
- automatic staging of the reverse-shell trigger (no manual `nc`)
- a built-in interactive shell listener with raw-TTY handling
- proof-file fallback and container-aware result checking

Local work is MIT-licensed; the upstream chain is not re-licensed. See the
repository root `LICENSE`.

## Usage

```bash
# Interactive reverse shell — no command, no listener to start:
python3 sessionshell.py -u http://127.0.0.1:8091/

# Explicit command (max 14 bytes; see below):
python3 sessionshell.py -u http://127.0.0.1:8091/ -c 'id>/out/p1'

# Framework targets with a larger memory_limit need a bigger OOM field:
python3 sessionshell.py -u http://127.0.0.1:8090/ -c 'id>/tmp/lv' \
    --proof-file ''
```

### The 14-byte command limit

The command is embedded in a 167-byte live `zend_string`
(167 − 0x98 header − 1 NUL = 14 bytes). For anything longer, stage a script on
the target's `/out` mount and run it via a read redirect:

```bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 sessionshell.py -u <url> -c 'sh</out/c'
```

The shipped `wordpress/stage.sh` does exactly this, which is why the demo uses
`sh</out/x` (8 bytes).

### Options

`--cmd`, `--proof-file`, `--fetch`, `--zif-offset`, `--dtor-offset`,
`--htdata-offset`, `--offsets-file`, `--docker-container`, `--huge-mb`,
`--no-pre-rotate`, `--no-auto-offsets`, `--retries`, `--profile`, `--quiet`.

On a local target the script runs `docker/offsets.py` once to read the real
`libphp.so` symbol offsets, so a rebuilt or upgraded image needs no manual
editing. Offsets land in `out/offsets.env`.

## How the chain works

Vulnerable surface: session initialization triggered by
`session.upload_progress` before RINIT, plus a dangling pointer left across
requests after an OOM bailout.

1. **Worker rotation** — a 3 MB live POST field plus a 12 MB OOM field is
   followed by a request that initializes a session. The child exits on
   SIGABRT; the replacement worker forked by prefork inherits the same
   `libphp` and chunk mappings, so leaked addresses stay valid.
2. **Heap leak** — 1001 fields trigger the `max_input_vars` warning
   (`display_errors=On` ⇒ `headers_sent=1`); `PHPSESSID=\x00` generates a new
   id and sets `send_cookie=1`; the final 12 MB field OOMs inside
   `php_session_initialize()`, leaving `PS(http_session_vars)` dangling. The
   next request reoccupies the old reference with a 56-byte multipart buffer
   and uses a surviving 192-byte `zend_string` to carry a fake `HashTable`.
   The out-of-bounds read in `php_url_encode()` writes Zend MM chunk pointers
   into a 4096-byte `Set-Cookie`.
3. **libphp leak** — the dangling `PS(id)` is placed at `chunk+0xb7400`; a
   56-byte `HashTable` page makes `ZSTR_LEN(PS(id))` read `nTableSize=16`, and
   the data area lines up as `nNextFreeElement|pDestructor` with
   `pDestructor = ZVAL_PTR_DTOR`, from which the `libphp` base is decoded.
4. **Execution** — six pads pin the dangling reference at `R0=chunk+0x24e0`;
   the next request overwrites `R0-0x10`, places the fake `HashTable` in a
   167-byte surviving string, and sets `pDestructor = zif_system`:

   ```text
   php_session_track_init()
     zval_ptr_dtor(PS(http_session_vars))
       zend_reference_destroy(R0)
         zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
           zend_array_destroy(fake HT)
             zend_hash_destroy(fake HT)
               pDestructor(&bucket->val)   # zif_system
   ```

   The terminal stage needs only `zif_system` inside `libphp`; libc is not
   involved.

## Why it works

- **No `session_start()` needed** — A/B session initialization happens in the
  multipart callbacks before RINIT (`FILE_START →
  php_session_rfc1867_update → php_session_initialize()`; `END →
  php_session_rfc1867_cleanup → php_session_initialize()`), independent of
  script content.
- **The pointer dangles** — the OOM bailout exits `php_session_initialize()`
  without clearing `PS(http_session_vars)` / `PS(id)`; the next session init
  calls `zval_ptr_dtor` on it.
- **Reoccupation is exact** — multipart field values are allocated as
  `zend_string`s during parsing; the 56-byte block, 55-byte reference, and
  167-byte string sizes line up to cover the old reference and carry the fake
  `HashTable`.
- **ASLR is bypassed over HTTP** — two `Set-Cookie` out-of-bounds reads leak
  the chunk base and the `libphp` base; abort/fork between stages swaps
  workers while the address space is preserved.

Offsets (default `bookworm` profile, auto-read from the container):

| Symbol | Offset |
|---|---|
| `zif_system` | `0x465370` |
| `zval_ptr_dtor` | `0x65eb60` |

Stage-3 fake `HashTable` data sits at `chunk+0x690d8`.

## Requirements on the target

`display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`,
`session.use_cookies=1`, `session.use_strict_mode=0`,
`session.upload_progress.enabled=1`, and **single-worker prefork**.

Raising `memory_limit` is fine, but the OOM field must exceed it or stage 1
never leaks. The script now reads `memory_limit` from the container and sizes
the field itself; `--huge-mb` overrides it if you need to force a value.

## Scope

This tool demonstrates code execution as the web user (`www-data`). It does
not include, and the CVE does not provide, privilege escalation.

For authorized testing and research only. It is designed against the lab
targets in this repository, which bind to `127.0.0.1`.
