'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8144;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe56h.txt';
var SRC_BINARY = '/home/owner/share/tmp/sdk_tools/tzmem_probe';
var DST_BINARY = '/run/user/5001/tzmem_probe';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',
  'try {',
  '  var buf = fs.readFileSync("/home/owner/share/tmp/sdk_tools/tzmem_probe");',
  '  result.src_read_ok = true; result.src_size = buf.length;',
  '  fs.writeFileSync("/run/user/5001/tzmem_probe", buf, {mode: 0o755});',
  '  result.dst_write_ok = true;',
  '  fs.chmodSync("/run/user/5001/tzmem_probe", 0755);',
  '  result.chmod_ok = true;',
  '} catch(e) { result.copy_err = e.message; }',
  'try {',
  '  var out = cp.execSync("/run/user/5001/tzmem_probe 2>&1", {timeout:15000});',
  '  result.tzmem_probe = out.toString();',
  '} catch(e) {',
  '  result.tzmem_probe_err = e.message.slice(0,300);',
  '  result.tzmem_probe_stdout = e.stdout ? e.stdout.toString() : "";',
  '}',
  'try {',
  '  var buf2 = fs.readFileSync("/home/owner/share/tmp/sdk_tools/tzmem_probe");',
  '  fs.writeFileSync("/tmp/tzmem_probe2", buf2, {mode: 0o755});',
  '  var out2 = cp.execSync("/tmp/tzmem_probe2 2>&1", {timeout:15000});',
  '  result.tzmem_probe_tmp = out2.toString();',
  '} catch(e) {',
  '  result.tzmem_probe_tmp_err = e.message.slice(0,300);',
  '  result.tzmem_probe_tmp_stdout = e.stdout ? e.stdout.toString() : "";',
  '}',
  'try { result.tz_sys_db = cp.execSync("ls -la /opt/dbspace/ 2>/dev/null; ls -la /usr/dbspace/ 2>/dev/null; ls -la /opt/usr/dbspace/ 2>/dev/null", {timeout:3000}).toString().trim(); } catch(e) { result.tz_sys_db_err = e.message; }',
  'try { result.proc_mounts_full = fs.readFileSync("/proc/mounts","utf8").trim(); } catch(e) {}',
  'try { result.getfattr = cp.execSync("getfattr -n security.SMACK64 /home/owner/share/tmp/sdk_tools/tzmem_probe 2>&1", {timeout:3000}).toString(); } catch(e) { result.getfattr_err = e.message; }',
  'try { result.getfattr_dst = cp.execSync("getfattr -n security.SMACK64 /run/user/5001/tzmem_probe 2>&1", {timeout:3000}).toString(); } catch(e) { result.getfattr_dst_err = e.message; }',
  'try { result.dbus_list = cp.execSync("dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>&1", {timeout:5000}).toString().slice(0,2000); } catch(e) { result.dbus_list_err = e.message; }',
  'try { result.pid = process.pid; } catch(e) {}',
  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'try { fs2.writeFileSync("/home/owner/share/tmp/sdk_tools/tbprobe56h.txt", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 60000 }, function(err, stdout, stderr) {
    var result;
    if (err) {
      result = JSON.stringify({ exec_error: err.message, stderr: stderr, stdout: stdout || '' });
    } else {
      result = stdout || '(empty)';
    }
    cb(result);
  });
}

var server = http.createServer(function(req, res) {
  runProbe(function(result) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(result);
  });
});

server.listen(PORT, function() {
  runProbe(function(result) {
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe56h.txt', result); } catch(e) {}
  });
});
