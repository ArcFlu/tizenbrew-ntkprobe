'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8145;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe57h.txt';
var DST_BINARY = '/run/user/5001/tzmem_probe';
var SRC_BINARY = '/home/owner/share/tmp/sdk_tools/tzmem_probe';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',
  'try { if (!fs.existsSync("/run/user/5001/tzmem_probe")) { var b = fs.readFileSync("/home/owner/share/tmp/sdk_tools/tzmem_probe"); fs.writeFileSync("/run/user/5001/tzmem_probe", b, {mode:0o755}); } fs.chmodSync("/run/user/5001/tzmem_probe", 0755); result.binary_ready = true; } catch(e) { result.binary_ready_err = e.message; }',
  'try {',
  '  var r = cp.execFileSync("/run/user/5001/tzmem_probe", [], {timeout:12000});',
  '  result.tzmem_execfile = r.toString();',
  '} catch(e) {',
  '  result.tzmem_execfile_err = e.message.slice(0,300);',
  '  result.tzmem_execfile_stdout = e.stdout ? e.stdout.toString() : "";',
  '}',
  'try {',
  '  var r2 = cp.execFileSync("/home/owner/share/tmp/sdk_tools/tzmem_probe", [], {timeout:12000});',
  '  result.tzmem_sdb_execfile = r2.toString();',
  '} catch(e) {',
  '  result.tzmem_sdb_execfile_err = e.message.slice(0,300);',
  '}',
  'try { result.smack_access = fs.readFileSync("/sys/fs/smackfs/access","utf8"); } catch(e) { result.smack_access_err = e.message; }',
  'try { result.smack_load_head = fs.readFileSync("/sys/fs/smackfs/load","utf8").split("\\n").slice(0,30); } catch(e) { result.smack_load_err = e.message; }',
  'try { result.smack_load2_head = fs.readFileSync("/sys/fs/smackfs/load2","utf8").split("\\n").slice(0,50); } catch(e) { result.smack_load2_err = e.message; }',
  'try {',
  '  var fd = fs.openSync("/dev/tzmem", "r+");',
  '  result.tzmem_fd = fd;',
  '  var tbuf = Buffer.alloc(256);',
  '  var nr = fs.readSync(fd, tbuf, 0, 256, 0);',
  '  result.tzmem_read_bytes = nr;',
  '  result.tzmem_read_hex = tbuf.slice(0, nr).toString("hex");',
  '  fs.closeSync(fd);',
  '} catch(e) { result.tzmem_read_err = e.message; }',
  'var services = ["com.samsung.tizen.ssm", "comss.server", "org.tizen.tv.automation-service", "com.jackpack.migration"];',
  'result.dbus_introspect = {};',
  'services.forEach(function(svc) {',
  '  try {',
  '    var r3 = cp.execSync("dbus-send --system --print-reply --dest=" + svc + " / org.freedesktop.DBus.Introspectable.Introspect 2>&1", {timeout:4000});',
  '    result.dbus_introspect[svc] = r3.toString().slice(0,1500);',
  '  } catch(e) {',
  '    result.dbus_introspect[svc] = "err:" + e.message.slice(0,100);',
  '  }',
  '});',
  'try { result.smack_self = fs.readFileSync("/proc/self/attr/current","utf8").trim(); } catch(e) {}',
  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'try { fs2.writeFileSync("/home/owner/share/tmp/sdk_tools/tbprobe57h.txt", out); } catch(e) {}',
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
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe57h.txt', result); } catch(e) {}
  });
});
