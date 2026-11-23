'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8158;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe70h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',
  'try { r.ntksys = JSON.stringify(fs.statSync("/dev/ntksys")); } catch(e) { r.ntksys_err = e.message; }',
  'try { r.tzmem = JSON.stringify(fs.statSync("/dev/tzmem")); } catch(e) { r.tzmem_err = e.message; }',
  'try { r.mem = JSON.stringify(fs.statSync("/dev/mem")); } catch(e) { r.mem_err = e.message; }',
  'try { r.kmem = JSON.stringify(fs.statSync("/dev/kmem")); } catch(e) { r.kmem_err = e.message; }',
  'try {',
  '  var devs = fs.readdirSync("/dev");',
  '  r.dev_ntk = devs.filter(function(d){ return d.indexOf("ntk") > -1 || d.indexOf("mem") > -1; });',
  '} catch(e) { r.dev_err = e.message; }',
  'try {',
  '  var out = cp.execSync("find /usr/bin /bin /usr/sbin /sbin -perm /4000 -type f 2>/dev/null", {timeout:10000});',
  '  r.suid = out.toString().trim();',
  '} catch(e) { r.suid_err = e.message.slice(0,80); }',
  'try { r.uname = cp.execSync("uname -a", {timeout:3000}).toString().trim(); } catch(e) { r.uname_err = e.message; }',
  'try { r.caps = cp.execSync("grep Cap /proc/self/status", {timeout:3000}).toString().trim(); } catch(e) { r.caps_err = e.message; }',
  'var out2 = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out2); } catch(e2) {}',
  'process.stdout.write(out2);'
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
