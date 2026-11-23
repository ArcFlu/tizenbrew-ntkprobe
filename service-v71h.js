'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8159;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe71h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // Full /dev listing
  'try { r.dev_all = fs.readdirSync("/dev"); } catch(e) { r.dev_all_err = e.message; }',

  // Stat all interesting devices
  'var devs = ["/dev/tzmem","/dev/sdp_hwmem","/dev/sdp_mem","/dev/memnotify","/dev/memory_bandwidth"];',
  'r.dev_stats = {};',
  'devs.forEach(function(d) {',
  '  try {',
  '    var s = fs.statSync(d);',
  '    r.dev_stats[d] = { mode: s.mode.toString(8), uid: s.uid, gid: s.gid, rdev: s.rdev };',
  '  } catch(e) { r.dev_stats[d] = e.message; }',
  '});',

  // Try open /dev/tzmem
  'try {',
  '  var fd = fs.openSync("/dev/tzmem", "r");',
  '  var buf = new Buffer(64);',
  '  var n = fs.readSync(fd, buf, 0, 64, 0);',
  '  fs.closeSync(fd);',
  '  r.tzmem_read = { bytes: n, hex: buf.slice(0,n).toString("hex") };',
  '} catch(e) { r.tzmem_read_err = e.message; }',

  // Try open /dev/sdp_hwmem
  'try {',
  '  var fd2 = fs.openSync("/dev/sdp_hwmem", "r");',
  '  var buf2 = new Buffer(64);',
  '  var n2 = fs.readSync(fd2, buf2, 0, 64, 0);',
  '  fs.closeSync(fd2);',
  '  r.sdp_hwmem_read = { bytes: n2, hex: buf2.slice(0,n2).toString("hex") };',
  '} catch(e) { r.sdp_hwmem_read_err = e.message; }',

  // Try open /dev/sdp_mem
  'try {',
  '  var fd3 = fs.openSync("/dev/sdp_mem", "r");',
  '  var buf3 = new Buffer(64);',
  '  var n3 = fs.readSync(fd3, buf3, 0, 64, 0);',
  '  fs.closeSync(fd3);',
  '  r.sdp_mem_read = { bytes: n3, hex: buf3.slice(0,n3).toString("hex") };',
  '} catch(e) { r.sdp_mem_read_err = e.message; }',

  // SUID scan with older busybox syntax
  'try {',
  '  var out = cp.execSync("find /usr/bin /bin /usr/sbin /sbin -perm +4000 -type f 2>/dev/null", {timeout:10000});',
  '  r.suid = out.toString().trim();',
  '} catch(e) {',
  '  try {',
  '    var out2 = cp.execSync("find / -perm +4000 -type f 2>/dev/null", {timeout:15000});',
  '    r.suid_root = out2.toString().trim();',
  '  } catch(e2) { r.suid_err = e2.message.slice(0,120); }',
  '}',

  // /proc/self/maps (first 3000 chars)
  'try { r.maps = fs.readFileSync("/proc/self/maps", "utf8").slice(0, 3000); } catch(e) { r.maps_err = e.message; }',

  // Check /proc/buddyinfo for physical memory info
  'try { r.buddyinfo = fs.readFileSync("/proc/buddyinfo", "utf8"); } catch(e) { r.buddyinfo_err = e.message; }',

  // smack label of tzmem
  'try { r.tzmem_smack = fs.readFileSync("/sys/class/misc/tzmem", "utf8"); } catch(e) { r.tzmem_smack_err = e.message; }',
  'try { r.tzmem_xattr = cp.execSync("getfattr -d /dev/tzmem 2>&1", {timeout:3000}).toString().trim(); } catch(e) { r.tzmem_xattr_err = e.message.slice(0,80); }',

  // uname + id
  'try { r.uname = cp.execSync("uname -a", {timeout:3000}).toString().trim(); } catch(e) {}',
  'try { r.id = cp.execSync("id", {timeout:3000}).toString().trim(); } catch(e) {}',

  'var out3 = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out3); } catch(e2) {}',
  'process.stdout.write(out3);'
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
