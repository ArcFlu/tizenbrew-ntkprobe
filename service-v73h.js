'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8161;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe73h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // SUID scan via JS stat (bit 0x800 = setuid, 0x400 = setgid)
  'r.suid = [];',
  'r.sgid = [];',
  'var sdirs = ["/usr/bin","/bin","/usr/sbin","/sbin"];',
  'sdirs.forEach(function(d) {',
  '  try {',
  '    fs.readdirSync(d).forEach(function(f) {',
  '      try {',
  '        var s = fs.statSync(d + "/" + f);',
  '        if (s.mode & 0x800) r.suid.push(d + "/" + f + " uid=" + s.uid + " mode=" + s.mode.toString(8));',
  '        if (s.mode & 0x400) r.sgid.push(d + "/" + f + " gid=" + s.gid + " mode=" + s.mode.toString(8));',
  '      } catch(e) {}',
  '    });',
  '  } catch(e) { r[d + "_err"] = e.message; }',
  '});',

  // TrustZone and misc device stats
  'var tzdevs = ["/dev/tzdev","/dev/tzdev_invoke","/dev/tzrsrc","/dev/tzlog","/dev/lwipc","/dev/cas_event","/dev/kfactory","/dev/ocm","/dev/socite"];',
  'r.tz_stats = {};',
  'tzdevs.forEach(function(d) {',
  '  try {',
  '    var s = fs.statSync(d);',
  '    r.tz_stats[d] = { mode: s.mode.toString(8), uid: s.uid, gid: s.gid, rdev: s.rdev };',
  '  } catch(e) { r.tz_stats[d] = e.message; }',
  '});',

  // Try opening tz devices (O_RDONLY = 0)
  'r.tz_open = {};',
  'tzdevs.forEach(function(d) {',
  '  try {',
  '    var fd = fs.openSync(d, 0);',
  '    var buf = new Buffer(16);',
  '    var n = -1;',
  '    try { n = fs.readSync(fd, buf, 0, 16, 0); } catch(re) { n = "read_err:" + re.code; }',
  '    fs.closeSync(fd);',
  '    r.tz_open[d] = { opened: true, read_result: n };',
  '  } catch(e) { r.tz_open[d] = "open_err:" + e.code; }',
  '});',

  // Full iomem
  'try { r.iomem = fs.readFileSync("/proc/iomem", "utf8"); } catch(e) { r.iomem_err = e.message; }',

  // Running processes (ps)
  'try {',
  '  var ps = cp.execSync("ps aux 2>/dev/null | head -60", {timeout:5000});',
  '  r.ps = ps.toString().trim();',
  '} catch(e) { r.ps_err = e.message.slice(0,80); }',

  // Check /run/user/5001 for execute permission and mount flags
  'try { r.run_stat = JSON.stringify(fs.statSync("/run/user/5001")); } catch(e) { r.run_stat_err = e.message; }',
  'try {',
  '  var mounts = fs.readFileSync("/proc/mounts", "utf8");',
  '  r.run_mount = mounts.split("\\n").filter(function(l){ return l.indexOf("/run") > -1; }).join("\\n");',
  '} catch(e) { r.mounts_err = e.message; }',

  // Check smack_access for key paths (can we write to system dirs?)
  'try { r.smack_load = fs.readFileSync("/sys/fs/smackfs/load", "utf8").slice(0,500); } catch(e) { r.smack_load_err = e.code; }',

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
