'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8160;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe72h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // Stat all interesting devices
  'var devs = ["/dev/RAW-mmap","/dev/kfactory","/dev/ocm","/dev/socite","/dev/ssdev",',
  '  "/dev/sdp_ddrbus","/dev/sdp_kade","/dev/sdpfrc","/dev/lwipc","/dev/pwsv_mode",',
  '  "/dev/fuse","/dev/cas_event","/dev/bptime","/dev/eeprom","/dev/smart_deadlock"];',
  'r.dev_stats = {};',
  'devs.forEach(function(d) {',
  '  try {',
  '    var s = fs.statSync(d);',
  '    r.dev_stats[d] = { mode: s.mode.toString(8), uid: s.uid, gid: s.gid, rdev: s.rdev };',
  '  } catch(e) { r.dev_stats[d] = e.message; }',
  '});',

  // Try open/read RAW-mmap
  'try {',
  '  var fd = fs.openSync("/dev/RAW-mmap", fs.constants ? fs.constants.O_RDWR : 2);',
  '  r.rawmmap_open = "ok fd=" + fd;',
  '  var buf = new Buffer(64);',
  '  try { var n = fs.readSync(fd, buf, 0, 64, 0); r.rawmmap_read = { n: n, hex: buf.slice(0,n).toString("hex") }; } catch(e) { r.rawmmap_read_err = e.message; }',
  '  fs.closeSync(fd);',
  '} catch(e) { r.rawmmap_open_err = e.message; }',

  // /proc/iomem — physical memory map
  'try { r.iomem = fs.readFileSync("/proc/iomem", "utf8"); } catch(e) { r.iomem_err = e.message; }',

  // /proc/mtd — flash partitions (useful for understanding layout)
  'try { r.mtd = fs.readFileSync("/proc/mtd", "utf8"); } catch(e) { r.mtd_err = e.message; }',

  // Check for compilers/build tools
  'var tools = ["gcc","cc","arm-linux-gnueabi-gcc","clang","as","ld","python","python3","perl","lua"];',
  'r.tools = {};',
  'tools.forEach(function(t) {',
  '  try {',
  '    var o = cp.execSync("which " + t + " 2>/dev/null", {timeout:2000});',
  '    r.tools[t] = o.toString().trim();',
  '  } catch(e) { r.tools[t] = "not found"; }',
  '});',

  // SUID via ls stat approach
  'try {',
  '  var bins = cp.execSync("ls -la /bin /usr/bin 2>/dev/null | grep -E \'..s\'", {timeout:5000});',
  '  r.suid_ls = bins.toString().trim();',
  '} catch(e) { r.suid_ls_err = e.message.slice(0,100); }',

  // Check writable paths
  'var paths = ["/tmp","/var/tmp","/run/user/5001","/home/owner/share/tmp/sdk_tools","/dev/shm"];',
  'r.writable = {};',
  'paths.forEach(function(p) {',
  '  try {',
  '    fs.writeFileSync(p + "/.probe_test", "x");',
  '    fs.unlinkSync(p + "/.probe_test");',
  '    r.writable[p] = true;',
  '  } catch(e) { r.writable[p] = e.message.slice(0,50); }',
  '});',

  // /proc/zoneinfo summary
  'try {',
  '  var zi = cp.execSync("grep -E .+managed.+ /proc/zoneinfo 2>/dev/null", {timeout:3000});',
  '  r.zoneinfo_managed = zi.toString().trim();',
  '} catch(e) { r.zoneinfo_err = e.message.slice(0,80); }',

  // smack label of RAW-mmap and sdp_mem
  'try { r.rawmmap_smack = cp.execSync("cat /proc/filesystems 2>/dev/null | head -20", {timeout:2000}).toString().trim(); } catch(e) {}',

  // Check if tzmem/sdp_mem have sysfs entries
  'try { r.misc_devices = cp.execSync("cat /proc/misc 2>/dev/null", {timeout:2000}).toString().trim(); } catch(e) { r.misc_devices_err = e.message.slice(0,80); }',

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
