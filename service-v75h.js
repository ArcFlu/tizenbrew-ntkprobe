'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8163;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe75h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Read wasutility binary around the patch offset 0x7e4b
  'try {',
  '  var buf = fs.readFileSync("/usr/bin/wasutility");',
  '  r.was_size = buf.length;',
  '  var off = 0x7e4b;',
  '  r.was_patch_bytes = buf.slice(off - 32, off + 32).toString("hex");',
  '  r.was_patch_offset = "0x" + off.toString(16);',
  '  // Also read the first 256 bytes for ELF header / magic',
  '  r.was_header = buf.slice(0, 64).toString("hex");',
  '} catch(e) { r.was_read_err = e.message; }',

  // 2. strings from wasutility (look for -e, shell, cmd, exec hints)
  'try {',
  '  var o = cp.spawnSync("strings", ["/usr/bin/wasutility"], {timeout:8000});',
  '  var strs = o.stdout ? o.stdout.toString() : "";',
  '  // filter for interesting strings',
  '  var lines = strs.split("\\n");',
  '  r.was_strings_e = lines.filter(function(l){ return l.indexOf("-e") > -1 || l.indexOf("exec") > -1 || l.indexOf("shell") > -1 || l.indexOf("cmd") > -1 || l.indexOf("root") > -1 || l.indexOf("uid") > -1; }).slice(0,30);',
  '  r.was_strings_count = lines.length;',
  '} catch(e) { r.was_strings_err = e.message.slice(0,80); }',

  // 3. wasutility with -e "id" but via sh -c (maybe it needs shell interpretation?)
  'try {',
  '  var o2 = cp.spawnSync("/bin/sh", ["-c", "/usr/bin/wasutility -e id; echo exitcode:$?"], {timeout:5000});',
  '  r.was_sh_e = {',
  '    out: ((o2.stdout||Buffer.from("")).toString() + (o2.stderr||Buffer.from("")).toString()).trim().slice(0,300)',
  '  };',
  '} catch(e) { r.was_sh_e_err = e.message.slice(0,100); }',

  // 4. Test wasutility with various flags to discover CLI
  'var flags = [["-v"],["-V"],["--version"],["--list"],["-l"],["-s"],["--debug"],["--dry-run"],["-e","ls /tmp"],["exec","id"]];',
  'r.was_flags = {};',
  'flags.forEach(function(f) {',
  '  try {',
  '    var o3 = cp.spawnSync("/usr/bin/wasutility", f, {timeout:3000});',
  '    r.was_flags[f.join(" ")] = {',
  '      out: ((o3.stdout||Buffer.from("")).toString() + (o3.stderr||Buffer.from("")).toString()).trim().slice(0,150),',
  '      status: o3.status',
  '    };',
  '  } catch(e) { r.was_flags[f.join(" ")] = e.message.slice(0,60); }',
  '});',

  // 5. OCM device: try read at different offsets to find valid data
  'try {',
  '  var fd = fs.openSync("/dev/ocm", 2);',  // O_RDWR=2
  '  r.ocm_open_rw = "ok";',
  '  var buf3 = new Buffer(16);',
  '  try { r.ocm_read_0 = { n: fs.readSync(fd, buf3, 0, 16, 0) }; } catch(e) { r.ocm_read_0_err = e.code; }',
  '  fs.closeSync(fd);',
  '} catch(e) { r.ocm_open_rw_err = e.code; }',

  // 6. lwipc: try writing something and see response
  'try {',
  '  var fd4 = fs.openSync("/dev/lwipc", 2);',
  '  r.lwipc_open = "ok";',
  '  // Try a simple write',
  '  var tbuf = new Buffer(8);',
  '  tbuf.fill(0);',
  '  try { var wn = fs.writeSync(fd4, tbuf, 0, 8); r.lwipc_write = wn; } catch(e) { r.lwipc_write_err = e.message.slice(0,60); }',
  '  fs.closeSync(fd4);',
  '} catch(e) { r.lwipc_open_err = e.code; }',

  // 7. /proc/self/maps for wasutility child (from ps - check PIDs)
  // Check if we can read maps of other processes
  'try {',
  '  var pidlist = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  r.pid_count = pidlist.length;',
  '  // Try to find root process maps',
  '  var root_pids = [];',
  '  for (var i = 0; i < pidlist.length && root_pids.length < 3; i++) {',
  '    try {',
  '      var st = fs.readFileSync("/proc/" + pidlist[i] + "/status", "utf8");',
  '      if (st.indexOf("\\nUid:\\t0\\t") > -1) root_pids.push(pidlist[i]);',
  '    } catch(e) {}',
  '  }',
  '  r.root_pids_sample = root_pids.slice(0,5);',
  '} catch(e) { r.proc_read_err = e.message; }',

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
