'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8167;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe79h.txt';
var PWN = '/tmp/pwn79h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. D-Bus: list all system bus service names
  'try {',
  '  var o = cp.spawnSync("/bin/sh", ["-c",',
  '    "gdbus call --system --dest org.freedesktop.DBus --object-path / --method org.freedesktop.DBus.ListNames 2>&1"',
  '  ], {timeout:8000});',
  '  r.dbus_names = (o.stdout||Buffer.from("")).toString().trim().slice(0,3000);',
  '} catch(e) { r.dbus_names_err = e.message.slice(0,100); }',

  // 2. D-Bus: list all session bus service names
  'try {',
  '  var o2 = cp.spawnSync("/bin/sh", ["-c",',
  '    "DBUS_SESSION_BUS_ADDRESS=$(cat /proc/$(pidof dbus-daemon | awk \\"{print $NF}\\")/environ 2>/dev/null | tr \'\\\\0\' \'\\\\n\' | grep DBUS_SESSION_BUS_ADDRESS | cut -d= -f2-) gdbus call --session --dest org.freedesktop.DBus --object-path / --method org.freedesktop.DBus.ListNames 2>&1"',
  '  ], {timeout:8000});',
  '  r.dbus_session_names = (o2.stdout||Buffer.from("")).toString().trim().slice(0,2000);',
  '} catch(e) { r.dbus_session_err = e.message.slice(0,100); }',

  // 3. Try to introspect RunningAppsService via system bus with various service names
  'var rasNames = [',
  '  "org.tizen.RunningAppsService",',
  '  "com.samsung.RunningAppsService",',
  '  "org.tizen.running_apps",',
  '  "com.native.RunningAppsServiceDBUS",',
  '  "org.tizen.tv.RunningAppsService",',
  '  "com.samsung.tv.RunningAppsService"',
  '];',
  'r.ras_dbus = {};',
  'rasNames.forEach(function(name) {',
  '  try {',
  '    var o3 = cp.spawnSync("/bin/sh", ["-c",',
  '      "gdbus introspect --system --dest " + name + " --object-path /com/native/RunningAppsServiceDBUS 2>&1"',
  '    ], {timeout:4000});',
  '    var out = (o3.stdout||Buffer.from("")).toString().trim().slice(0,500);',
  '    if (out && out.indexOf("Error") === -1 && out.length > 10) {',
  '      r.ras_dbus[name] = out;',
  '    } else {',
  '      r.ras_dbus[name] = out.slice(0,100);',
  '    }',
  '  } catch(e) { r.ras_dbus[name] = e.message.slice(0,60); }',
  '});',

  // 4. Check Smack label on wasdb
  'try {',
  '  var o4 = cp.spawnSync("/bin/sh", ["-c",',
  '    "ls -Z /opt/dbspace/.webappservice.db 2>&1 || getfattr --only-values -n security.SMACK64 /opt/dbspace/.webappservice.db 2>&1"',
  '  ], {timeout:3000});',
  '  r.wasdb_smack = (o4.stdout||Buffer.from("")).toString().trim();',
  '} catch(e) { r.wasdb_smack_err = e.message; }',

  // 5. Read wasdb schema (what tables it has)
  'try {',
  '  var o5 = cp.spawnSync("/bin/sh", ["-c",',
  '    "sqlite3 /tmp/wasdb_copy.db \\\".tables\\\" 2>&1; sqlite3 /tmp/wasdb_copy.db \\\".schema apps_info\\\" 2>&1"',
  '  ], {timeout:5000});',
  '  r.wasdb_schema = (o5.stdout||Buffer.from("")).toString().trim().slice(0,1000);',
  '} catch(e) { r.wasdb_schema_err = e.message; }',

  // 6. Find RunningAppsService process
  'try {',
  '  var o6 = cp.spawnSync("/bin/sh", ["-c",',
  '    "ps aux 2>/dev/null | grep -i running 2>&1"',
  '  ], {timeout:3000});',
  '  r.running_ps = (o6.stdout||Buffer.from("")).toString().trim().slice(0,500);',
  '} catch(e) { r.running_ps_err = e.message; }',

  // 7. Find all running user/system processes (non-kernel)
  'try {',
  '  var o7 = cp.spawnSync("/bin/sh", ["-c",',
  '    "ps aux 2>/dev/null | grep -v \'\\\\[\\' | head -40 2>&1"',
  '  ], {timeout:3000});',
  '  r.user_procs = (o7.stdout||Buffer.from("")).toString().trim().slice(0,3000);',
  '} catch(e) { r.user_procs_err = e.message; }',

  // 8. Check /opt/usr/home/owner/apps_rw/ write permission
  'try {',
  '  var s2 = fs.statSync("/opt/usr/home/owner/apps_rw");',
  '  r.apps_rw_stat = { mode: s2.mode.toString(8), uid: s2.uid, gid: s2.gid };',
  '} catch(e) { r.apps_rw_err = e.message; }',

  // 9. Try direct dbus-send on RunningAppsService
  'try {',
  '  var o8 = cp.spawnSync("/bin/sh", ["-c",',
  '    "dbus-send --system --print-reply --dest=org.tizen.RunningAppsService /com/native/RunningAppsServiceDBUS org.freedesktop.DBus.Introspectable.Introspect 2>&1"',
  '  ], {timeout:5000});',
  '  r.ras_introspect = (o8.stdout||Buffer.from("")).toString().trim().slice(0,1000);',
  '} catch(e) { r.ras_introspect_err = e.message.slice(0,60); }',

  // 10. Check if wasdb_copy valid test: copy to /tmp and test smack chattr
  'try {',
  '  var o9 = cp.spawnSync("/bin/sh", ["-c",',
  '    "/bin/chsmack -a System /tmp/wasdb_copy.db 2>&1; echo exit:$?"',
  '  ], {timeout:3000});',
  '  r.chsmack_test = (o9.stdout||Buffer.from("")).toString().trim();',
  '} catch(e) { r.chsmack_test_err = e.message; }',

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
