'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8148;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe60h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. D-Bus GetConnectionUnixUser for all known services
  'var services = [',
  '  "org.tizen.tv.automation-service",',
  '  "comss.server",',
  '  "com.samsung.tizen.ssm",',
  '  "com.jackpack.migration",',
  '  "org.freedesktop.DBus"',
  '];',
  'result.dbus_uids = {};',
  'services.forEach(function(svc) {',
  '  try {',
  '    var r = cp.execSync(',
  '      "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixUser string:" + svc + " 2>&1",',
  '      {timeout:4000}',
  '    );',
  '    result.dbus_uids[svc] = r.toString().trim();',
  '  } catch(e) { result.dbus_uids[svc+"_err"] = e.message.slice(0,100); }',
  '  try {',
  '    var r2 = cp.execSync(',
  '      "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID string:" + svc + " 2>&1",',
  '      {timeout:4000}',
  '    );',
  '    result.dbus_uids[svc+"_pid"] = r2.toString().trim();',
  '  } catch(e) { result.dbus_uids[svc+"_pid_err"] = e.message.slice(0,100); }',
  '});',

  // 2. kallsyms: search for tzmem, tzdev, tz_ kernel symbols
  'try {',
  '  var ks = fs.readFileSync("/proc/kallsyms","utf8");',
  '  var tzlines = ks.split("\\n").filter(function(l){',
  '    return l.match(/tzmem|tzdev|tz_|TZ_|TZMEM|ntksys|ntkhdma/i);',
  '  '+'});',
  '  result.kallsyms_tz = tzlines.slice(0,50);',
  '} catch(e) { result.kallsyms_err = e.message; }',

  // 3. wasutility DB paths — find what SQLite databases it accesses
  'try {',
  '  var r3 = cp.execSync("find /opt/dbspace /usr/dbspace /opt/usr/dbspace -name \'*.db\' 2>/dev/null | head -30", {timeout:5000});',
  '  result.db_files = r3.toString().trim();',
  '} catch(e) { result.db_files_err = e.message; }',

  // 4. Read wasutility binary strings related to SQL/DB
  'try {',
  '  var wb = fs.readFileSync("/usr/bin/wasutility");',
  '  var ws = wb.toString("latin1");',
  '  var sqls = [];',
  '  var idx = 0;',
  '  while(idx < ws.length) {',
  '    var end = ws.indexOf("\\0", idx);',
  '    if(end<0) break;',
  '    var s = ws.slice(idx, end);',
  '    if(s.length > 8 && (s.match(/SELECT|INSERT|UPDATE|sqlite|dbspace|\\.db$/i) || s.match(/^\\/opt\\/|^\\/usr\\//))){',
  '      sqls.push(s);',
  '    }',
  '    idx = end+1;',
  '  }',
  '  result.wasutility_strings = sqls.slice(0,40);',
  '} catch(e) { result.wasutility_strings_err = e.message; }',

  // 5. Find world-writable files with System Smack label (need xattr check)
  // Check key directories for writable System-labeled files
  'try {',
  '  var r4 = cp.execSync("find /run /tmp /var/tmp -maxdepth 3 -writable -type f 2>/dev/null | head -20", {timeout:5000});',
  '  result.writable_files = r4.toString().trim();',
  '} catch(e) { result.writable_files_err = e.message; }',

  // 6. Full list of D-Bus services on system bus with their UIDs
  'try {',
  '  var allnames = cp.execSync("dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>&1", {timeout:5000});',
  '  result.dbus_names = allnames.toString().slice(0,3000);',
  '} catch(e) { result.dbus_names_err = e.message; }',

  // 7. Check /proc/self/status for capabilities
  'try { result.proc_status = fs.readFileSync("/proc/self/status","utf8").split("\\n").filter(function(l){return l.match(/Cap|Uid|Gid/i);}); } catch(e) {}',

  // 8. Check kptr_restrict and dmesg access
  'try { result.kptr_restrict = fs.readFileSync("/proc/sys/kernel/kptr_restrict","utf8").trim(); } catch(e) {}',
  'try {',
  '  var dm = cp.execSync("dmesg 2>&1 | grep -i tzmem | head -10", {timeout:3000});',
  '  result.dmesg_tzmem = dm.toString();',
  '} catch(e) { result.dmesg_tzmem_err = e.message; }',

  'var out = JSON.stringify(result, null, 2);',
  'try { require("fs").writeFileSync("' + PROBE_FILE + '", out); } catch(e) {}',
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
    try { fs.writeFileSync(PROBE_FILE, result); } catch(e) {}
  });
});
