'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8147;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe59h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. Find automation-service owner: scan /proc/*/cmdline for 'automation'
  'try {',
  '  var procs = fs.readdirSync("/proc").filter(function(d){return /^\\d+$/.test(d);});',
  '  var hits = [];',
  '  procs.forEach(function(pid){',
  '    try{',
  '      var cmd = fs.readFileSync("/proc/"+pid+"/cmdline","utf8").replace(/\\0/g," ").trim();',
  '      if(cmd.toLowerCase().indexOf("automation")!==-1 || cmd.indexOf("auto")!==-1){',
  '        var status = fs.readFileSync("/proc/"+pid+"/status","utf8");',
  '        var uid = (status.match(/^Uid:\\s*(\\S+)/m)||[])[1]||"?";',
  '        var smack = "";',
  '        try{smack=fs.readFileSync("/proc/"+pid+"/attr/current","utf8").trim();}catch(e){}',
  '        hits.push({pid:pid, cmd:cmd, uid:uid, smack:smack});',
  '      }',
  '    }catch(e){}',
  '  });',
  '  result.automation_procs = hits;',
  '} catch(e) { result.automation_procs_err = e.message; }',

  // Also find all privileged (uid=0) processes for reference
  'try {',
  '  var root_procs = [];',
  '  var procs2 = fs.readdirSync("/proc").filter(function(d){return /^\\d+$/.test(d);});',
  '  procs2.forEach(function(pid){',
  '    try{',
  '      var status = fs.readFileSync("/proc/"+pid+"/status","utf8");',
  '      var uid = (status.match(/^Uid:\\s*(\\S+)/m)||[])[1]||"";',
  '      if(uid==="0"||uid.startsWith("0\\t")){',
  '        var cmd = fs.readFileSync("/proc/"+pid+"/cmdline","utf8").replace(/\\0/g," ").trim().slice(0,80);',
  '        root_procs.push({pid:pid, cmd:cmd});',
  '      }',
  '    }catch(e){}',
  '  });',
  '  result.root_procs = root_procs;',
  '} catch(e) { result.root_procs_err = e.message; }',

  // 2. /dev/ntksys probe
  'try {',
  '  var nfd = fs.openSync("/dev/ntksys","r+");',
  '  result.ntksys_fd = nfd;',
  '  fs.closeSync(nfd);',
  '} catch(e) { result.ntksys_err = e.code+":"+e.message; }',

  // 3. ExecuteCommand via dbus-send — try data0 values 0..4
  'result.execute_cmd = {};',
  'for(var i=0; i<=4; i++) {',
  '  (function(val){',
  '    try {',
  '      var r = cp.execSync(',
  '        "dbus-send --system --dest=org.tizen.tv.automation-service --type=method_call --print-reply /TIFacAutoObj org.tizen.tv.automation-service.TIFacAutoObj.ExecuteCommand int32:" + val + " int32:0 2>&1",',
  '        {timeout:5000}',
  '      );',
  '      result.execute_cmd["val"+val] = r.toString().slice(0,500);',
  '    } catch(e) {',
  '      result.execute_cmd["val"+val+"_err"] = e.message.slice(0,200);',
  '    }',
  '  })(i);',
  '}',

  // ExecuteCommand with data0=100,200 (might be app-launch or cmd opcodes)
  'try {',
  '  var r2 = cp.execSync(',
  '    "dbus-send --system --dest=org.tizen.tv.automation-service --type=method_call --print-reply /TIFacAutoObj org.tizen.tv.automation-service.TIFacAutoObj.ExecuteCommand int32:100 int32:0 2>&1",',
  '    {timeout:5000}',
  '  );',
  '  result.execute_cmd_100 = r2.toString().slice(0,500);',
  '} catch(e) { result.execute_cmd_100_err = e.message.slice(0,200); }',

  // 4. ExecuteCommandWithData — try with a small byte payload (data0=1, len=4, data=[0x69,0x64,0x0a,0x00] = "id\n\0")
  'try {',
  '  var r3 = cp.execSync(',
  '    "dbus-send --system --dest=org.tizen.tv.automation-service --type=method_call --print-reply /TIFacAutoObj org.tizen.tv.automation-service.TIFacAutoObj.ExecuteCommandWithData int32:1 int32:0 array:byte:0x69,0x64,0x0a,0x00 int32:4 2>&1",',
  '    {timeout:5000}',
  '  );',
  '  result.execute_with_data = r3.toString().slice(0,500);',
  '} catch(e) { result.execute_with_data_err = e.message.slice(0,200); }',

  // 5. Full interface list from TIFacAutoObj (deeper introspect)
  'try {',
  '  var r4 = cp.execSync(',
  '    "dbus-send --system --dest=org.tizen.tv.automation-service --type=method_call --print-reply /TIFacAutoObj org.freedesktop.DBus.Introspectable.Introspect 2>&1",',
  '    {timeout:5000}',
  '  );',
  '  result.tifac_introspect = r4.toString().slice(0,4000);',
  '} catch(e) { result.tifac_introspect_err = e.message.slice(0,200); }',

  // 6. Check tzmem device info (stat for major/minor, try ioctl number guessing via /proc/net/unix)
  'try { result.tzmem_stat = JSON.stringify(fs.statSync("/dev/tzmem")); } catch(e) {}',
  'try { result.ntksys_stat = JSON.stringify(fs.statSync("/dev/ntksys")); } catch(e) { result.ntksys_stat_err = e.message; }',

  // 7. Check /dev/misc for interesting devices
  'try {',
  '  var r5 = cp.execSync("ls -la /dev/ 2>&1 | grep -v ^total | head -60", {timeout:3000});',
  '  result.dev_ls = r5.toString();',
  '} catch(e) { result.dev_ls_err = e.message; }',

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
