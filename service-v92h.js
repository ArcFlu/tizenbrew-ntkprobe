'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8181;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe92h.txt';
var PWN = '/tmp/pwn92h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. GetChildItem(3, 0..31) - Debug menu children (32 items)
  'r.debug_children = [];',
  'for (var i = 0; i < 32; i++) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","3",String(i)],{timeout:4000});',
  '    var out = (o.stdout||new Buffer(0)).toString().trim();',
  '    if (out && out.indexOf("(1,)") === -1 && out !== "") {',
  '      r.debug_children.push({ idx: i, data: out.slice(0,200) });',
  '    } else {',
  '      r.debug_children.push({ idx: i, empty: true });',
  '    }',
  '  } catch(e) { r.debug_children.push({ idx: i, err: e.message.slice(0,40) }); }',
  '}',

  // 2. GetChildItem(4, 0..10) - SVC menu children (11 items)
  'r.svc_children = [];',
  'for (var j = 0; j < 11; j++) {',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","4",String(j)],{timeout:4000});',
  '    var out2 = (o2.stdout||new Buffer(0)).toString().trim();',
  '    r.svc_children.push({ idx: j, data: out2.slice(0,200) });',
  '  } catch(e) { r.svc_children.push({ idx: j, err: e.message.slice(0,40) }); }',
  '}',

  // 3. GetChildItem(5, 0..76) - Hidden menu children (77 items) - batched
  'r.hidden_children = [];',
  'for (var k = 0; k < 77; k++) {',
  '  try {',
  '    var o3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","5",String(k)],{timeout:3000});',
  '    var out3 = (o3.stdout||new Buffer(0)).toString().trim();',
  '    if (out3 && out3.indexOf("(1,)") === -1) {',
  '      r.hidden_children.push({ idx: k, data: out3.slice(0,200) });',
  '    }',
  '  } catch(e) {}',
  '}',

  // 4. GetOptionStringData(0..6) - read current option string values for all small keys
  'r.opt_strings = {};',
  'for (var os = 0; os <= 6; os++) {',
  '  try {',
  '    var o_os = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData",String(os)],{timeout:4000});',
  '    r.opt_strings["k"+os] = (o_os.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 5. Try SetOptionStringData(3, "1", 1) to toggle Debug flag
  'try {',
  '  var o_s1 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","3","1","1"],{timeout:5000});',
  '  r.set_debug_1 = (o_s1.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_debug_1_err = e.message.slice(0,60); }',
  'try {',
  '  var o_gd = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","3"],{timeout:4000});',
  '  r.get_debug_after = (o_gd.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',

  // 6. kfactory 40-byte write - try command patterns, then read back
  // Struct guess: [type(4), id(4), cmd(4), p1(4), p2(4), p3(4), p4(4), p5(4), len(4), result(4)]
  // Try type=0xFE01 (factory command), id=3 (Debug), cmd=0
  'var payload_exec = new Buffer(40);',
  'payload_exec.fill(0);',
  'payload_exec.writeUInt32LE(0x01, 0);',
  'payload_exec.writeUInt32LE(3, 4);',
  'payload_exec.writeUInt32LE(0, 8);',
  'try {',
  '  var kfd_w = fs.openSync("/dev/kfactory", "w");',
  '  var kn_w = fs.writeSync(kfd_w, payload_exec, 0, 40);',
  '  fs.closeSync(kfd_w);',
  '  r.kfac_write_debug = { written: kn_w };',
  '} catch(e) { r.kfac_write_debug_err = e.message.slice(0,60); }',

  // 7. Wait 100ms then read from kfactory to see if kfactoryd wrote a response
  'try {',
  '  var kfd_r = fs.openSync("/dev/kfactory", "r");',
  '  var kbuf = new Buffer(40);',
  '  kbuf.fill(0);',
  '  var kn_r = fs.readSync(kfd_r, kbuf, 0, 40, 0);',
  '  fs.closeSync(kfd_r);',
  '  r.kfac_read_after = { n: kn_r, hex: kbuf.slice(0,kn_r).toString("hex") };',
  '} catch(e) { r.kfac_read_after_err = e.message.slice(0,60); }',

  // 8. Fresh dmesg after everything
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  var last50 = dm.slice(-50);',
  '  r.dmesg_last50 = last50.join("\\n").slice(0,3000);',
  '} catch(e) {}',

  // 9. pwn check
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
