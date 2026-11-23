'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8186;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe97h.txt';
var PWN = '/tmp/pwn97h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Pre-create pwn file
  'try { fs.writeFileSync("' + PWN + '", "pre\\n"); r.pwn_ok = true; } catch(e) {}',

  // 2. Read interesting /tmp files
  'r.tmp_reads = {};',
  'var tmp_targets = ["testestest","sim_log.txt","fb_log","vrtInstallerStartFile.txt","save_booting_count","dotnet_error.442.2.log","dotnet_init_done.dat","AFTER_PRODUCTION","FLASH_8G","factory-ready","factory-init-ready","ugbridge_tmpdata.dat","preview-updater-blacklist.json"];',
  'tmp_targets.forEach(function(f) {',
  '  try { r.tmp_reads[f] = fs.readFileSync("/tmp/"+f,"utf8").trim().slice(0,300); } catch(e) { r.tmp_reads[f] = "ERR:"+e.message.slice(0,40); }',
  '});',

  // 3. GetChildItem(6, 0..30) - Deleted menu (95 children!) - first batch
  'r.deleted_children_0_30 = [];',
  'for (var i = 0; i < 31; i++) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","6",String(i)],{timeout:3000});',
  '    r.deleted_children_0_30.push({ idx: i, data: (o.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 4. GetChildItem(7, 0..7) - ADC/WB (8 children)
  'r.adc_wb_children = [];',
  'for (var j = 0; j < 8; j++) {',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","7",String(j)],{timeout:3000});',
  '    r.adc_wb_children.push({ idx: j, data: (o2.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 5. SaveLog sweep (modes 0..15) + /tmp monitoring after each
  'r.savelog_sweep = {};',
  'var tmp_before_sl = [];',
  'try { tmp_before_sl = fs.readdirSync("/tmp"); } catch(e) {}',
  'for (var sl = 0; sl <= 15; sl++) {',
  '  try {',
  '    var o_sl = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SaveLog",String(sl)],{timeout:8000});',
  '    var slout = (o_sl.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '    r.savelog_sweep["sl"+sl] = slout;',
  '    if (slout.indexOf("(0,)") > -1 || (slout.indexOf("(1,)") === -1 && slout.length > 5)) {',
  '      var tmp_after_sl = fs.readdirSync("/tmp");',
  '      var new_files_sl = tmp_after_sl.filter(function(f){ return tmp_before_sl.indexOf(f) < 0; });',
  '      if (new_files_sl.length > 0) r.savelog_sweep["sl"+sl+"_newfiles"] = new_files_sl;',
  '      tmp_before_sl = tmp_after_sl;',
  '    }',
  '  } catch(e) {}',
  '}',

  // 6. List /opt/media to understand USB structure
  'try {',
  '  r.opt_media_ls = fs.readdirSync("/opt/media");',
  '} catch(e) { r.opt_media_err = e.message.slice(0,60); }',
  'try {',
  '  r.opt_ls = fs.readdirSync("/opt");',
  '} catch(e) { r.opt_ls_err = e.message.slice(0,60); }',

  // 7. Pic_Data_USB (240804) with full dmesg capture
  'var dm_base = 0;',
  'try { dm_base = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n").length; } catch(e) {}',
  'try {',
  '  var o_pdu = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","240804","0"],{timeout:12000});',
  '  r.pic_data_usb_exec = (o_pdu.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',
  'try {',
  '  var dm_all = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.pic_data_dmesg = dm_all.slice(dm_base).join("\\n").slice(0,2000);',
  '  dm_base = dm_all.length;',
  '} catch(e) {}',

  // 8. SetParameter(10804, 2..5) + execute — different modes for TCON upgrade
  'r.tcon_setparam_modes = {};',
  'for (var tm = 2; tm <= 5; tm++) {',
  '  try {',
  '    var o_tsp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","10804",String(tm)],{timeout:3000});',
  '    var tsp_out = (o_tsp.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '    r.tcon_setparam_modes["m"+tm] = { set: tsp_out };',
  '    if (tsp_out === "((0,),)") {',
  '      var o_tex = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","10804","0"],{timeout:8000});',
  '      var texout = (o_tex.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '      r.tcon_setparam_modes["m"+tm].exec = texout;',
  '      var dm_new = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '      r.tcon_setparam_modes["m"+tm].dmesg = dm_new.slice(dm_base).join("\\n").slice(0,500);',
  '      dm_base = dm_new.length;',
  '    }',
  '  } catch(e) {}',
  '}',

  // 9. Executes on k7 ADC/WB children items (using formula: child 0 of k7 = 1*100+7 = 107)
  'r.adc_wb_execs = {};',
  'var adc_keys = [107,207,307,407,507,607,707,807];',
  'adc_keys.forEach(function(ak) {',
  '  try {',
  '    var o_ae = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(ak),"0"],{timeout:5000});',
  '    r.adc_wb_execs["k"+ak] = (o_ae.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '});',

  // 10. /tmp new files check
  'try {',
  '  var tmp_now = fs.readdirSync("/tmp");',
  '  r.tmp_new_in_v97 = tmp_now.filter(function(f){',
  '    return f.indexOf("pwn")>-1||f.indexOf("log")>-1||f.indexOf("dump")>-1||f.indexOf("save")>-1||f.indexOf("factory")>-1;',
  '  });',
  '} catch(e) {}',

  // 11. Final dmesg - filter for new events
  'try {',
  '  var o_dm2 = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm2 = (o_dm2.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_tail30 = dm2.slice(-30).join("\\n").slice(0,2000);',
  '} catch(e) {}',

  // 12. pwn check
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
