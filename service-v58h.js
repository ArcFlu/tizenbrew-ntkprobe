'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8146;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe58h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // tzmem read - fixed for Node 4.x (new Buffer instead of Buffer.alloc)
  'try {',
  '  var fd = fs.openSync("/dev/tzmem", "r+");',
  '  result.tzmem_fd = fd;',
  '  var tbuf = new Buffer(256);',
  '  tbuf.fill(0);',
  '  try {',
  '    var nr = fs.readSync(fd, tbuf, 0, 256, 0);',
  '    result.tzmem_read_bytes = nr;',
  '    result.tzmem_read_hex = tbuf.slice(0, nr).toString("hex");',
  '  } catch(e2) { result.tzmem_read_err = e2.message; }',
  '  try {',
  '    var wbuf = new Buffer(4); wbuf.writeUInt32LE(0xdeadbeef, 0);',
  '    var nw = fs.writeSync(fd, wbuf, 0, 4, 0);',
  '    result.tzmem_write_ok = nw;',
  '  } catch(e3) { result.tzmem_write_err = e3.message; }',
  '  fs.closeSync(fd);',
  '} catch(e) { result.tzmem_open_err = e.message; }',

  // Check ELF header of our compiled binary
  'try {',
  '  var eb = fs.readFileSync("/run/user/5001/tzmem_probe").slice(0, 64);',
  '  result.elf_magic = eb.slice(0,4).toString("hex");',
  '  result.elf_class = eb[4];',
  '  result.elf_data = eb[5];',
  '  result.elf_type = eb[16]|(eb[17]<<8);',
  '  result.elf_machine = eb[18]|(eb[19]<<8);',
  '  result.elf_flags = (eb[36]|(eb[37]<<8)|(eb[38]<<16)|(eb[39]<<24))>>>0;',
  '} catch(e) { result.elf_err = e.message; }',

  // Search Smack rules for our label
  'try {',
  '  var allRules = fs.readFileSync("/sys/fs/smackfs/load","utf8");',
  '  var myRules = allRules.split("\\n").filter(function(l){return l.indexOf("xvvl3S1bvH")>=0;});',
  '  result.smack_my_rules_load = myRules;',
  '  result.smack_total_rules = allRules.split("\\n").length;',
  '} catch(e) { result.smack_my_rules_err = e.message; }',
  'try {',
  '  var allRules2 = fs.readFileSync("/sys/fs/smackfs/load2","utf8");',
  '  var myRules2 = allRules2.split("\\n").filter(function(l){return l.indexOf("xvvl3S1bvH")>=0;});',
  '  result.smack_my_rules_load2 = myRules2;',
  '} catch(e) { result.smack_my_rules2_err = e.message; }',

  // D-Bus introspect sub-paths
  'var paths = [',
  '  ["org.tizen.tv.automation-service", "/TIFacAutoObj"],',
  '  ["comss.server", "/comss"],',
  '  ["com.samsung.tizen.ssm", "/com"],',
  '  ["com.samsung.tizen.ssm", "/viola"],',
  '  ["com.jackpack.migration", "/com"]',
  '];',
  'result.dbus_subpaths = {};',
  'paths.forEach(function(p) {',
  '  var key = p[0]+p[1];',
  '  try {',
  '    var r = cp.execSync("dbus-send --system --print-reply --dest=" + p[0] + " " + p[1] + " org.freedesktop.DBus.Introspectable.Introspect 2>&1", {timeout:4000});',
  '    result.dbus_subpaths[key] = r.toString().slice(0,2500);',
  '  } catch(e) {',
  '    result.dbus_subpaths[key] = "err:" + e.message.slice(0,100);',
  '  }',
  '});',

  // execFileSync with error code for diagnosis
  'try {',
  '  var r2 = cp.execFileSync("/run/user/5001/tzmem_probe", [], {timeout:3000});',
  '  result.tzmem_execfile_ok = r2.toString();',
  '} catch(e) {',
  '  result.tzmem_execfile_err2 = (e.code || "") + " " + e.message.slice(0,200);',
  '}',

  // Check Smack self label
  'try { result.smack_self = fs.readFileSync("/proc/self/attr/current","utf8").trim(); } catch(e) {}',

  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'try { fs2.writeFileSync("' + PROBE_FILE + '", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 60000 }, function(err, stdout, stderr) {
    var result;
    if (err) {
      result = JSON.stringify({ exec_error: err.message, stderr: stderr, stdout: stdout || '' });
    } else {
      result = stdout || '(empty)';
    }
    cb(result);
  });
}

var server = http.createServer(function(req, res) {
  runProbe(function(result) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(result);
  });
});

server.listen(PORT, function() {
  runProbe(function(result) {
    try { fs.writeFileSync(PROBE_FILE, result); } catch(e) {}
  });
});
