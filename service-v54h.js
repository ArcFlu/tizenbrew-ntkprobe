'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8142;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe54h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',
  'try { result.aslr = fs.readFileSync("/proc/sys/kernel/randomize_va_space","utf8").trim(); } catch(e) {}',
  'try { result.proc_self_status = fs.readFileSync("/proc/self/status","utf8").trim(); } catch(e) {}',
  'try { result.dmesg = cp.execSync("dmesg 2>&1 | head -60", {timeout:5000}).toString().trim(); } catch(e) { result.dmesg_err = e.message; }',
  'try {',
  '  var wb = fs.readFileSync("/usr/bin/wasutility");',
  '  result.wasutility_size = wb.length;',
  '  result.wasutility_elf_type = wb[16] | (wb[17]<<8);',
  '  result.wasutility_entry = "0x"+(((wb[24])|(wb[25]<<8)|(wb[26]<<16)|(wb[27]<<24))>>>0).toString(16);',
  '  var strs = []; var cur = "";',
  '  for (var i = 0; i < wb.length && strs.length < 80; i++) {',
  '    var c = wb[i];',
  '    if (c >= 0x20 && c <= 0x7e) { cur += String.fromCharCode(c); }',
  '    else { if (cur.length >= 5) strs.push(cur); cur = ""; }',
  '  }',
  '  result.wasutility_strings = strs;',
  '  result.wasutility_has_canary = (wb.toString("binary").indexOf("__stack_chk_fail") >= 0);',
  '  result.wasutility_has_fortify = (wb.toString("binary").indexOf("__printf_chk") >= 0);',
  '} catch(e) { result.wasutility_err = e.message; }',
  'try {',
  '  var rb = fs.readFileSync("/usr/bin/RunningAppsService");',
  '  result.rnas_size = rb.length;',
  '  result.rnas_elf_type = rb[16] | (rb[17]<<8);',
  '  result.rnas_entry = "0x"+(((rb[24])|(rb[25]<<8)|(rb[26]<<16)|(rb[27]<<24))>>>0).toString(16);',
  '  var strs2 = []; var cur2 = "";',
  '  for (var j = 0; j < rb.length && strs2.length < 80; j++) {',
  '    var c2 = rb[j];',
  '    if (c2 >= 0x20 && c2 <= 0x7e) { cur2 += String.fromCharCode(c2); }',
  '    else { if (cur2.length >= 5) strs2.push(cur2); cur2 = ""; }',
  '  }',
  '  result.rnas_strings = strs2;',
  '  result.rnas_has_canary = (rb.toString("binary").indexOf("__stack_chk_fail") >= 0);',
  '} catch(e) { result.rnas_err = e.message; }',
  'try { var wo = cp.execSync("/usr/bin/wasutility 2>&1", {timeout:5000}); result.wasutility_run = wo.toString(); } catch(e) { result.wasutility_run = e.message + "\\nstdout=" + (e.stdout ? e.stdout.toString() : ""); }',
  'try { var ro = cp.execSync("/usr/bin/RunningAppsService 2>&1", {timeout:2000}); result.rnas_run = ro.toString(); } catch(e) { result.rnas_run = e.message + "\\nstdout=" + (e.stdout ? e.stdout.toString() : ""); }',
  'try { result.unix_sockets = cp.execSync("ls -la /tmp/*.sock /run/*.sock /var/run/*.sock 2>/dev/null | head -20", {timeout:3000}).toString().trim(); } catch(e) { result.unix_sockets_err = e.message; }',
  'try { var sysrq = fs.statSync("/proc/sysrq-trigger"); result.sysrq_mode = "0"+(sysrq.mode&0xFFF).toString(8); } catch(e) {}',
  'try { fs.writeFileSync("/opt/data/tbtest.txt", "test"); fs.unlinkSync("/opt/data/tbtest.txt"); result.opt_data_writable = true; } catch(e) { result.opt_data_writable = false; }',
  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'try { fs2.writeFileSync("/home/owner/share/tmp/sdk_tools/tbprobe54h.txt", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 40000 }, function(err, stdout, stderr) {
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
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe54h.txt', result); } catch(e) {}
  });
});
