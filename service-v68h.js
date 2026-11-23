'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8156;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe68h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. Check /dev/ntksys (the MADBugs kernel R/W device)
  'try {',
  '  var st = fs.statSync("/dev/ntksys");',
  '  result.ntksys_stat = { mode: st.mode.toString(8), uid: st.uid, gid: st.gid, rdev: st.rdev };',
  '} catch(e) { result.ntksys_err = e.message; }',

  // Try to open it
  'try {',
  '  var fd = fs.openSync("/dev/ntksys", "r");',
  '  result.ntksys_open = "OK fd=" + fd;',
  '  fs.closeSync(fd);',
  '} catch(e) { result.ntksys_open_err = e.message; }',

  // 2. List /dev for ntk* devices
  'try {',
  '  var devs = fs.readdirSync("/dev");',
  '  result.dev_ntk = devs.filter(function(d){ return d.indexOf("ntk") !== -1 || d.indexOf("tzmem") !== -1 || d.indexOf("mem") !== -1 || d.indexOf("kmem") !== -1; });',
  '  result.dev_all = devs.join(",");',
  '} catch(e) { result.dev_list_err = e.message; }',

  // 3. /dev/tzmem ioctl probe — try ioctl(fd, 0, buf) and similar
  'try {',
  '  var tzmem_fd = fs.openSync("/dev/tzmem", "r+");',
  '  result.tzmem_fd = tzmem_fd;',
  '  // Can\'t do ioctl from JS directly — just confirm open
  fs.closeSync(tzmem_fd);',
  '} catch(e) { result.tzmem_open_err = e.message; }',

  // 4. Check /dev/mem, /dev/kmem
  'var mem_devs = ["/dev/mem", "/dev/kmem", "/dev/port"];',
  'result.mem_devs = {};',
  'mem_devs.forEach(function(d) {',
  '  try {',
  '    var st2 = fs.statSync(d);',
  '    result.mem_devs[d] = { mode: st2.mode.toString(8), uid: st2.uid, gid: st2.gid };',
  '  } catch(e) { result.mem_devs[d] = e.message; }',
  '});',

  // 5. SUID/SGID binary scan
  'try {',
  '  var suid = cp.execSync("find /usr/bin /usr/sbin /bin /sbin -perm /6000 -type f 2>/dev/null", {timeout:10000});',
  '  result.suid_bins = suid.toString().trim().split("\n");',
  '} catch(e) { result.suid_err = e.message.slice(0,100); }',

  // 6. Check if kernel has /proc/sysrq-trigger or other privileged files
  'var priv_files = ["/proc/sysrq-trigger", "/proc/kcore", "/sys/kernel/kexec_load_disabled"];',
  'result.priv_files = {};',
  'priv_files.forEach(function(f) {',
  '  try {',
  '    var st3 = fs.statSync(f);',
  '    result.priv_files[f] = { mode: st3.mode.toString(8), uid: st3.uid, gid: st3.gid };',
  '  } catch(e) { result.priv_files[f] = e.message; }',
  '});',

  // 7. /proc/self: check capabilities, securebits, NoNewPrivs
  'try {',
  '  result.proc_status = cp.execSync("grep -E \"Cap|Seccomp|NoNew\" /proc/self/status 2>/dev/null", {timeout:3000}).toString().trim();',
  '} catch(e) { result.proc_status_err = e.message; }',

  // 8. Kernel version and uname
  'try {',
  '  result.uname = cp.execSync("uname -a", {timeout:3000}).toString().trim();',
  '} catch(e) { result.uname_err = e.message; }',

  // 9. Check /proc/net/unix for interesting sockets
  'try {',
  '  var unixsock = cp.execSync("grep -E \'ntk|was|jack|auto|root|priv\' /proc/net/unix 2>/dev/null | head -20", {timeout:3000});',
  '  result.unix_sockets = unixsock.toString().trim();',
  '} catch(e) { result.unix_sockets_err = e.message; }',

  'var out = JSON.stringify(result, null, 2);',
  'try { require("fs").writeFileSync("' + PROBE_FILE + '", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 60000 }, function(err, stdout, stderr) {
    var result;
    if (err) {
      result = JSON.stringify({ exec_error: err.message.slice(0, 200), stderr: (stderr || '').slice(0, 300), stdout: stdout || '' });
    } else {
      result = stdout || '{}';
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

server.listen(PORT, '127.0.0.1', function() {
  runProbe(function(result) {
    try { fs.writeFileSync(PROBE_FILE, result); } catch(e) {}
  });
});

server.on('error', function(e) {
  try { fs.writeFileSync(PROBE_FILE, JSON.stringify({ server_err: e.message })); } catch(e2) {}
});

setInterval(function() {}, 60000);
