'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8141;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe53h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',
  'try { result.kernel = fs.readFileSync("/proc/version", "utf8").trim(); } catch(e) { result.kernel_err = e.message; }',
  'try { var ks = fs.readFileSync("/proc/kallsyms", "utf8"); result.kallsyms_readable = true; result.kallsyms_len = ks.length; var lines = ks.split("\\n").slice(0,30); result.kallsyms_head = lines; } catch(e) { result.kallsyms_readable = false; result.kallsyms_err = e.message; }',
  'var devInterest = ["mem","kmem","port","zero","full","random","urandom","ptmx","tty","console","samsung","smem","ntk","ion","tzmem","secmem","sec","tzdev","rpmb","efuse"];',
  'result.dev_special = {};',
  'devInterest.forEach(function(d){ try { var st = fs.statSync("/dev/"+d); result.dev_special[d] = { mode: "0"+(st.mode&0xFFF).toString(8), rdev: st.rdev }; } catch(e) {} });',
  'try { var devs = fs.readdirSync("/dev"); result.dev_samsung = devs.filter(function(d){return d.indexOf("samsung")===0;}); result.dev_sec = devs.filter(function(d){return d.indexOf("sec")===0;}); result.dev_ion = devs.filter(function(d){return d.indexOf("ion")===0;}); result.dev_misc = devs.filter(function(d){return d.indexOf("tz")===0||d.indexOf("smem")===0||d.indexOf("rpm")===0||d.indexOf("efuse")===0;}); } catch(e) { result.dev_list_err = e.message; }',
  'try { result.proc_driver = fs.readdirSync("/proc/driver"); } catch(e) { result.proc_driver_err = e.message; }',
  'try { var mods = fs.readdirSync("/sys/module"); result.sys_module_count = mods.length; result.sys_module_head = mods.slice(0,30); } catch(e) { result.sys_module_err = e.message; }',
  'try { var mounts = fs.readFileSync("/proc/mounts", "utf8"); result.mounts_tmpfs = mounts.split("\\n").filter(function(l){ return l.indexOf("tmpfs")>=0||l.indexOf("vdfs")>=0||l.indexOf("ext4")>=0; }); } catch(e) { result.mounts_err = e.message; }',
  'try { result.setuid_bins = cp.execSync("find /usr/bin /usr/sbin /bin /sbin /opt/samsung -perm -4000 -type f 2>/dev/null | head -30", {timeout:10000}).toString().trim().split("\\n").filter(function(x){return x.length>0;}); } catch(e) { result.setuid_err = e.message; }',
  'try { result.ps = cp.execSync("ps | head -40", {timeout:5000}).toString().trim(); } catch(e) { result.ps_err = e.message; }',
  'try { result.kptr_restrict = fs.readFileSync("/proc/sys/kernel/kptr_restrict","utf8").trim(); } catch(e) {}',
  'try { result.perf_paranoid = fs.readFileSync("/proc/sys/kernel/perf_event_paranoid","utf8").trim(); } catch(e) {}',
  'try { result.dmesg_restrict = fs.readFileSync("/proc/sys/kernel/dmesg_restrict","utf8").trim(); } catch(e) {}',
  'try { var kc = fs.openSync("/proc/kcore","r"); fs.closeSync(kc); result.kcore_readable = true; } catch(e) { result.kcore_readable = false; result.kcore_err = e.message; }',
  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'try { fs2.writeFileSync("/home/owner/share/tmp/sdk_tools/tbprobe53h.txt", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 30000 }, function(err, stdout, stderr) {
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
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe53h.txt', result); } catch(e) {}
  });
});
