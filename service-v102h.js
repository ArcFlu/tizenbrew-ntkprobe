'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8191;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe102h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Check for ntksys and related devices
  'r.dev_ntk = {};',
  'var ntk_devs = ["ntksys","ntkhdma","ntkxdma","ntk0","ntk1","sdpsys","sdphdma","kfactory","kmalloc","smem"];',
  'ntk_devs.forEach(function(d) {',
  '  try {',
  '    var st = fs.statSync("/dev/"+d);',
  '    r.dev_ntk[d] = { mode: "0"+st.mode.toString(8), uid: st.uid, gid: st.gid };',
  '  } catch(e) { r.dev_ntk[d] = "NOENT"; }',
  '});',

  // 2. Try to open /dev/ntksys
  'try {',
  '  var ntk_fd = fs.openSync("/dev/ntksys", "r+");',
  '  fs.closeSync(ntk_fd);',
  '  r.ntksys_open_rdwr = "SUCCESS";',
  '} catch(e) { r.ntksys_open_rdwr = "FAIL:"+e.message.slice(0,60); }',

  // 3. /proc/cmdline — physical memory layout
  'try { r.proc_cmdline = fs.readFileSync("/proc/cmdline","utf8").trim(); }',
  'catch(e) { r.proc_cmdline = "ERR:"+e.message.slice(0,50); }',

  // 4. /proc/iomem — physical memory map
  'try { r.proc_iomem = fs.readFileSync("/proc/iomem","utf8").slice(0,3000); }',
  'catch(e) { r.proc_iomem = "ERR:"+e.message.slice(0,50); }',

  // 5. Check interpreters for memfd execution
  'r.interpreters = {};',
  'var interps = ["python3","python","python2","python2.7","perl","ruby","lua","bash","dash"];',
  'interps.forEach(function(i) {',
  '  try {',
  '    var o = cp.spawnSync("which",[i],{timeout:2000});',
  '    r.interpreters[i] = (o.stdout||new Buffer(0)).toString().trim().slice(0,80) || "not found";',
  '  } catch(e) { r.interpreters[i] = "ERR"; }',
  '});',

  // 6. Test python3 memfd_create
  'try {',
  '  var py_test = "import ctypes\\nfd=ctypes.CDLL(None).memfd_create(b\'x\',1)\\nprint(fd)";',
  '  var o_py = cp.spawnSync("python3",["-c",py_test],{timeout:5000});',
  '  r.python3_memfd = (o_py.stdout||new Buffer(0)).toString().trim().slice(0,80);',
  '  r.python3_memfd_err = (o_py.stderr||new Buffer(0)).toString().trim().slice(0,80);',
  '} catch(e) { r.python3_memfd = "ERR:"+e.message.slice(0,50); }',

  // 7. /dev/shm availability
  'try { r.dev_shm = fs.readdirSync("/dev/shm"); r.dev_shm_writable = true; }',
  'catch(e) { r.dev_shm = "ERR:"+e.message.slice(0,50); r.dev_shm_writable = false; }',
  'try {',
  '  fs.writeFileSync("/dev/shm/testntk102","x");',
  '  fs.unlinkSync("/dev/shm/testntk102");',
  '  r.dev_shm_write_ok = true;',
  '} catch(e) { r.dev_shm_write_ok = false; r.dev_shm_write_err = e.message.slice(0,50); }',

  // 8. Test node require() of a .node addon from /tmp
  // Write a minimal valid ELF .so to /tmp and try require() it
  // (If this fails with something other than EPERM, dlopen might work)
  'try {',
  '  require("/tmp/nonexistent_test_addon.node");',
  '} catch(e2) {',
  '  r.node_require_nonexistent_err = e2.message.slice(0,100);',
  '}',

  // 9. /usr/bin and /bin contents (truncated) for available tools
  'try { r.usr_bin = fs.readdirSync("/usr/bin").slice(0,60); }',
  'catch(e) { r.usr_bin = "ERR:"+e.message.slice(0,50); }',
  'try { r.bin_ls = fs.readdirSync("/bin").slice(0,60); }',
  'catch(e) { r.bin_ls = "ERR:"+e.message.slice(0,50); }',

  // 10. busybox applets list
  'try {',
  '  var o_bb = cp.spawnSync("busybox",["--list"],{timeout:3000});',
  '  r.busybox_applets = (o_bb.stdout||new Buffer(0)).toString().trim().split("\\n").slice(0,100);',
  '} catch(e) { r.busybox_applets = "ERR:"+e.message.slice(0,50); }',

  // 11. /proc/self/maps — find any RWX regions in Node.js process
  'try {',
  '  var maps = fs.readFileSync("/proc/self/maps","utf8").split("\\n");',
  '  r.rwx_maps = maps.filter(function(l){ return l.indexOf("rwx")>-1 || l.indexOf("rwxp")>-1; }).slice(0,10);',
  '  r.exec_maps = maps.filter(function(l){ return l.indexOf(" r-xp ")>-1 && l.length>20; }).slice(0,15);',
  '} catch(e) { r.maps_err = e.message.slice(0,50); }',

  // 12. Try to exec /tmp/x — to verify UEP actually blocks us
  // Write a minimal ELF header to /tmp/ueptest
  'try {',
  '  // Write ARM "exit 0" ELF: minimal ELF header + exit(0) ARM EABI code',
  '  // 7f 45 4c 46 01 01 01 00 ... (ELF header)',
  '  // Skip for now — just try with current node binary to see if /tmp exec is blocked',
  '  cp.spawnSync(process.execPath,["-e","process.exit(0)"],{timeout:3000});',
  '  r.node_self_exec = "can exec node";',
  '} catch(e) { r.node_self_exec = "ERR:"+e.message.slice(0,60); }',

  // 13. Check writable paths that might be execve-accessible
  'r.path_exec_tests = {};',
  'var testpaths = ["/tmp","/dev/shm","/home/owner/share/tmp/sdk_tools","/opt/usr/apps/factory-service/share"];',
  'testpaths.forEach(function(p) {',
  '  try {',
  '    var st = fs.statSync(p);',
  '    r.path_exec_tests[p] = { mode: "0"+st.mode.toString(8), uid: st.uid };',
  '  } catch(e) { r.path_exec_tests[p] = "ERR:"+e.message.slice(0,40); }',
  '});',

  // 14. /proc/self/status
  'try { r.proc_self_status = fs.readFileSync("/proc/self/status","utf8").split("\\n").filter(function(l){ return l.indexOf("Uid")>-1||l.indexOf("Gid")>-1||l.indexOf("Smack")>-1; }).join("\\n"); }',
  'catch(e) {}',

  // 15. /proc/sys/kernel/perf_event_paranoid — may allow kernel memory access
  'try { r.perf_event_paranoid = fs.readFileSync("/proc/sys/kernel/perf_event_paranoid","utf8").trim(); }',
  'catch(e) { r.perf_event_paranoid = "ERR"; }',

  'var out = JSON.stringify(r,null,2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '",out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 120000 }, function(err, stdout, stderr) {
    if (err) cb(JSON.stringify({ exec_error: err.message.slice(0,200), stderr: (stderr||'').slice(0,500) }));
    else cb(stdout || '{}');
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
