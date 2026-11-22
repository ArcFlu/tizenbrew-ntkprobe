// v21 - pure JS exploit paths: child_process, /proc/self/mem, wasutility, capabilities
// Pull server port 8094
try {
  var cp    = require('child_process');
  var fs    = require('fs');
  var net   = require('net');
  var http  = require('http');
  var lines = ['=== js-exploit-paths v21 ==='];

  // ---- 1. child_process ----
  function testCP() {
    // spawnSync
    try {
      var r = cp.spawnSync('/usr/bin/id', [], {timeout: 1000});
      lines.push('cp.spawnSync id: status=' + r.status +
        ' stdout=' + (r.stdout||'').toString().trim().substring(0,80) +
        ' err=' + (r.stderr||'').toString().trim().substring(0,40));
    } catch(e) { lines.push('cp.spawnSync id: threw ' + String(e.code||e.message)); }

    // execSync
    try {
      var out = cp.execSync('id', {timeout: 1000, encoding: 'utf8'});
      lines.push('cp.execSync id: ' + out.trim());
    } catch(e) { lines.push('cp.execSync id: threw ' + String(e.code||e.message)); }

    // Try wasutility (setuid root) with no args
    try {
      var r2 = cp.spawnSync('/bin/wasutility', [], {timeout: 1000});
      lines.push('cp.spawnSync wasutility: status=' + r2.status +
        ' stdout=' + (r2.stdout||'').toString().trim().substring(0,80) +
        ' stderr=' + (r2.stderr||'').toString().trim().substring(0,80));
    } catch(e) { lines.push('cp.spawnSync wasutility: threw ' + String(e.code||e.message)); }

    // Try RunningAppsService (another setuid binary)
    try {
      var r3 = cp.spawnSync('/bin/RunningAppsService', [], {timeout: 500});
      lines.push('cp.spawnSync RunningAppsService: status=' + r3.status +
        ' stderr=' + (r3.stderr||'').toString().trim().substring(0,80));
    } catch(e) { lines.push('cp.spawnSync RunningAppsService: threw ' + String(e.code||e.message)); }
  }

  // ---- 2. /proc/self/mem writability ----
  function testProcMem() {
    try {
      var maps = fs.readFileSync('/proc/self/maps', 'utf8');
      var mlines = maps.split('\n');
      var libcLine = mlines.filter(function(l){ return l.indexOf('libc-')!==-1 && l.indexOf('r-xp')!==-1; });
      lines.push('maps_libc_rx: ' + (libcLine[0]||'NOT FOUND').substring(0,80));
      var nodeLine = mlines.filter(function(l){ return l.indexOf('/node')!==-1 && l.indexOf('r-xp')!==-1; });
      lines.push('maps_node_rx: ' + (nodeLine[0]||'NOT FOUND').substring(0,80));
      var heap = mlines.filter(function(l){ return l.indexOf('[heap]')!==-1; });
      lines.push('maps_heap: ' + (heap[0]||'NOT FOUND'));
    } catch(e) { lines.push('proc_maps: threw ' + String(e.code||e.message)); }

    // Try opening /proc/self/mem read-only
    try {
      var fd = fs.openSync('/proc/self/mem', 'r');
      lines.push('proc_mem_ro: OK fd=' + fd);
      fs.closeSync(fd);
    } catch(e) { lines.push('proc_mem_ro: ' + String(e.code||e.message)); }

    // Try opening /proc/self/mem read-write (KEY TEST)
    try {
      var fd2 = fs.openSync('/proc/self/mem', 'r+');
      lines.push('proc_mem_rw: OK fd=' + fd2 + ' -- WRITABLE!');
      fs.closeSync(fd2);
    } catch(e) { lines.push('proc_mem_rw: ' + String(e.code||e.message)); }
  }

  // ---- 3. wasutility binary analysis ----
  function testWasutility() {
    try {
      var st = fs.statSync('/bin/wasutility');
      var mode = (st.mode).toString(8);
      lines.push('wasutility: size=' + st.size + ' mode=' + mode + ' uid=' + st.uid);
    } catch(e) { lines.push('wasutility_stat: ' + String(e.code||e.message)); }

    // Read first 64 bytes (ELF header + arch info)
    try {
      var buf = Buffer.allocUnsafe(64);
      var fd = fs.openSync('/bin/wasutility', 'r');
      var n = fs.readSync(fd, buf, 0, 64, 0);
      fs.closeSync(fd);
      lines.push('wasutility_elf: ' + buf.slice(0,n).toString('hex'));
      // EI_CLASS (byte 4): 1=32bit 2=64bit
      // EI_DATA (byte 5): 1=LE 2=BE
      // e_machine (bytes 18-19): 0x28=ARM 0xB7=AArch64
      lines.push('wasutility_arch: class=' + buf[4] + ' endian=' + buf[5] + ' machine=0x' + buf.readUInt16LE(18).toString(16));
    } catch(e) { lines.push('wasutility_read: ' + String(e.code||e.message)); }

    // List all setuid binaries in /bin
    try {
      var bins = fs.readdirSync('/bin');
      var suid = [];
      bins.forEach(function(b) {
        try {
          var s = fs.statSync('/bin/' + b);
          if (s.mode & 0o4000) suid.push(b + '(uid=' + s.uid + ')');
        } catch(e2) {}
      });
      lines.push('suid_in_bin: ' + suid.join(', '));
    } catch(e) { lines.push('suid_scan: ' + String(e.code||e.message)); }
  }

  // ---- 4. Process capabilities ----
  function testCaps() {
    try {
      var status = fs.readFileSync('/proc/self/status', 'utf8');
      var cap = status.split('\n').filter(function(l){ return l.indexOf('Cap')!==-1; });
      lines.push('caps: ' + cap.join(' | '));
    } catch(e) { lines.push('proc_status: ' + String(e.code||e.message)); }

    // Check smack label
    try {
      var label = fs.readFileSync('/proc/self/attr/current', 'utf8');
      lines.push('smack_label: ' + label.trim());
    } catch(e) { lines.push('smack_label: ' + String(e.code||e.message)); }

    // Check /proc/self/fd open file descriptors
    try {
      var fds = fs.readdirSync('/proc/self/fd');
      var fdinfo = fds.slice(0,20).map(function(f){
        try { return f+':'+fs.readlinkSync('/proc/self/fd/'+f); } catch(e2){ return f+':?'; }
      });
      lines.push('open_fds: ' + fdinfo.join(', '));
    } catch(e) { lines.push('proc_fd: ' + String(e.code||e.message)); }
  }

  // ---- 5. /dev/sdp_mem via JS ----
  function testSdpMem() {
    // Try opening directly from JS (not via native code)
    try {
      var fd = fs.openSync('/dev/sdp_mem', 'r');
      lines.push('sdp_mem_ro: OK fd=' + fd);
      // Try reading 4 bytes at offset 0
      var buf = Buffer.allocUnsafe(4);
      try {
        var n = fs.readSync(fd, buf, 0, 4, 0);
        lines.push('sdp_mem_read: ' + buf.slice(0,n).toString('hex'));
      } catch(e2) { lines.push('sdp_mem_read: ' + String(e2.code||e2.message)); }
      fs.closeSync(fd);
    } catch(e) { lines.push('sdp_mem_ro: ' + String(e.code||e.message)); }

    try {
      var fd2 = fs.openSync('/dev/sdp_mem', 'r+');
      lines.push('sdp_mem_rw: OK -- WRITABLE!');
      fs.closeSync(fd2);
    } catch(e) { lines.push('sdp_mem_rw: ' + String(e.code||e.message)); }
  }

  // ---- 6. Smack xattr on our addon ----
  function testXattr() {
    var addonPath = '/home/owner/share/tmp/sdk_tools/timing-probe.node';
    try {
      var st = fs.statSync(addonPath);
      lines.push('addon_stat: size=' + st.size + ' mode=' + st.mode.toString(8) + ' uid=' + st.uid);
    } catch(e) { lines.push('addon_stat: ' + String(e.code||e.message)); }
  }

  // Run all tests synchronously
  testCP();
  testProcMem();
  testWasutility();
  testCaps();
  testSdpMem();
  testXattr();

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe21.txt', body); } catch(e) {}

  var pullSrv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullSrv.listen(8094, '127.0.0.1', function() {});
  pullSrv.on('error', function(e) {});
  setInterval(function() {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe21-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
