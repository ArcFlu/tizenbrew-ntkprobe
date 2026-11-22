// v24c - fixed GOT overwrite: read libc by sections only (no full readFileSync)
// Pull server: 8101
try {
  var fs   = require('fs');
  var http = require('http');
  var net  = require('net');
  var lines = ['=== GOT-overwrite v24c ==='];

  var ADDON = '/home/owner/share/tmp/sdk_tools/timing-probe.node';

  // ---- ELF32 helpers on a Buffer ----
  function u32le(buf, o) { return buf[o] | (buf[o+1]<<8) | (buf[o+2]<<16) | (buf[o+3]<<24); }
  function u16le(buf, o) { return buf[o] | (buf[o+1]<<8); }
  function cstr(buf, o)  {
    var e = o; while (e < buf.length && buf[e]) e++;
    return buf.slice(o, e).toString('ascii');
  }

  // Parse ELF32 section headers from a full Buffer
  function getELF32Sections(buf) {
    if (buf[0]!==0x7f||buf[1]!==0x45||buf[2]!==0x4c||buf[3]!==0x46) return null;
    var shoff = u32le(buf,32), shentsize = u16le(buf,46), shnum = u16le(buf,48), shstrndx = u16le(buf,50);
    var secs = [];
    for (var i = 0; i < shnum; i++) {
      var o = shoff + i*shentsize;
      secs.push({ ni: u32le(buf,o), type: u32le(buf,o+4), addr: u32le(buf,o+12),
                  off: u32le(buf,o+16), size: u32le(buf,o+20),
                  link: u32le(buf,o+24), entsize: u32le(buf,o+36) });
    }
    var shstr = secs[shstrndx];
    secs.forEach(function(s){ s.name = cstr(buf, shstr.off+s.ni); });
    var smap = {};
    secs.forEach(function(s){ smap[s.name] = s; });
    return smap;
  }

  // Read a section from an fd into a new Buffer
  function readSection(fd, sec) {
    var b = new Buffer(sec.size);
    fs.readSync(fd, b, 0, sec.size, sec.off);
    return b;
  }

  // ---- Step 1: Load addon ----
  try { require(ADDON); } catch(e) { lines.push('step1: ' + String(e.message||e).substring(0,40)); }

  // ---- Step 2: Maps ----
  var maps = fs.readFileSync('/proc/self/maps', 'utf8').split('\n');
  var addonBase = 0, libcBase = 0;
  maps.forEach(function(l) {
    if (l.indexOf('timing-probe.node') !== -1 && l.indexOf('r-xp') !== -1)
      addonBase = parseInt(l.split('-')[0], 16);
    if (l.indexOf('timing-probe.node') !== -1 && !addonBase)
      addonBase = parseInt(l.split('-')[0], 16);
    if (l.indexOf('libc-2.24.so') !== -1 && l.indexOf('r-xp') !== -1)
      libcBase = parseInt(l.split('-')[0], 16);
  });
  lines.push('step2: addonBase=0x' + addonBase.toString(16) + ' libcBase=0x' + libcBase.toString(16));

  // ---- Step 3: Parse addon ELF -> GOT slots ----
  var addonBuf = fs.readFileSync(ADDON);
  var addonSecs = getELF32Sections(addonBuf);
  var relPlt = addonSecs['.rel.plt'];
  var dynSym = addonSecs['.dynsym'];
  var dynStr = addonSecs['.dynstr'];
  lines.push('step3_secs: relPlt=' + (relPlt?'found':'MISS') + ' dynSym=' + (dynSym?'found':'MISS') + ' dynStr=' + (dynStr?'found':'MISS'));

  var gotSlots = {}; // funcName -> virtual offset of GOT slot from addon base
  if (relPlt && dynSym && dynStr) {
    var entSz = relPlt.entsize || 8;
    var n = Math.floor(relPlt.size / entSz);
    for (var i = 0; i < n; i++) {
      var o = relPlt.off + i*entSz;
      var r_offset = u32le(addonBuf, o);       // VA of GOT slot (offset from addon base)
      var r_info   = u32le(addonBuf, o+4);
      var symIdx   = (r_info >>> 8) & 0xffffff;
      var symOff   = dynSym.off + symIdx*16;
      var stName   = u32le(addonBuf, symOff);
      var funcName = cstr(addonBuf, dynStr.off + stName);
      gotSlots[funcName] = r_offset;
    }
  }
  lines.push('step3_slots: ' + Object.keys(gotSlots).join(','));

  // ---- Step 4: Parse libc .dynsym (sections only, no full read) ----
  var libcFd = fs.openSync('/usr/lib/libc-2.24.so', 'r');
  // Read libc header + section headers
  var libcHdr = new Buffer(52);
  fs.readSync(libcFd, libcHdr, 0, 52, 0);
  var l_shoff = u32le(libcHdr, 32), l_shentsize = u16le(libcHdr, 46), l_shnum = u16le(libcHdr, 48), l_shstrndx = u16le(libcHdr, 50);
  var l_shBuf = new Buffer(l_shnum * l_shentsize);
  fs.readSync(libcFd, l_shBuf, 0, l_shBuf.length, l_shoff);

  // Read section name string table
  var l_strOff = u32le(l_shBuf, l_shstrndx*l_shentsize+16);
  var l_strSz  = u32le(l_shBuf, l_shstrndx*l_shentsize+20);
  var l_strBuf = new Buffer(l_strSz);
  fs.readSync(libcFd, l_strBuf, 0, l_strSz, l_strOff);

  // Find .dynsym and .dynstr
  var l_dynSym = null, l_dynStr = null;
  for (var j = 0; j < l_shnum; j++) {
    var jo = j * l_shentsize;
    var secNi = u32le(l_shBuf, jo);
    var secName = cstr(l_strBuf, secNi);
    var secType = u32le(l_shBuf, jo+4);
    if (secName === '.dynsym') l_dynSym = { off: u32le(l_shBuf,jo+16), size: u32le(l_shBuf,jo+20), entsize: u32le(l_shBuf,jo+36) };
    if (secName === '.dynstr') l_dynStr = { off: u32le(l_shBuf,jo+16), size: u32le(l_shBuf,jo+20) };
  }
  lines.push('step4_secs: dynSym=' + (l_dynSym?'found':'MISS') + ' dynStr=' + (l_dynStr?'found':'MISS'));

  // Read just .dynsym and .dynstr
  var libcOffsets = {}; // funcName -> absolute VA
  if (l_dynSym && l_dynStr) {
    var dSymBuf = new Buffer(l_dynSym.size);
    var dStrBuf = new Buffer(l_dynStr.size);
    fs.readSync(libcFd, dSymBuf, 0, l_dynSym.size, l_dynSym.off);
    fs.readSync(libcFd, dStrBuf, 0, l_dynStr.size, l_dynStr.off);
    var dEntSz = l_dynSym.entsize || 16;
    var dCnt = Math.floor(dSymBuf.length / dEntSz);
    for (var k = 0; k < dCnt; k++) {
      var ko = k * dEntSz;
      var dst_name  = u32le(dSymBuf, ko);
      var dst_value = u32le(dSymBuf, ko+4);  // absolute VA (pre-linked .so)
      var dst_info  = dSymBuf[ko+12];
      if ((dst_info & 0xf) === 2 && dst_value !== 0) { // STT_FUNC
        var dname = cstr(dStrBuf, dst_name);
        libcOffsets[dname] = dst_value;
      }
    }
  }
  fs.closeSync(libcFd);

  var keyFuncs = ['usleep','getpid','socket','connect','send','open','mmap','close','write','munmap'];
  var found = keyFuncs.filter(function(f){ return libcOffsets[f]; });
  lines.push('step4_found: ' + found.join(','));
  found.forEach(function(f){ lines.push('  ' + f + ' -> 0x' + libcOffsets[f].toString(16)); });

  // ---- Step 5: Read current GOT values before patching ----
  var memFd = fs.openSync('/proc/self/mem', 'r+');
  var readBuf = new Buffer(4);
  lines.push('step5_before_patch:');
  Object.keys(gotSlots).forEach(function(fn) {
    var gotVA = addonBase + gotSlots[fn];
    try {
      fs.readSync(memFd, readBuf, 0, 4, gotVA);
      lines.push('  ' + fn + '@0x' + gotVA.toString(16) + ' = 0x' + readBuf.readUInt32LE(0).toString(16));
    } catch(e) { lines.push('  ' + fn + '@0x' + gotVA.toString(16) + ': ' + String(e.code||e.message)); }
  });

  // ---- Step 6: Patch GOT with real libc addresses ----
  var patched = [], failed = [];
  var writeBuf = new Buffer(4);
  Object.keys(gotSlots).forEach(function(fn) {
    if (libcOffsets[fn]) {
      var gotVA = addonBase + gotSlots[fn];
      var realVA = libcOffsets[fn]; // already absolute VA
      writeBuf.writeUInt32LE(realVA, 0);
      try {
        fs.writeSync(memFd, writeBuf, 0, 4, gotVA);
        patched.push(fn + '@0x' + gotVA.toString(16) + '->0x' + realVA.toString(16));
      } catch(we) { failed.push(fn + ':' + String(we.code||we.message)); }
    }
  });
  fs.closeSync(memFd);
  lines.push('step6_patched: ' + patched.join(', '));
  if (failed.length) lines.push('step6_failed: ' + failed.join(', '));

  // ---- Step 7: Re-require and time ----
  delete require.cache[ADDON];
  try { delete require.cache[require.resolve(ADDON)]; } catch(e) {}

  // Listener on 7781
  var socketData = '';
  var srv = net.createServer(function(c) {
    c.on('data', function(d) { socketData += d.toString(); });
    c.on('end', function() { srv.close(); });
  });
  srv.on('error', function(e) { lines.push('srv_err: ' + e.message); });
  srv.listen(7781, '127.0.0.1', function() { lines.push('srv7781: ready'); });

  setTimeout(function() {
    var t0 = Date.now();
    try { require(ADDON); lines.push('step7_load: OK'); }
    catch(e) { lines.push('step7_load: threw: ' + String(e.message||e).substring(0,60)); }
    var ms = Date.now() - t0;
    lines.push('step7_ms: ' + ms);
    if      (ms < 20)   lines.push('RESULT: STUBS STILL ACTIVE (glibc broken)');
    else if (ms < 100)  lines.push('RESULT: usleep WORKS! pid%10=0, socket not tested');
    else if (ms < 1000) lines.push('RESULT: glibc WORKS! pid%10 ~= ' + Math.round((ms-50)/100));
    else if (ms < 3000) lines.push('RESULT: usleep ok, socket FAILED errno~=' + Math.round((ms-1000)/10));
    else                lines.push('RESULT: socket SUCCEEDED -> full glibc works!');

    setTimeout(function() {
      if (socketData) lines.push('socket_data: ' + socketData.trim());
      var body = lines.join('\n') + '\n=== END ===\n';
      try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24c.txt', body); } catch(e3) {}
      var pullSrv = http.createServer(function(req, res) {
        res.writeHead(200, {'Content-Type':'text/plain'});
        res.end(body);
      });
      pullSrv.listen(8101, '127.0.0.1', function(){});
      pullSrv.on('error', function(e){});
      setInterval(function(){}, 60000);
    }, 5000);
  }, 300);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24c-crash.txt', String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
