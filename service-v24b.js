// v24b - read crash/probe files from v24 + debug ELF parsing
// Pull server port 8100
try {
  var fs   = require('fs');
  var http = require('http');
  var lines = ['=== v24b debug ==='];

  // Read crash/output files from v24
  var files = [
    '/home/owner/share/tmp/sdk_tools/tbprobe24-crash.txt',
    '/home/owner/share/tmp/sdk_tools/tbprobe24.txt',
  ];
  files.forEach(function(f) {
    try { lines.push(f + ': ' + fs.readFileSync(f, 'utf8').substring(0,500)); }
    catch(e) { lines.push(f + ': ' + String(e.code||e.message)); }
  });

  // Also debug: can we read libc? (size check)
  try {
    var st = fs.statSync('/usr/lib/libc-2.24.so');
    lines.push('libc_size: ' + st.size);
    // Try reading just the first 64 bytes
    var fd = fs.openSync('/usr/lib/libc-2.24.so', 'r');
    var buf = new Buffer(64);
    var n = fs.readSync(fd, buf, 0, 64, 0);
    fs.closeSync(fd);
    lines.push('libc_header: ' + buf.slice(0,n).toString('hex'));
  } catch(e) { lines.push('libc_check: ' + String(e.code||e.message)); }

  // Debug: try parseELF on small buffer
  try {
    var ADDON = '/home/owner/share/tmp/sdk_tools/timing-probe.node';
    var addonBuf = fs.readFileSync(ADDON);
    lines.push('addon_read: ' + addonBuf.length + ' bytes');
    // Check e_shoff
    var e_shoff = addonBuf.readUInt32LE(32);
    var e_shentsize = addonBuf.readUInt16LE(46);
    var e_shnum = addonBuf.readUInt16LE(48);
    var e_shstrndx = addonBuf.readUInt16LE(50);
    lines.push('addon_elf: shoff=' + e_shoff + ' shnum=' + e_shnum + ' shentsize=' + e_shentsize + ' shstrndx=' + e_shstrndx);

    // Try loading libc in chunks to see if memory is the issue
    var libcFd = fs.openSync('/usr/lib/libc-2.24.so', 'r');
    var libcSt = fs.statSync('/usr/lib/libc-2.24.so');
    var libcSize = libcSt.size;

    // Read libc header to find section headers
    var hdr = new Buffer(52);
    fs.readSync(libcFd, hdr, 0, 52, 0);
    var l_shoff     = hdr.readUInt32LE(32);
    var l_shentsize = hdr.readUInt16LE(46);
    var l_shnum     = hdr.readUInt16LE(48);
    var l_shstrndx  = hdr.readUInt16LE(50);
    lines.push('libc_elf: shoff=' + l_shoff + ' shnum=' + l_shnum + ' size=' + libcSize);

    // Read all section headers
    var l_shBuf = new Buffer(l_shnum * l_shentsize);
    fs.readSync(libcFd, l_shBuf, 0, l_shBuf.length, l_shoff);

    // Get section name string table
    var strsh_offset = l_shBuf.readUInt32LE(l_shstrndx * l_shentsize + 16);
    var strsh_size   = l_shBuf.readUInt32LE(l_shstrndx * l_shentsize + 20);
    var strBuf = new Buffer(strsh_size);
    fs.readSync(libcFd, strBuf, 0, strsh_size, strsh_offset);

    // Find .dynsym and .dynstr sections
    var l_dynSym = null, l_dynStr = null;
    for (var i = 0; i < l_shnum; i++) {
      var o = i * l_shentsize;
      var nameIdx = l_shBuf.readUInt32LE(o);
      var nameEnd = nameIdx;
      while (nameEnd < strBuf.length && strBuf[nameEnd] !== 0) nameEnd++;
      var secName = strBuf.slice(nameIdx, nameEnd).toString('ascii');
      var sh_type = l_shBuf.readUInt32LE(o + 4);
      var sh_offset = l_shBuf.readUInt32LE(o + 16);
      var sh_size = l_shBuf.readUInt32LE(o + 20);
      if (secName === '.dynsym') l_dynSym = { offset: sh_offset, size: sh_size, entsize: l_shBuf.readUInt32LE(o+36) };
      if (secName === '.dynstr') l_dynStr = { offset: sh_offset, size: sh_size };
    }
    lines.push('libc_secs: dynsym=' + (l_dynSym?'found@'+l_dynSym.offset:'MISSING') + ' dynstr=' + (l_dynStr?'found@'+l_dynStr.offset:'MISSING'));

    if (l_dynSym && l_dynStr) {
      // Read just .dynsym and .dynstr (NOT the whole libc)
      var dynSymBuf = new Buffer(l_dynSym.size);
      var dynStrBuf = new Buffer(l_dynStr.size);
      fs.readSync(libcFd, dynSymBuf, 0, l_dynSym.size, l_dynSym.offset);
      fs.readSync(libcFd, dynStrBuf, 0, l_dynStr.size, l_dynStr.offset);
      lines.push('libc_dynsym_read: ' + dynSymBuf.length + ' bytes');
      lines.push('libc_dynstr_read: ' + dynStrBuf.length + ' bytes');

      // Find target functions
      var targets = ['usleep','getpid','socket','mmap','open','write','close','munmap','connect','send'];
      var found = {};
      var entSz = l_dynSym.entsize || 16;
      var symCount = Math.floor(dynSymBuf.length / entSz);
      for (var j = 0; j < symCount; j++) {
        var so = j * entSz;
        var st_name = dynSymBuf.readUInt32LE(so);
        var st_value = dynSymBuf.readUInt32LE(so + 4);
        var st_info = dynSymBuf[so + 12];
        if ((st_info & 0xf) === 2 && st_value !== 0) {
          var ne = st_name;
          while (ne < dynStrBuf.length && dynStrBuf[ne] !== 0) ne++;
          var sym = dynStrBuf.slice(st_name, ne).toString('ascii');
          if (targets.indexOf(sym) !== -1) found[sym] = st_value;
        }
      }
      lines.push('libc_offsets: ' + JSON.stringify(found));
    }
    fs.closeSync(libcFd);
  } catch(e) { lines.push('debug_elf: threw: ' + String(e.stack||e.message).substring(0,300)); }

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24b.txt', body); } catch(e) {}
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8100, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24b-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
