// v40 - check /dev/ for ps_mknod created nodes, read privserv scripts,
//       introspect gumd+pkgdir, serve libc for GOT analysis
// Pull server: 8124 (main), /libc (binary)
(function() {
  var fs = require('fs');
  var http = require('http');
  var cp = require('child_process');
  var RES = {};
  var TOTAL = 11; // fixed count
  var DONE = 0;

  function finish(k, v) {
    RES[k] = String(v).substring(0, 1500);
    if (++DONE >= TOTAL) flush();
  }
  function flush() {
    var body = Object.keys(RES).map(function(k){ return '[' + k + ']: ' + RES[k]; }).join('\n') + '\n=== LIVE ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe40.txt', body); } catch(e) {}
    var srv = http.createServer(function(req, resp) {
      resp.writeHead(200, {'Content-Type': 'text/plain'});
      resp.end(body);
    });
    srv.listen(8124, '127.0.0.1', function(){});
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }
  function run(k, cmd) {
    cp.exec(cmd + ' 2>&1', {timeout:8000}, function(e,o){ finish(k, o||String(e)); });
  }
  function dbus(k, dest, path, iface) {
    var cmd = 'dbus-send --system --print-reply --dest=' + dest + ' ' + path + ' org.freedesktop.DBus.Introspectable.Introspect 2>&1';
    cp.exec(cmd, {timeout:8000}, function(e,o){ finish(k, o||String(e)); });
  }

  // 1. Check /dev/ for previously created device nodes
  run('dev_check',  'find /dev -name "mem3*" -o -name "null3*" -o -name "zero3*" -o -name "loop3*" 2>/dev/null; ls -la /dev/mem37 /dev/null37 /dev/zero37 2>/dev/null || echo none_found');

  // 2. Read privileged-service scripts
  run('ps_scripts',  'ls /usr/apps/privileged-service/scripts/ 2>/dev/null; cat /usr/apps/privileged-service/scripts/*.sh 2>/dev/null | head -60');

  // 3. Introspect gumd (user management daemon)
  dbus('gumd_root', 'org.tizen.gumd', '/', 'org.freedesktop.DBus.Introspectable.Introspect');

  // 4. Introspect pkgdir_tool
  dbus('pkgdir_root', 'org.tizen.pkgdir_tool', '/', 'org.freedesktop.DBus.Introspectable.Introspect');

  // 5. Introspect pkg_recovery
  dbus('pkgrecov_root', 'org.tizen.pkg_recovery', '/', 'org.freedesktop.DBus.Introspectable.Introspect');

  // 6. Read libc ELF header for GOT analysis (first 128 bytes = ELF header)
  try {
    var libcBuf = fs.readFileSync('/usr/lib/libc-2.24.so');
    // Parse ARM32 ELF header
    // e_shoff at offset 0x20
    var e_shoff = libcBuf.readUInt32LE(0x20);
    var e_shentsize = libcBuf.readUInt16LE(0x2E);
    var e_shnum = libcBuf.readUInt16LE(0x30);
    var e_shstrndx = libcBuf.readUInt16LE(0x32);
    // Read .shstrtab to get section names
    var strtab_sh = e_shoff + e_shstrndx * e_shentsize;
    var strtab_offset = libcBuf.readUInt32LE(strtab_sh + 0x10);
    var strtab_size = libcBuf.readUInt32LE(strtab_sh + 0x14);
    var strtab = libcBuf.slice(strtab_offset, strtab_offset + strtab_size);
    // Find .got and .got.plt sections
    var gotInfo = [];
    for (var i = 0; i < e_shnum; i++) {
      var shOff = e_shoff + i * e_shentsize;
      var nameOff = libcBuf.readUInt32LE(shOff);
      var nameEnd = nameOff;
      while (nameEnd < strtab.length && strtab[nameEnd] !== 0) nameEnd++;
      var name = strtab.slice(nameOff, nameEnd).toString();
      if (name === '.got' || name === '.got.plt' || name === '.rel.plt') {
        var sh_addr = libcBuf.readUInt32LE(shOff + 0x0C);
        var sh_offset = libcBuf.readUInt32LE(shOff + 0x10);
        var sh_size = libcBuf.readUInt32LE(shOff + 0x14);
        gotInfo.push(name + '→addr=0x' + sh_addr.toString(16) + ',off=0x' + sh_offset.toString(16) + ',sz=' + sh_size);
      }
    }
    // Also find .rel.dyn and .rela.plt for symbol resolution
    var pltSyms = [];
    for (var i = 0; i < e_shnum; i++) {
      var shOff = e_shoff + i * e_shentsize;
      var nameOff2 = libcBuf.readUInt32LE(shOff);
      var nameEnd2 = nameOff2;
      while (nameEnd2 < strtab.length && strtab[nameEnd2] !== 0) nameEnd2++;
      var name2 = strtab.slice(nameOff2, nameEnd2).toString();
      if (name2 === '.rel.plt') {
        var rel_offset = libcBuf.readUInt32LE(shOff + 0x10);
        var rel_size = libcBuf.readUInt32LE(shOff + 0x14);
        // .rel.plt link = .dynsym index, info = .dynstr
        // Each entry: r_offset(4) + r_info(4) = 8 bytes
        for (var j = 0; j < rel_size; j += 8) {
          var r_offset = libcBuf.readUInt32LE(rel_offset + j);
          var r_info = libcBuf.readUInt32LE(rel_offset + j + 4);
          var sym_idx = r_info >> 8;
          pltSyms.push('got_addr=0x' + r_offset.toString(16) + ',sym=' + sym_idx);
        }
        break;
      }
    }
    finish('libc_got', 'sections:' + gotInfo.join('; ') + '\nrel_plt_first_10:' + pltSyms.slice(0,10).join('; '));
  } catch(e) {
    finish('libc_got', 'err: ' + String(e.message));
  }

  // 7. Read libc .dynsym to map symbol indices to names (for GOT entry resolution)
  try {
    var libcBuf2 = fs.readFileSync('/usr/lib/libc-2.24.so');
    var e_shoff2 = libcBuf2.readUInt32LE(0x20);
    var e_shentsize2 = libcBuf2.readUInt16LE(0x2E);
    var e_shnum2 = libcBuf2.readUInt16LE(0x30);
    var e_shstrndx2 = libcBuf2.readUInt16LE(0x32);
    var strtab2_sh = e_shoff2 + e_shstrndx2 * e_shentsize2;
    var strtab2_off = libcBuf2.readUInt32LE(strtab2_sh + 0x10);
    var strtab2_sz = libcBuf2.readUInt32LE(strtab2_sh + 0x14);
    var shstrtab2 = libcBuf2.slice(strtab2_off, strtab2_off + strtab2_sz);
    var dynsymOff = 0, dynsymSz = 0, dynstrOff = 0, dynstrSz = 0;
    for (var i = 0; i < e_shnum2; i++) {
      var shOff = e_shoff2 + i * e_shentsize2;
      var nameOff = libcBuf2.readUInt32LE(shOff);
      var nameEnd = nameOff; while(nameEnd < shstrtab2.length && shstrtab2[nameEnd]) nameEnd++;
      var nm = shstrtab2.slice(nameOff, nameEnd).toString();
      if (nm === '.dynsym') { dynsymOff = libcBuf2.readUInt32LE(shOff+0x10); dynsymSz = libcBuf2.readUInt32LE(shOff+0x14); }
      if (nm === '.dynstr') { dynstrOff = libcBuf2.readUInt32LE(shOff+0x10); dynstrSz = libcBuf2.readUInt32LE(shOff+0x14); }
    }
    var dynstr = libcBuf2.slice(dynstrOff, dynstrOff + dynstrSz);
    // Each Elf32_Sym: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2) = 16 bytes
    var freeIdx = -1, mallocIdx = -1, strlenIdx = -1;
    for (var i = 0; i < dynsymSz; i += 16) {
      var nameOff = libcBuf2.readUInt32LE(dynsymOff + i);
      var nameEnd = nameOff; while(nameEnd < dynstr.length && dynstr[nameEnd]) nameEnd++;
      var nm = dynstr.slice(nameOff, nameEnd).toString();
      var idx = i / 16;
      if (nm === 'free') freeIdx = idx;
      if (nm === 'malloc') mallocIdx = idx;
      if (nm === 'strlen') strlenIdx = idx;
    }
    finish('libc_syms', 'free_idx=' + freeIdx + ' malloc_idx=' + mallocIdx + ' strlen_idx=' + strlenIdx);
  } catch(e) {
    finish('libc_syms', 'err:' + String(e.message));
  }

  // 8. Get the full libc maps including rw-p segment
  try {
    var maps = fs.readFileSync('/proc/self/maps', 'utf8');
    var libcLines = maps.split('\n').filter(function(l){ return l.indexOf('libc-2.24') !== -1; });
    finish('libc_maps', libcLines.join('\n'));
  } catch(e) { finish('libc_maps', String(e.message)); }

  // 9. Check for python/perl/lua on TV
  run('interps',   'which python python3 python2 perl lua awk gawk 2>/dev/null; ls /usr/bin/python* /usr/bin/perl* 2>/dev/null');

  // 10. Try pkgdir_tool ListDirs method (guessing)
  cp.exec('dbus-send --system --print-reply --dest=org.tizen.pkgdir_tool /org/tizen/pkgdir_tool org.freedesktop.DBus.Introspectable.Introspect 2>&1', {timeout:8000}, function(e,o){ finish('pkgdir_obj', o||String(e)); });

  // 11. Check /etc/dbus-1/system.d for ps_mknod conf (different path)
  run('psmknod_conf2', 'find /etc /usr -name "*ps_mknod*" -o -name "*privileged*" 2>/dev/null | head -10; cat /etc/dbus-1/system.d/privileged-service.conf 2>/dev/null');

})();
