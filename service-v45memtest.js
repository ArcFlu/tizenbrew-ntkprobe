(function() {
  var fs = require('fs');
  var http = require('http');
  var log = '';

  // Find rwx JIT page
  var maps = fs.readFileSync('/proc/self/maps', 'utf8');
  var jit = 0;
  maps.split('\n').forEach(function(line) {
    if (!jit && line.indexOf('rwxp') !== -1) {
      jit = parseInt(line.split('-')[0], 16);
    }
  });
  log += 'jit=0x' + jit.toString(16) + '\n';

  if (!jit) { log += 'NO_RWX\n=== END ===\n'; finish(log); return; }

  // Try writing 4 NOP bytes (Thumb-2 nop = 00 bf) via /proc/self/mem
  var ok = false;
  try {
    var fd = fs.openSync('/proc/self/mem', 'r+');
    log += 'fd_open_ok\n';
    var nops = new Buffer([0x00, 0xbf, 0x00, 0xbf]);
    var w = fs.writeSync(fd, nops, 0, 4, jit);
    log += 'write_ok bytes=' + w + '\n';
    // Read back
    var rb = new Buffer(4);
    var r = fs.readSync(fd, rb, 0, 4, jit);
    log += 'readback=' + rb.toString('hex') + ' n=' + r + '\n';
    fs.closeSync(fd);
    ok = true;
  } catch(e) {
    log += 'err=' + e.message + '\n';
  }

  // Now try larger write (512 bytes)
  if (ok) {
    try {
      var fd2 = fs.openSync('/proc/self/mem', 'r+');
      var big = new Buffer(512);
      for (var i = 0; i < 512; i += 2) { big[i] = 0x00; big[i+1] = 0xbf; }
      var w2 = fs.writeSync(fd2, big, 0, 512, jit);
      log += 'big_write_ok bytes=' + w2 + '\n';
      fs.closeSync(fd2);
    } catch(e2) {
      log += 'big_write_err=' + e2.message + '\n';
    }
  }

  log += '=== END ===\n';
  finish(log);

  function finish(body) {
    fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe45.txt', body);
    var srv = http.createServer(function(req, res) { res.end(body); });
    srv.listen(8130, '127.0.0.1');
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }
})();
