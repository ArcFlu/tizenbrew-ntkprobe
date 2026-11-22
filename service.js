// v20 - timing-probe.node: measures require() duration to decode glibc status
// Pull server port 8093
try {
  var net = require('net');
  var http = require('http');
  var fs = require('fs');
  var lines = ['=== timing-probe v20 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/timing-probe.node';
  var socketData = '';

  // Start socket receiver on 7779
  var srv = net.createServer(function(c) {
    c.on('data', function(d) { socketData += d.toString(); });
    c.on('end', function() { srv.close(); });
  });
  srv.on('error', function(e) { lines.push('srv_err: ' + e.message); });
  srv.listen(7779, '127.0.0.1', function() {
    lines.push('srv7779: ready');
  });

  // Load addon and time it
  setTimeout(function() {
    var t0 = Date.now();
    try {
      require(addonPath);
      lines.push('addon: loaded OK');
    } catch(e) {
      lines.push('addon: threw: ' + String(e.message || e));
    }
    var elapsed = Date.now() - t0;
    lines.push('require_ms: ' + elapsed);

    // Decode timing:
    if (elapsed < 20) {
      lines.push('DECODE: glibc BROKEN (instant return, <20ms)');
    } else if (elapsed < 100) {
      lines.push('DECODE: usleep(50ms) worked (glibc ok), pid%10=0 or similar, socket not tested yet');
    } else if (elapsed < 1000) {
      var pidDigit = Math.round((elapsed - 50) / 100);
      lines.push('DECODE: glibc ok, pid%10 ~= ' + pidDigit);
    } else if (elapsed >= 1000 && elapsed < 3000) {
      var sockErrno = Math.round((elapsed - 1000) / 10);
      lines.push('DECODE: socket FAILED, errno ~= ' + sockErrno + ' (' + errnoName(sockErrno) + ')');
    } else if (elapsed >= 3000) {
      lines.push('DECODE: socket SUCCEEDED!');
    }

    if (socketData) {
      lines.push('socket_data: ' + socketData.trim());
    }

    var body = lines.join('\n') + '\n=== END ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe20.txt', body); } catch(e) {}

    var pullSrv = http.createServer(function(req, res) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end(body);
    });
    pullSrv.listen(8093, '127.0.0.1', function() {});
    pullSrv.on('error', function(e) {});
    setInterval(function() {}, 60000);
  }, 300);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe20-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}

function errnoName(n) {
  var names = {1:'EPERM',2:'ENOENT',9:'EBADF',11:'EAGAIN',12:'ENOMEM',
               13:'EACCES',22:'EINVAL',23:'ENFILE',24:'EMFILE',111:'ECONNREFUSED',
               110:'ETIMEDOUT',113:'EHOSTUNREACH',99:'EADDRNOTAVAIL'};
  return names[n] || '?';
}
