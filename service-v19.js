// v19 - diag-glibc probe: addon loaded unconditionally, probe server on 7779
// Checks all glibc paths: socket, file I/O, dprintf to stderr
// Pull server port 8092
try {
  var net = require('net');
  var http = require('http');
  var fs = require('fs');
  var lines = ['=== diag-glibc v19 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/diag-glibc.node';
  var socketData = '';

  // Start probe socket server on 7779 (addon will try to connect here)
  var srv7779 = net.createServer(function(c) {
    c.on('data', function(d) { socketData += d.toString(); });
    c.on('end', function() { srv7779.close(); });
  });
  srv7779.on('error', function(e) {
    lines.push('srv7779_err: ' + e.message);
  });
  srv7779.listen(7779, '127.0.0.1', function() {
    lines.push('srv7779: ready');
  });

  // Load addon UNCONDITIONALLY (not inside server callback)
  setTimeout(function() {
    try {
      require(addonPath);
      lines.push('addon: loaded OK');
    } catch(e) {
      lines.push('addon: threw: ' + String(e.message || e));
    }

    // Give socket data 500ms to arrive, then finalize
    setTimeout(function() {
      // Check all possible output files
      var filePaths = [
        '/opt/usr/home/owner/share/tmp/sdk_tools/diag_probe.txt',
        '/home/owner/share/tmp/sdk_tools/diag_probe.txt',
        '/home/owner/share/tmp/sdk_tools/diag_probe2.txt',
        '/tmp/diag_probe3.txt'
      ];
      filePaths.forEach(function(p) {
        try {
          var c = fs.readFileSync(p, 'utf8');
          lines.push('FILE_OK ' + p + ': ' + c.trim());
        } catch(e) {
          lines.push('FILE_MISS ' + p);
        }
      });

      if (socketData) {
        lines.push('SOCKET_DATA: ' + socketData.trim());
      } else {
        lines.push('SOCKET_DATA: none');
      }

      var body = lines.join('\n') + '\n=== END ===\n';
      try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe19.txt', body); } catch(e) {}

      var pullSrv = http.createServer(function(req, res) {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        // Show live socket data too
        res.end(body + '[live_socket: ' + (socketData||'none') + ']\n');
      });
      pullSrv.listen(8092, '127.0.0.1', function() {});
      pullSrv.on('error', function(e) {});
      setInterval(function() {}, 60000);
    }, 500);
  }, 200); // 200ms gives srv7779 time to start

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe19-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
