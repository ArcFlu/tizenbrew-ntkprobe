// v18 - diag-glibc.node: test glibc syscall paths, capture via sdb dlog
// Pull server port 8091 — results come via dlog, not this server
try {
  var net = require('net');
  var http = require('http');
  var fs = require('fs');
  var lines = ['=== diag-glibc v18 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/diag-glibc.node';

  // Start probe receiver on 7778 (addon may connect here)
  var probeData = '';
  var probeServer = net.createServer(function(c) {
    c.on('data', function(d) { probeData += d.toString(); });
    c.on('end', function() { probeServer.close(); });
  });
  probeServer.on('error', function(e) {
    lines.push('probe_server_err: ' + e.message);
  });

  probeServer.listen(7778, '127.0.0.1', function() {
    lines.push('probe_server: ready');
    try {
      require(addonPath);
      lines.push('addon: loaded OK');
    } catch(e) {
      lines.push('addon: threw: ' + String(e.message || e));
    }
  });

  // Check for files the addon may have written
  setTimeout(function() {
    var filePaths = [
      '/opt/usr/home/owner/share/tmp/sdk_tools/diag_probe.txt',
      '/home/owner/share/tmp/sdk_tools/diag_probe.txt',
      '/home/owner/share/tmp/sdk_tools/diag_probe2.txt',
      '/tmp/diag_probe3.txt'
    ];
    filePaths.forEach(function(p) {
      try {
        var c = fs.readFileSync(p, 'utf8');
        lines.push('FILE_FOUND ' + p + ': ' + c.trim());
      } catch(e) {
        lines.push('FILE_MISSING ' + p);
      }
    });

    if (probeData) {
      lines.push('socket_data: ' + probeData.trim());
    } else {
      lines.push('socket_data: none');
    }

    var body = lines.join('\n') + '\n=== END ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe18.txt', body); } catch(e) {}

    var srv = http.createServer(function(req, res) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end(body);
    });
    srv.listen(8091, '127.0.0.1', function() {});
    srv.on('error', function(e) {});
    setInterval(function() {}, 60000);
  }, 3000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe18-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
