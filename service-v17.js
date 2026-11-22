// v17 - socket-based probe: addon connects back to JS TCP server on 7778
// No file I/O - avoids Tizen sandbox filesystem restrictions
// Pull server port 8090
try {
  var net = require('net');
  var http = require('http');
  var fs = require('fs');
  var lines = ['=== mmap-sock probe v17 ==='];
  var probeResult = '';

  var addonPath = '/home/owner/share/tmp/sdk_tools/mmap-sock.node';

  // Start probe receiver first, then require addon inside the callback
  var probeServer = net.createServer(function(c) {
    c.on('data', function(d) { probeResult += d.toString(); });
    c.on('end', function() { probeServer.close(); });
    c.on('error', function(e) { probeResult += '\nsocket_err: ' + e.message; });
  });

  probeServer.listen(7778, '127.0.0.1', function() {
    lines.push('probe_server: listening on 7778');
    try {
      require(addonPath);
      lines.push('addon: loaded OK (or threw after connecting)');
    } catch(e) {
      lines.push('addon: threw: ' + String(e.message || e));
    }
  });

  probeServer.on('error', function(e) {
    lines.push('probe_server_err: ' + e.message);
  });

  // Give the probe 3 seconds to connect and finish, then start pull server
  setTimeout(function() {
    if (probeResult) {
      lines.push('--- probe output ---');
      lines.push(probeResult.trim());
    } else {
      lines.push('probe: no data received');
    }

    var body = lines.join('\n') + '\n=== END ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe17.txt', body); } catch(e) {}

    var srv = http.createServer(function(req, res) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end(body + '\n[live: ' + (probeResult ? probeResult.trim() : 'no probe data') + ']');
    });
    srv.listen(8090, '127.0.0.1', function() {});
    srv.on('error', function(e) {});
    setInterval(function() {}, 60000);
  }, 3000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe17-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
