// v9 - Adds pull HTTP server on port 8082 so results can be fetched via SDB forward
// Node.js v4 compat (no for...of, no const in loops, no arrow funcs in for)
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew probe v9 (pull-server) ==='];
  var devs = ['/dev/ntksys', '/dev/ntkhdma', '/dev/sdp_mem', '/dev/mem'];
  var i, dev, fd;

  for (i = 0; i < devs.length; i++) {
    dev = devs[i];
    try {
      fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS fd=' + fd);
      fs.closeSync(fd);
    } catch(e) {
      lines.push(dev + ': ' + String(e.message).slice(0, 60));
    }
  }

  // /proc/self/maps first 4KB
  try {
    var maps = fs.readFileSync('/proc/self/maps', 'utf8');
    lines.push('/proc/self/maps (4KB):\n' + maps.slice(0, 4000));
  } catch(e) { lines.push('maps: ' + e.message); }

  // Try loading pushed .node addon if present
  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  try {
    var addonStat = fs.statSync(addonPath);
    lines.push('exploit.node: found (' + addonStat.size + ' bytes)');
    var addon = require(addonPath);
    lines.push('exploit.node: loaded! exports=' + JSON.stringify(Object.keys(addon)));
    var result = addon.exploit ? String(addon.exploit()) : 'no exploit export';
    lines.push('exploit.node: result=' + result);
  } catch(e) {
    lines.push('exploit.node: ' + String(e.message).slice(0, 120));
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe9.txt', body); } catch(e) {}

  // Pull server: GET / on port 8082 returns results
  var pullServer = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullServer.listen(8082, '127.0.0.1', function() {
    lines.push('pull-server: listening on 127.0.0.1:8082');
  });
  pullServer.on('error', function(e) {
    lines.push('pull-server: ' + e.message);
  });

  // Also POST back to Mac in case server is running
  var req2 = http.request({
    hostname: '192.168.0.241', port: 8080, path: '/', method: 'POST',
    headers: { 'Content-Length': Buffer.byteLength(body), 'Content-Type': 'text/plain' }
  }, function(res) { res.resume(); });
  req2.on('error', function(e) {});
  req2.write(body);
  req2.end();

  setInterval(function() {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe9-crash.txt', String(e.stack || e.message)); } catch(e2) {}
}
