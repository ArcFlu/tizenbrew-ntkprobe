// v12 - Load sdp-mmap-probe.node, then read output file from probe constructor
// Pull server on port 8085
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew sdp_mem mmap probe v12 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  var probePath = '/home/owner/share/tmp/sdk_tools/sdpmem_probe.txt';

  // Load addon — the __attribute__((constructor)) runs at dlopen time
  // and writes to sdpmem_probe.txt before require() returns
  try {
    var addon = require(addonPath);
    lines.push('addon: loaded exports=' + JSON.stringify(Object.keys(addon)));
  } catch(e) {
    lines.push('addon: require threw: ' + String(e.message || e));
    lines.push('(constructor still ran before the throw)');
  }

  // Read probe output file (written by constructor)
  try {
    var probeOut = fs.readFileSync(probePath, 'utf8');
    lines.push('--- sdpmem_probe.txt ---');
    lines.push(probeOut);
  } catch(e) {
    lines.push('probe file missing: ' + String(e.message));
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe12.txt', body); } catch(e) {}

  var pullServer = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullServer.listen(8085, '127.0.0.1', function() {});
  pullServer.on('error', function(e) {});
  setInterval(function() {}, 60000);

} catch(e) {
  try {
    require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe12-crash.txt', String(e.stack || e.message));
  } catch(e2) {}
}
