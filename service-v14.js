// v14 - Load regfunc-probe.node, check results
// node_register_module_v46 does the work directly when called by Node.js
// Pull server port 8087
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew regfunc probe v14 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  var probePaths = [
    '/home/owner/share/tmp/sdk_tools/sdpmem_probe.txt',
    '/tmp/sdpmem_probe.txt'
  ];

  try {
    require(addonPath);
    lines.push('addon: loaded OK');
  } catch(e) {
    lines.push('addon: threw: ' + String(e.message || e));
    lines.push('(node_register_module_v46 ran before this throw)');
  }

  var i;
  for (i = 0; i < probePaths.length; i++) {
    try {
      var c = fs.readFileSync(probePaths[i], 'utf8');
      lines.push('FOUND ' + probePaths[i] + ':');
      lines.push(c.trim());
    } catch(e) {
      lines.push('NOT FOUND ' + probePaths[i]);
    }
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe14.txt', body); } catch(e) {}

  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8087, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe14-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
