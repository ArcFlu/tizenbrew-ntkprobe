// v13 - Load hello-probe.node, check if constructor wrote file
// Pull server port 8086
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew constructor probe v13 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  var paths = [
    '/home/owner/share/tmp/sdk_tools/hello_probe.txt',
    '/tmp/hello_probe.txt'
  ];

  try {
    require(addonPath);
    lines.push('addon: loaded OK');
  } catch(e) {
    lines.push('addon: threw: ' + String(e.message || e));
  }

  var i;
  for (i = 0; i < paths.length; i++) {
    try {
      var content = fs.readFileSync(paths[i], 'utf8');
      lines.push('FOUND ' + paths[i] + ': ' + content.trim());
    } catch(e) {
      lines.push('NOT FOUND ' + paths[i] + ': ' + String(e.message));
    }
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe13.txt', body); } catch(e) {}

  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8086, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe13-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
