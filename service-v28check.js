// v28check - read tbprobe28 output file and serve it
// Pull server: 8109
try {
  var fs = require('fs');
  var http = require('http');
  var body = '';
  try { body = fs.readFileSync('/home/owner/share/tmp/sdk_tools/tbprobe28.txt', 'utf8'); }
  catch(e) { body = 'tbprobe28.txt not found: ' + String(e.code||e.message) + '\n'; }
  try { body += '\ncrash: ' + fs.readFileSync('/home/owner/share/tmp/sdk_tools/tbprobe28-crash.txt', 'utf8'); }
  catch(e) { body += '\n(no crash file)\n'; }
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'}); res.end(body);
  });
  srv.listen(8109, '127.0.0.1', function(){});
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
} catch(e) {}
