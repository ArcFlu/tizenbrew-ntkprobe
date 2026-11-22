// v39read - serve tbprobe39.txt + chrome-sandbox result
// Pull server: 8123
try {
  var fs = require('fs');
  var http = require('http');
  var body = '';
  try { body = fs.readFileSync('/home/owner/share/tmp/sdk_tools/tbprobe39.txt', 'utf8'); } catch(e) { body = 'no file: ' + e.message; }
  try { body += '\n[r39_check]: ' + fs.readFileSync('/tmp/r39.txt', 'utf8'); } catch(e) { body += '\n[r39_check]: not found'; }
  var srv = http.createServer(function(req, res) { res.writeHead(200); res.end(body); });
  srv.listen(8123, '127.0.0.1', function(){});
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
} catch(e) {}
