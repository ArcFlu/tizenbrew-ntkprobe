(function() {
  var fs = require('fs');
  var http = require('http');
  var body = '';
  try { body = fs.readFileSync('/home/owner/share/tmp/sdk_tools/tbprobe44.txt', 'utf8'); }
  catch(e) { body = 'tbprobe44.txt not found: ' + String(e.code||e.message) + '\n'; }
  try { body += '\n[pwn.txt]\n' + fs.readFileSync('/tmp/pwn.txt', 'utf8'); }
  catch(e) { body += '\n[pwn.txt] ' + String(e.code||e.message) + '\n'; }
  body += '\n=== END ===\n';
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(8129, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
