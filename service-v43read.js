(function() {
  var fs = require('fs');
  var http = require('http');
  var probe = '', pwn = '';
  try { probe = fs.readFileSync('/home/owner/share/tmp/sdk_tools/tbprobe43.txt', 'utf8'); } catch(e) { probe = 'err:' + e.message; }
  try { pwn   = fs.readFileSync('/tmp/pwn.txt', 'utf8'); } catch(e) { pwn = 'err:' + e.message; }
  var body = '[tbprobe43]\n' + probe + '\n[pwn.txt]\n' + pwn + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe43read.txt', body); } catch(e) {}
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(8128, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
