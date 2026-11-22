(function() {
  var fs = require('fs');
  var http = require('http');
  var PORT = 8129;
  var paths = [
    '/home/owner/share/tmp/sdk_tools/tbprobe44e.txt',
    '/home/owner/share/tmp/sdk_tools/tbprobe44c.txt',
    '/home/owner/share/tmp/sdk_tools/tbprobe44b.txt',
    '/tmp/tbprobe44c.txt'
  ];
  var body = '';
  paths.forEach(function(p) {
    var v = '(missing)';
    try { v = fs.readFileSync(p, 'utf8'); } catch(e) { v = 'err:' + e.message; }
    body += '=== ' + p.replace('/home/owner/share/tmp/sdk_tools/', '') + ' ===\n' + v + '\n';
  });
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(PORT, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
