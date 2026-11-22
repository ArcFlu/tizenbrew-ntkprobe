(function() {
  var fs = require('fs');
  var http = require('http');
  var body = '';
  ['tbprobe45b.txt','tbprobe44.txt'].forEach(function(f) {
    try { body += '[' + f + ']\n' + fs.readFileSync('/home/owner/share/tmp/sdk_tools/' + f, 'utf8') + '\n'; }
    catch(e) { body += '[' + f + '] ' + e.code + '\n'; }
  });
  body += '=== END ===\n';
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(8132, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
