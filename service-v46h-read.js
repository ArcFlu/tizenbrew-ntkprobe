(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var PORT = 8134;
  var FILES = [
    '/home/owner/share/tmp/sdk_tools/tbprobe46h.txt',
    '/home/owner/share/tmp/sdk_tools/tbprobe45h.txt',
    '/tmp/pwn.txt'
  ];
  var body = '';
  FILES.forEach(function(f) {
    body += '=== ' + f + ' ===\n';
    try { body += fs.readFileSync(f, 'utf8'); } catch(e) { body += 'MISSING: ' + e.message; }
    body += '\n';
  });
  // Also check wasutility byte
  try {
    var b = fs.readFileSync('/bin/wasutility')[0x7e4b];
    body += 'wasByte=0x' + (b & 0xff).toString(16) + '\n';
  } catch(e) { body += 'wasByte:err\n'; }
  body += '=== END ===\n';
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(PORT, '127.0.0.1');
  srv.on('error', function(e) { body += 'PORT_ERR:' + e.message + '\n'; });
  setInterval(function() {}, 60000);
})();
