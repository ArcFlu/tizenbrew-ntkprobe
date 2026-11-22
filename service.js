// v16 - Load mmap-libc.node (arm-linux-gnueabihf / glibc, no raw syscalls)
// Tests /dev/sdp_mem mmap via proper libc wrappers
// Pull server port 8089
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== mmap-libc probe v16 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/mmap-libc.node';
  var probePaths = [
    '/home/owner/share/tmp/sdk_tools/mmap_libc.txt',
    '/tmp/mmap_libc.txt'
  ];

  try {
    require(addonPath);
    lines.push('addon: loaded OK');
  } catch(e) {
    lines.push('addon: threw: ' + String(e.message || e));
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

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe16.txt', body); } catch(e) {}

  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8089, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe16-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
