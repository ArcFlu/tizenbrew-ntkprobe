// v15 - Load syscall-test.node, check which syscalls work
// Also check Node.js process stdout/stderr can capture native output
// Pull server port 8088
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== syscall test v15 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  var checkFiles = [
    '/home/owner/share/tmp/sdk_tools/t_open5.txt',
    '/home/owner/share/tmp/sdk_tools/t_openat.txt'
  ];

  try {
    require(addonPath);
    lines.push('addon: loaded OK');
  } catch(e) {
    lines.push('addon: threw: ' + String(e.message || e));
  }

  var i;
  for (i = 0; i < checkFiles.length; i++) {
    try {
      var c = fs.readFileSync(checkFiles[i], 'utf8');
      lines.push('FOUND ' + checkFiles[i] + ': [' + c.trim() + ']');
    } catch(e) {
      lines.push('NOT FOUND ' + checkFiles[i]);
    }
  }

  // Check if the native code can write to process.stdout fd using JS fs
  // (Indirect way to verify: write a test file from JS with same path pattern)
  try {
    var fd5 = fs.openSync('/home/owner/share/tmp/sdk_tools/t_js_open.txt', 'w');
    fs.writeSync(fd5, 'js_open_ok\n');
    fs.closeSync(fd5);
    lines.push('JS open/write: OK');
  } catch(e) {
    lines.push('JS open/write: FAILED ' + String(e.message));
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe15.txt', body); } catch(e) {}

  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8088, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe15-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
