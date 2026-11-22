(function() {
  'use strict';
  var fs   = require('fs');
  var http = require('http');
  var cp   = require('child_process');
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe44d.txt';
  var PORT  = 8128;
  var maps = '', err1 = '', wasB = '', err2 = '', cpOk = 'ok';
  try { maps = fs.readFileSync('/proc/self/maps', 'utf8').split('\n').length + ' lines'; }
  catch(e) { err1 = e.message; }
  try { wasB = '0x' + (fs.readFileSync('/bin/wasutility')[0x7e4b] & 0xff).toString(16); }
  catch(e) { err2 = e.message; }
  try { cp.execSync('echo hi', {timeout:1000}); } catch(e) { cpOk = e.message; }
  var body = 'maps=' + maps + ' err=' + err1 + '\nwasByte=' + wasB + ' err=' + err2 + '\ncp=' + cpOk + '\n=== END ===\n';
  try { fs.writeFileSync(PROBE, body); } catch(e) {}
  var srv = http.createServer(function(req, res) { res.end(body); });
  srv.listen(PORT, '127.0.0.1');
  srv.on('error', function(){});
  setInterval(function(){}, 60000);
})();
