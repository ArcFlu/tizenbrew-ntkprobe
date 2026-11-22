// v11 - UEP probe: try loading pushed exploit.node, report result
// Pull server on port 8084
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew UEP probe v11 ==='];

  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';

  // Check if file exists first
  try {
    var st = fs.statSync(addonPath);
    lines.push('exploit.node: found, size=' + st.size + ', mode=' + st.mode.toString(8));
  } catch(e) {
    lines.push('exploit.node: stat failed: ' + String(e.message));
  }

  // Try loading it
  try {
    var addon = require(addonPath);
    lines.push('exploit.node: LOADED! exports=' + JSON.stringify(Object.keys(addon)));
    lines.push('UEP: PASS - dlopen succeeded');
  } catch(e) {
    lines.push('exploit.node: require error: ' + String(e.message || e));
    // UEP would show "Operation not permitted" or similar
    // "undefined symbol" means dlopen worked but ABI mismatch -> UEP PASS
    lines.push('UEP: ' + (String(e.message).indexOf('ermit') >= 0 ? 'BLOCK' : 'PASS (abi/sym mismatch)'));
  }

  // Also check /dev/sdp_mem ioctl possibilities
  try {
    var memFd = fs.openSync('/dev/sdp_mem', 'r+');
    lines.push('/dev/sdp_mem: open ok, fd=' + memFd);
    fs.closeSync(memFd);
  } catch(e) {
    lines.push('/dev/sdp_mem: ' + String(e.message));
  }

  // Check /proc/self/maps to understand our address space
  try {
    var maps = fs.readFileSync('/proc/self/maps', 'utf8');
    lines.push('/proc/self/maps (2KB):\n' + maps.slice(0, 2000));
  } catch(e) {}

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe11.txt', body); } catch(e) {}

  var pullServer = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullServer.listen(8084, '127.0.0.1', function() {});
  pullServer.on('error', function(e) {});

  setInterval(function() {}, 60000);

} catch(e) {
  try {
    require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe11-crash.txt', String(e.stack || e.message));
  } catch(e2) {}
}
