// v7 - http-only callback, no child_process (child_process causes crash)
try {
  const fs = require('fs');
  const http = require('http');

  const lines = ['=== TizenBrew probe v7 ==='];
  lines.push('node: ' + process.version);

  for (const dev of ['/dev/ntksys', '/dev/ntkhdma', '/dev/sdp_mem', '/dev/mem']) {
    try {
      const fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS fd=' + fd);
      fs.closeSync(fd);
    } catch(e) { lines.push(dev + ': ' + e.message.slice(0,60)); }
  }

  try { lines.push(fs.readFileSync('/proc/self/status','utf8').split('\n').slice(0,12).join('\n')); }
  catch(e) { lines.push('status: ' + e.message); }

  try { lines.push('cmdline: ' + fs.readFileSync('/proc/cmdline','utf8').trim()); }
  catch(e) {}

  try { lines.push('version: ' + fs.readFileSync('/proc/version','utf8').trim()); }
  catch(e) {}

  const body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe7.txt', body); } catch(e) {}

  // HTTP POST to Mac
  const req = http.request({
    hostname: '192.168.0.241',
    port: 8080,
    path: '/',
    method: 'POST',
    headers: { 'Content-Length': Buffer.byteLength(body), 'Content-Type': 'text/plain' }
  }, (res) => { res.resume(); });

  req.on('error', (e) => {
    try { fs.appendFileSync('/home/owner/share/tmp/sdk_tools/tbprobe7.txt', '\nHTTP_ERR: ' + e.message + ' code=' + e.code); } catch(e2) {}
  });
  req.write(body);
  req.end();

  setInterval(() => {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe7-crash.txt', e.stack || e.message); } catch(e2) {}
}
