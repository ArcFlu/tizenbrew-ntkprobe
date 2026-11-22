// v6 - HTTP POST callback on port 8080 (TV network policy usually allows HTTP)
try {
  const fs = require('fs');
  const http = require('http');

  const lines = ['=== TizenBrew probe v6 ==='];
  lines.push('node: ' + (typeof process !== 'undefined' ? process.version : 'unknown'));

  for (const dev of ['/dev/ntksys', '/dev/ntkhdma', '/dev/sdp_mem']) {
    try {
      const fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS fd=' + fd);
      fs.closeSync(fd);
    } catch(e) { lines.push(dev + ': ' + e.message.slice(0,50)); }
  }

  try { lines.push(fs.readFileSync('/proc/self/status','utf8').split('\n').slice(0,10).join('\n')); }
  catch(e) { lines.push('status: ' + e.message); }

  try { lines.push('cmdline: ' + fs.readFileSync('/proc/cmdline','utf8').trim()); }
  catch(e) {}

  // Also try exec
  try {
    const { spawnSync } = require('child_process');
    const r = spawnSync('/bin/id', [], { timeout: 3000 });
    lines.push('id: ' + (r.stdout ? r.stdout.toString().trim() : 'no output') + ' err:' + (r.stderr ? r.stderr.toString().trim() : ''));
  } catch(e) { lines.push('exec: ' + e.message.slice(0,60)); }

  const body = lines.join('\n') + '\n=== DONE ===\n';
  fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe6.txt', body);

  // HTTP POST to Mac
  const req = http.request({
    hostname: '192.168.0.241',
    port: 8080,
    path: '/',
    method: 'POST',
    headers: { 'Content-Length': Buffer.byteLength(body), 'Content-Type': 'text/plain' }
  }, (res) => {
    res.resume();
  });
  req.on('error', (e) => {
    fs.appendFileSync('/home/owner/share/tmp/sdk_tools/tbprobe6.txt', '\nHTTP_ERR: ' + e.message);
  });
  req.write(body);
  req.end();

  setInterval(() => {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe6-crash.txt', e.stack || e.message); } catch(e2) {}
}
