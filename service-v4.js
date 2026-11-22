// v4 - network callback + exec test
try {
  const fs = require('fs');
  const net = require('net');
  const { execSync } = require('child_process');

  const BEACON = '192.168.0.241';
  const PORT = 4444;

  const lines = ['=== TizenBrew ntksys probe v4 ==='];

  // Module check
  for (const m of ['fs','net','http','https','child_process','os']) {
    try { require(m); lines.push(m + ': OK'); }
    catch(e) { lines.push(m + ': FAIL - ' + e.message.slice(0,60)); }
  }

  // ntksys devices
  for (const dev of ['/dev/ntksys', '/dev/ntkhdma', '/dev/sdp_mem', '/dev/mem']) {
    try {
      const fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS (fd=' + fd + ')');
      fs.closeSync(fd);
    } catch(e) { lines.push(dev + ': ' + e.message); }
  }

  // Process identity + cmdline
  try { lines.push('/proc/self/status:\n' + fs.readFileSync('/proc/self/status','utf8').split('\n').slice(0,12).join('\n')); }
  catch(e) { lines.push('status: ' + e.message); }
  try { lines.push('cmdline: ' + fs.readFileSync('/proc/cmdline','utf8').trim()); }
  catch(e) {}

  // exec test - signed system binary
  try {
    lines.push('exec id: ' + execSync('id', { timeout: 3000 }).toString().trim());
    lines.push('uname: ' + execSync('uname -a', { timeout: 3000 }).toString().trim());
  } catch(e) { lines.push('exec: FAIL - ' + e.message.slice(0,80)); }

  // Send back via TCP
  const sock = new net.Socket();
  sock.setTimeout(8000);
  sock.connect(PORT, BEACON, () => {
    sock.write(lines.join('\n') + '\n=== DONE ===\n');
    sock.end();
  });
  sock.on('error', (e) => {
    // If TCP fails, write to disk
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe4.txt', lines.join('\n') + '\nNET_ERR: ' + e.message + '\n'); } catch(e2) {}
  });
  sock.on('timeout', () => sock.destroy());

  setInterval(() => {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe4-crash.txt', e.stack || e.message); } catch(e2) {}
}
