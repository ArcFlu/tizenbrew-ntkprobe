// v5 - net ONLY, no child_process
// Isolate whether net.Socket works in TizenBrew sandbox
try {
  const fs = require('fs');
  const net = require('net');

  const lines = ['=== TizenBrew probe v5 (net-only) ==='];
  lines.push('node: ' + process.version);

  // ntksys check
  for (const dev of ['/dev/ntksys', '/dev/ntkhdma', '/dev/sdp_mem']) {
    try {
      const fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS fd=' + fd);
      fs.closeSync(fd);
    } catch(e) { lines.push(dev + ': ' + e.message.slice(0,50)); }
  }

  // proc/self/status for uid
  try { lines.push(fs.readFileSync('/proc/self/status','utf8').split('\n').slice(0,10).join('\n')); }
  catch(e) { lines.push('status: ' + e.message); }

  // Write to disk as fallback
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe5.txt', lines.join('\n')); }
  catch(e) {}

  // TCP callback
  const sock = new net.Socket();
  sock.on('error', (e) => {
    try {
      fs.appendFileSync('/home/owner/share/tmp/sdk_tools/tbprobe5.txt', '\nNET_ERR: ' + e.message);
    } catch(e2) {}
  });
  sock.connect(4444, '192.168.0.241', () => {
    sock.write(lines.join('\n') + '\n=== DONE ===\n', () => sock.end());
  });

  setInterval(() => {}, 60000);

} catch(e) {
  try {
    require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe5-crash.txt', (e.stack || e.message));
  } catch(e2) {}
}
