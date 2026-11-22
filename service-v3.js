// v3 - no network, write to disk, keep process alive
try {
  const fs = require('fs');
  const path = '/home/owner/share/tmp/sdk_tools/tbprobe.txt';

  const lines = ['=== TizenBrew probe v3 ==='];

  // Basic identity
  try { lines.push('process.version: ' + process.version); } catch(e) { lines.push('process: ' + e); }
  try { lines.push('pid: ' + process.pid); } catch(e) {}

  // Module availability
  for (const m of ['fs','net','http','https','child_process','os']) {
    try { require(m); lines.push(m + ': OK'); }
    catch(e) { lines.push(m + ': FAIL'); }
  }

  // ntksys check
  try {
    const fd = fs.openSync('/dev/ntksys', 'r+');
    lines.push('/dev/ntksys: EXISTS fd=' + fd);
    fs.closeSync(fd);
  } catch(e) { lines.push('/dev/ntksys: ' + e.message); }

  // Write to known path
  fs.writeFileSync(path, lines.join('\n') + '\n');

  // Keep service alive so we can trigger v4 for network test
  setInterval(() => {}, 60000);

} catch(e) {
  // If even fs fails, try writing to /tmp
  try {
    require('fs').writeFileSync('/tmp/tbprobe.txt', 'CRASH: ' + e.message);
  } catch(e2) {}
}
