// v10 - Extended device probe: all SDP devices + mmap test + /proc checks
// Node.js v4 compat
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== TizenBrew probe v10 (extended) ==='];

  // All SDP device paths to check
  var devs = [
    '/dev/sdp_pqe_fdet',
    '/dev/sdp_pqe_mcde',
    '/dev/sdp_dip',
    '/dev/sdp_vdec',
    '/dev/sdp_venc',
    '/dev/sdp_mem',
    '/dev/sdp_drm',
    '/dev/sdp_osd',
    '/dev/sdp_scaler',
    '/dev/sdp_tvp',
    '/dev/ntksys',
    '/dev/ntkhdma',
    '/dev/mem',
    '/dev/kmem',
    '/dev/ptmx',
  ];

  var i, dev, fd;
  for (i = 0; i < devs.length; i++) {
    dev = devs[i];
    try {
      fd = fs.openSync(dev, 'r+');
      lines.push(dev + ': EXISTS fd=' + fd);
      fs.closeSync(fd);
    } catch(e) {
      lines.push(dev + ': ' + String(e.message).slice(0, 70));
    }
  }

  // Check /proc/self/mem writability
  try {
    var memFd = fs.openSync('/proc/self/mem', 'r+');
    lines.push('/proc/self/mem: WRITABLE fd=' + memFd);
    fs.closeSync(memFd);
  } catch(e) {
    lines.push('/proc/self/mem: ' + String(e.message).slice(0, 70));
  }

  // Check /proc/sysrq-trigger
  try {
    var sysrqStat = fs.statSync('/proc/sysrq-trigger');
    lines.push('/proc/sysrq-trigger: mode=' + sysrqStat.mode.toString(8));
  } catch(e) {
    lines.push('/proc/sysrq-trigger: ' + String(e.message).slice(0, 50));
  }

  // Check setuid binaries in key paths
  var binDirs = ['/bin', '/usr/bin', '/sbin', '/usr/sbin'];
  var setuidBins = [];
  for (i = 0; i < binDirs.length; i++) {
    try {
      var entries = fs.readdirSync(binDirs[i]);
      var j;
      for (j = 0; j < entries.length; j++) {
        try {
          var binPath = binDirs[i] + '/' + entries[j];
          var binStat = fs.statSync(binPath);
          // mode 0x800 = setuid
          if (binStat.mode & 0x800) {
            setuidBins.push(binPath + ' (mode=' + binStat.mode.toString(8) + ')');
          }
        } catch(e2) {}
      }
    } catch(e) {}
  }
  if (setuidBins.length > 0) {
    lines.push('setuid_bins: ' + setuidBins.join(', '));
  } else {
    lines.push('setuid_bins: none found');
  }

  // Check /proc/self/status for capabilities
  try {
    var status = fs.readFileSync('/proc/self/status', 'utf8');
    var capLines = status.split('\n').filter(function(l) {
      return l.match(/^(Uid|Gid|Cap)/);
    });
    lines.push('/proc/self/status:\n' + capLines.join('\n'));
  } catch(e) {}

  // Try loading a pushed .node addon if present
  var addonPath = '/home/owner/share/tmp/sdk_tools/exploit.node';
  try {
    var addonStat = fs.statSync(addonPath);
    lines.push('exploit.node: found (' + addonStat.size + ' bytes)');
    var addon = require(addonPath);
    lines.push('exploit.node: loaded! exports=' + JSON.stringify(Object.keys(addon)));
    var result = addon.exploit ? String(addon.exploit()) : 'no exploit export';
    lines.push('exploit.node: result=' + result);
  } catch(e) {
    lines.push('exploit.node: ' + String(e.message).slice(0, 120));
  }

  var body = lines.join('\n') + '\n=== DONE ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe10.txt', body); } catch(e) {}

  // Pull server on port 8083 (8082 used by v9)
  var pullServer = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullServer.listen(8083, '127.0.0.1', function() {});
  pullServer.on('error', function(e) {});

  setInterval(function() {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe10-crash.txt', String(e.stack || e.message)); } catch(e2) {}
}
