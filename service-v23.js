// v23 - process tree, all setuid binaries, RunningAppsService analysis, wasutility parent bypass
// Pull server port 8097 (probe), 8098 (RunningAppsService binary)
try {
  var cp    = require('child_process');
  var fs    = require('fs');
  var http  = require('http');
  var lines = ['=== process-tree v23 ==='];

  // ---- 1. Full PPID chain ----
  function readStatus(pid) {
    try {
      var s = fs.readFileSync('/proc/' + pid + '/status', 'utf8');
      var ppid = 0, uid = 0, name = '';
      s.split('\n').forEach(function(l) {
        if (l.indexOf('PPid:') === 0) ppid = parseInt(l.split('\t')[1]);
        if (l.indexOf('Uid:') === 0) uid = parseInt(l.split('\t')[1]);
        if (l.indexOf('Name:') === 0) name = l.split('\t')[1].trim();
      });
      return { pid: pid, ppid: ppid, uid: uid, name: name };
    } catch(e) { return null; }
  }

  function readExe(pid) {
    try { return fs.readlinkSync('/proc/' + pid + '/exe'); } catch(e) { return '?'; }
  }

  var selfPid = parseInt(cp.execSync('cat /proc/self/status | grep "^Pid:" | awk \'{print $2}\'', {encoding:'utf8'}).trim());
  lines.push('self_pid: ' + selfPid);

  var chain = [];
  var cur = selfPid;
  for (var i = 0; i < 20; i++) {
    var info = readStatus(cur);
    if (!info || info.pid === 0) break;
    info.exe = readExe(cur);
    chain.push(info);
    if (info.ppid === 0 || info.ppid === cur) break;
    cur = info.ppid;
  }
  lines.push('ppid_chain: ' + JSON.stringify(chain));

  // ---- 2. Find webappservice PID and UID ----
  try {
    var pids = fs.readdirSync('/proc').filter(function(p) { return /^\d+$/.test(p); });
    var wasvc = pids.map(function(p) {
      try {
        var exe = fs.readlinkSync('/proc/' + p + '/exe');
        if (exe.indexOf('webappservice') !== -1) {
          var info = readStatus(parseInt(p));
          return { pid: parseInt(p), exe: exe, uid: info ? info.uid : -1 };
        }
      } catch(e) {}
      return null;
    }).filter(Boolean);
    lines.push('webappservice_procs: ' + JSON.stringify(wasvc));

    // Can we write to webappservice's mem?
    if (wasvc.length > 0) {
      var wspid = wasvc[0].pid;
      try {
        var fd = fs.openSync('/proc/' + wspid + '/mem', 'r+');
        lines.push('webappservice_mem_rw: OK! ' + wspid);
        fs.closeSync(fd);
      } catch(e) { lines.push('webappservice_mem_rw: ' + String(e.code||e.message)); }
    }
  } catch(e) { lines.push('webappservice_find: ' + String(e.code||e.message)); }

  // ---- 3. All setuid binaries on the system ----
  var searchDirs = ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/system/bin',
                    '/usr/local/bin', '/opt/usr/bin'];
  var allSuid = [];
  searchDirs.forEach(function(d) {
    try {
      fs.readdirSync(d).forEach(function(b) {
        try {
          var s = fs.statSync(d + '/' + b);
          if (s.mode & 0o4000) allSuid.push(d + '/' + b + '(uid=' + s.uid + ',mode=' + s.mode.toString(8) + ')');
        } catch(e2) {}
      });
    } catch(e) {}
  });
  lines.push('all_suid: ' + allSuid.join(', '));

  // ---- 4. RunningAppsService analysis ----
  var rasBuf = null;
  try {
    rasBuf = fs.readFileSync('/bin/RunningAppsService');
    lines.push('ras_read: ' + rasBuf.length + ' bytes');
    var rasStrings = [];
    var cur2 = '';
    for (var j = 0; j < rasBuf.length; j++) {
      var c = rasBuf[j];
      if (c >= 0x20 && c <= 0x7e) { cur2 += String.fromCharCode(c); }
      else {
        if (cur2.length >= 5) rasStrings.push(cur2);
        cur2 = '';
      }
    }
    var rasInteresting = rasStrings.filter(function(s) {
      return s.indexOf('/') === 0 || s.indexOf('system') !== -1 || s.indexOf('exec') !== -1 ||
             s.indexOf('popen') !== -1 || s.indexOf('%s') !== -1 || s.indexOf('PATH') !== -1 ||
             s.indexOf('parent') !== -1 || s.indexOf('author') !== -1 || s.indexOf('ppid') !== -1 ||
             s.indexOf('PPID') !== -1 || (s.length > 25 && s.indexOf(' ') !== -1);
    });
    lines.push('ras_interesting: ' + JSON.stringify(rasInteresting.slice(0,50)));

    // Serve RunningAppsService on port 8098
    var rasSrv = http.createServer(function(req, res) {
      res.writeHead(200, {'Content-Type': 'application/octet-stream', 'Content-Length': rasBuf.length});
      res.end(rasBuf);
    });
    rasSrv.listen(8098, '127.0.0.1', function() {});
    rasSrv.on('error', function(e) {});
  } catch(e) { lines.push('ras_read: ' + String(e.code||e.message)); }

  // ---- 5. Try wasutility invoked with correct-looking PPID scenario ----
  // Test: does wasutility do anything with -a (activate) flag? Maybe it activates an app
  var wasActivate = cp.spawnSync('/bin/wasutility', ['-a', 'org.tizen.test'], {timeout: 2000});
  lines.push('was_-a: status=' + wasActivate.status +
    ' out=' + ((wasActivate.stdout||'').toString()+(wasActivate.stderr||'').toString()).trim().substring(0,80));

  // Try -v (uninstall) with a fake app ID
  var wasV = cp.spawnSync('/bin/wasutility', ['-v', 'com.fake.test'], {timeout: 2000});
  lines.push('was_-v: status=' + wasV.status +
    ' out=' + ((wasV.stdout||'').toString()+(wasV.stderr||'').toString()).trim().substring(0,80));

  // Try -e (not sure what it does)
  var wasE = cp.spawnSync('/bin/wasutility', ['-e', 'test'], {timeout: 2000});
  lines.push('was_-e: status=' + wasE.status +
    ' out=' + ((wasE.stdout||'').toString()+(wasE.stderr||'').toString()).trim().substring(0,80));

  // ---- 6. Node.js process maps for GOT overwrite planning ----
  var maps = fs.readFileSync('/proc/self/maps', 'utf8');
  var addonLine = maps.split('\n').filter(function(l) {
    return l.indexOf('timing-probe.node') !== -1 || l.indexOf('mmap-libc.node') !== -1;
  });
  lines.push('addon_maps: ' + JSON.stringify(addonLine));
  // Also get libc text base and r/w segments
  var libcLines = maps.split('\n').filter(function(l) { return l.indexOf('libc-2.24.so') !== -1; });
  lines.push('libc_maps: ' + JSON.stringify(libcLines));

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe23.txt', body); } catch(e) {}

  var pullSrv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  pullSrv.listen(8097, '127.0.0.1', function() {});
  pullSrv.on('error', function(e) {});
  setInterval(function() {}, 60000);

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe23-crash.txt', String(e.stack||e.message)); } catch(e2) {}
}
