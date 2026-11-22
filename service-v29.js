// v29 - writable rootfs dirs, RunningAppsService async, D-Bus, strings probe
// Pull server: 8110  ALL child_process calls are async
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe29.txt';
  var PORT = 8110;
  var lines = ['=== probe v29 ===', 'started: ' + new Date().toISOString()];
  function save() {
    try { fs.writeFileSync(OUT, lines.join('\n') + '\n=== END ===\n'); } catch(e) {}
  }
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(lines.join('\n') + '\n=== LIVE ===\n');
  });
  srv.listen(PORT, '127.0.0.1', function() {});
  srv.on('error', function() {});
  setInterval(function() {}, 60000);
  function run(label, cmd, timeout) {
    cp.exec(cmd + ' 2>&1', {timeout: timeout || 5000}, function(err, stdout) {
      var out = (stdout || '').trim();
      if (!out && err) out = String(err.message || err.code || '').substring(0, 120);
      lines.push('[' + label + ']: ' + out.substring(0, 400));
      save();
    });
  }
  run('writable_rootfs', 'find /bin /lib /usr /opt /sbin /etc /system /firmware -type d -writable', 15000);
  run('writable_var_tmp', 'find /var /tmp -type d -writable', 5000);
  run('ras_strings', 'strings /usr/bin/RunningAppsService | grep -iE "(-e|-c|-x|exec|spawn|system|popen|help|usage|version|arg|cmd|run)" | head -30', 5000);
  run('ras_stat',    'ls -la /usr/bin/RunningAppsService', 3000);
  var RAS = '/usr/bin/RunningAppsService';
  ['-h', '--help', '--version', '-l', '-e "id"', '-c "id"'].forEach(function(arg, i) {
    run('ras_' + i, RAS + ' ' + arg, 3000);
  });
  run('ras_noarg', RAS, 2000);
  run('dbus_names', 'dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames', 6000);
  ['org.tizen.app.manager','org.tizen.debug_launchpad','org.tizen.launch_app',
   'org.tizen.system.deviced','org.tizen.system.sysman'].forEach(function(dest, i) {
    run('dbus_i_' + i, 'dbus-send --system --print-reply --type=method_call --dest=' + dest +
      ' / org.freedesktop.DBus.Introspectable.Introspect', 3000);
  });
  run('proc_maps_rwx', 'grep rwx /proc/' + process.pid + '/maps | head -10', 3000);
  run('smack_own',  'cat /proc/self/attr/current', 2000);
  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe29-crash.txt',
    String(e.stack || e.message).substring(0, 500)); } catch(e2) {}
}
