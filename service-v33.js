// v33 - deviced Process+Core introspect, ps_mknod/umount /com/safe
// Pull server: 8116
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe33.txt';
  var PORT = 8116;
  var BASE = '/Org/Tizen/System/DeviceD';
  var DEV  = 'org.tizen.system.deviced';
  var lines = ['=== probe v33 ===', 'started: ' + new Date().toISOString()];
  function save() {
    try { fs.writeFileSync(OUT, lines.join('\n') + '\n=== END ===\n'); } catch(e) {}
  }
  var srv = http.createServer(function(req, res) {
    res.writeHead(200,{'Content-Type':'text/plain'});
    res.end(lines.join('\n')+'\n=== LIVE ===\n');
  });
  srv.listen(PORT,'127.0.0.1',function(){});
  srv.on('error',function(){});
  setInterval(function(){},60000);
  function run(label, cmd, timeout) {
    cp.exec(cmd+' 2>&1',{timeout:timeout||8000},function(err,stdout){
      var out=(stdout||'').trim();
      if(!out&&err) out=String(err.message||err.code||'').substring(0,200);
      lines.push('['+label+']: '+out.substring(0,5000));
      save();
    });
  }
  function dbus(label, dest, path) {
    run(label, 'dbus-send --system --print-reply --type=method_call --dest=' + dest +
      ' ' + path + ' org.freedesktop.DBus.Introspectable.Introspect', 6000);
  }

  // deviced: Process and Core are the most promising
  dbus('deviced_Process', DEV, BASE + '/Process');
  dbus('deviced_Core',    DEV, BASE + '/Core');
  dbus('deviced_SysNoti', DEV, BASE + '/SysNoti');
  dbus('deviced_Display', DEV, BASE + '/Display');

  // ps_mknod: try /com/safe and /com/safe/ps_mknod children
  dbus('psmknod_comsafe',   'com.safe.ps_mknod',  '/com/safe');
  dbus('psumount_comsafe',  'com.safe.ps_umount', '/com/safe');

  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe33-crash.txt',
    String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
