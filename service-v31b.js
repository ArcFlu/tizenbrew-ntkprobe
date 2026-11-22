// v31b - minimal: only deviced + ps_mknod D-Bus introspect, no execFile
// Pull server: 8113
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe31b.txt';
  var PORT = 8113;
  var lines = ['=== probe v31b ===', 'started: ' + new Date().toISOString()];
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
      lines.push('['+label+']: '+out.substring(0,3000));
      save();
    });
  }
  run('deviced_root', 'dbus-send --system --print-reply --type=method_call --dest=org.tizen.system.deviced / org.freedesktop.DBus.Introspectable.Introspect', 6000);
  run('deviced_org',  'dbus-send --system --print-reply --type=method_call --dest=org.tizen.system.deviced /Org org.freedesktop.DBus.Introspectable.Introspect', 6000);
  run('psmknod_root', 'dbus-send --system --print-reply --type=method_call --dest=com.safe.ps_mknod / org.freedesktop.DBus.Introspectable.Introspect', 6000);
  run('psumount_root','dbus-send --system --print-reply --type=method_call --dest=com.safe.ps_umount / org.freedesktop.DBus.Introspectable.Introspect', 6000);
  run('jit_maps',     'grep -E "rwxp.*00:00" /proc/' + process.pid + '/maps | head -5', 3000);
  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe31b-crash.txt',
    String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
