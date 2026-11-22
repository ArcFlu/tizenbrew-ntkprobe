// v32 - drill deeper into deviced /Org/Tizen, ps_mknod /com, ps_umount /com
// Pull server: 8114
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe32.txt';
  var PORT = 8114;
  var lines = ['=== probe v32 ===', 'started: ' + new Date().toISOString()];
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
      lines.push('['+label+']: '+out.substring(0,4000));
      save();
    });
  }
  function dbus(label, dest, path) {
    run(label, 'dbus-send --system --print-reply --type=method_call --dest=' + dest +
      ' ' + path + ' org.freedesktop.DBus.Introspectable.Introspect', 6000);
  }

  // deviced tree: / -> /Org -> /Org/Tizen -> ?
  dbus('deviced_tizen',      'org.tizen.system.deviced', '/Org/Tizen');

  // ps_mknod tree: / -> /com -> ?
  dbus('psmknod_com',        'com.safe.ps_mknod',  '/com');

  // ps_umount tree: / -> /com -> ?
  dbus('psumount_com',       'com.safe.ps_umount', '/com');

  // Also try common Samsung path patterns directly
  dbus('deviced_full',       'org.tizen.system.deviced', '/Org/Tizen/System/DeviceD');
  dbus('psmknod_safe',       'com.safe.ps_mknod',  '/com/safe/ps_mknod');
  dbus('psumount_safe',      'com.safe.ps_umount', '/com/safe/ps_umount');

  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe32-crash.txt',
    String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
