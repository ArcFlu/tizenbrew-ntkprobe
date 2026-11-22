// v34 - blind method probe on deviced/Process, read ps_mknod binary
// Pull server: 8117
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe34.txt';
  var PORT = 8117;
  var DEV  = 'org.tizen.system.deviced';
  var PROC = '/Org/Tizen/System/DeviceD/Process';
  var MKNOD_DEST = 'com.safe.ps_mknod';
  var MKNOD_PATH = '/com/safe/ps_mknod';
  var lines = ['=== probe v34 ===', 'started: ' + new Date().toISOString()];
  var psmknodBin = null;

  function save() {
    try { fs.writeFileSync(OUT, lines.join('\n') + '\n=== END ===\n'); } catch(e) {}
  }

  // Serve ps_mknod binary at /bin and text at /
  var srv = http.createServer(function(req, res) {
    if (req.url === '/bin' && psmknodBin) {
      res.writeHead(200, {'Content-Type': 'application/octet-stream', 'Content-Length': psmknodBin.length});
      res.end(psmknodBin);
    } else {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      res.end(lines.join('\n') + '\n=== LIVE ===\n');
    }
  });
  srv.listen(PORT,'127.0.0.1',function(){});
  srv.on('error',function(){});
  setInterval(function(){},60000);

  function run(label, cmd, timeout) {
    cp.exec(cmd+' 2>&1',{timeout:timeout||5000},function(err,stdout){
      var out=(stdout||'').trim();
      if(!out&&err) out=String(err.message||err.code||'').substring(0,200);
      lines.push('['+label+']: '+out.substring(0,500));
      save();
    });
  }

  // --- 1: blind method calls on deviced/Process ---
  // If method exists, we get a real response; if not, UnknownMethod error
  ['Launch','Execute','Exec','Run','Spawn','Kill','Signal','GetPid',
   'PidOf','StatusOf','ChangeAffinity','SetAffinity'].forEach(function(meth) {
    run('proc_' + meth,
      'dbus-send --system --print-reply --dest=' + DEV +
      ' ' + PROC + ' org.tizen.system.deviced.Process.' + meth + ' string:"id"', 4000);
  });

  // --- 2: blind method calls on deviced/SysNoti/kernel to probe behavior ---
  // kernel(s, i, s) -> i  -- test with no-op values
  run('sysnoti_kernel_probe',
    'dbus-send --system --print-reply --dest=' + DEV +
    ' /Org/Tizen/System/DeviceD/SysNoti' +
    ' org.tizen.system.deviced.SysNoti.kernel' +
    ' string:"tizen" int32:0 string:"probe"', 5000);

  // --- 3: find and read ps_mknod binary ---
  run('psmknod_find', 'find /usr /bin /sbin -name "ps_mknod" -o -name "*mknod*" 2>/dev/null | head -5', 5000);
  run('psumount_find','find /usr /bin /sbin -name "ps_umount" -o -name "*umount*" 2>/dev/null | head -5', 5000);

  // read ps_mknod binary after find completes
  cp.exec('find /usr /bin /sbin -name "ps_mknod" 2>/dev/null | head -1',
    {timeout:5000}, function(err, stdout) {
    var binPath = (stdout||'').trim();
    if (!binPath) {
      lines.push('[psmknod_bin]: binary not found');
      save(); return;
    }
    lines.push('[psmknod_bin]: found at ' + binPath + ', size=' +
      (function(){ try { return fs.statSync(binPath).size; } catch(e){ return '?'; }}()));
    save();
    try { psmknodBin = fs.readFileSync(binPath); } catch(e) {
      lines.push('[psmknod_bin]: read failed: ' + String(e.code||e.message));
      save();
    }
  });

  // --- 4: check if deviced/Process interface accepts empty call (no args) ---
  run('proc_noarg',
    'dbus-send --system --print-reply --dest=' + DEV +
    ' ' + PROC + ' org.tizen.system.deviced.Process.GetProcessList', 4000);

  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe34-crash.txt',
    String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
