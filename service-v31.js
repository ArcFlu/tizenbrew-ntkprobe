// v31 - deviced introspect, com.safe.ps_mknod/umount, execFile cp label test
// Pull server: 8112
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe31.txt';
  var PORT = 8112;
  var lines = ['=== probe v31 ===', 'started: ' + new Date().toISOString()];
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
  function run(label, cmd, timeout, limit) {
    limit = limit || 3000;
    cp.exec(cmd+' 2>&1',{timeout:timeout||8000},function(err,stdout){
      var out=(stdout||'').trim();
      if(!out&&err) out=String(err.message||err.code||'').substring(0,200);
      lines.push('['+label+']: '+out.substring(0,limit));
      save();
    });
  }

  // --- C1: deviced (the one that responded in v29 as dbus_i_3) ---
  run('deviced_root', 'dbus-send --system --print-reply --type=method_call --dest=org.tizen.system.deviced / org.freedesktop.DBus.Introspectable.Introspect', 6000, 4000);
  run('deviced_org',  'dbus-send --system --print-reply --type=method_call --dest=org.tizen.system.deviced /Org org.freedesktop.DBus.Introspectable.Introspect', 6000, 4000);

  // --- C2: com.safe.ps_mknod - what can it do? ---
  run('psmknod_root', 'dbus-send --system --print-reply --type=method_call --dest=com.safe.ps_mknod / org.freedesktop.DBus.Introspectable.Introspect', 6000, 4000);
  run('psmknod_props', 'dbus-send --system --print-reply --dest=com.safe.ps_mknod / org.freedesktop.DBus.Properties.GetAll string:""', 5000, 2000);

  // --- C3: com.safe.ps_umount ---
  run('psumount_root', 'dbus-send --system --print-reply --type=method_call --dest=com.safe.ps_umount / org.freedesktop.DBus.Introspectable.Introspect', 6000, 4000);

  // --- C4: more interesting D-Bus services ---
  run('bms_root',    'dbus-send --system --print-reply --type=method_call --dest=com.samsung.bms.service / org.freedesktop.DBus.Introspectable.Introspect', 5000, 3000);
  run('vddmr_root',  'dbus-send --system --print-reply --type=method_call --dest=com.samsung.tizen.vddmr / org.freedesktop.DBus.Introspectable.Introspect', 5000, 3000);
  run('uifw_root',   'dbus-send --system --print-reply --type=method_call --dest=com.uifw / org.freedesktop.DBus.Introspectable.Introspect', 5000, 3000);

  // --- A3: direct execFile test (bypass sh - does cp get _ label?) ---
  // Use cp.execFile to run /bin/cp directly (not through sh)
  // Then try to execFile the result - if exec works, it has _ label
  var testSrc = '/bin/true'; // small binary
  var testDst = '/home/owner/share/tmp/sdk_tools/test_execfile_v31';
  cp.execFile('/bin/cp', [testSrc, testDst], {timeout: 3000}, function(cpErr, cpOut) {
    if (cpErr) {
      lines.push('[execfile_cp]: cp failed: ' + String(cpErr.message||cpErr.code||'').substring(0,100));
      save(); return;
    }
    lines.push('[execfile_cp]: cp succeeded, file at ' + testDst);
    save();
    // Now try to exec the copied file directly (not through sh)
    cp.execFile(testDst, [], {timeout: 2000}, function(exErr, exOut) {
      if (exErr && (exErr.code === 'EACCES' || (exErr.message && exErr.message.indexOf('EACCES') >= 0))) {
        lines.push('[execfile_test]: EACCES - still our label (Option A dead even with execFile)');
      } else if (exErr) {
        lines.push('[execfile_test]: err=' + String(exErr.message||exErr.code).substring(0,100));
      } else {
        lines.push('[execfile_test]: SUCCESS - execFile works! execFile creates _ labeled files');
      }
      save();
    });
  });

  // --- D2: JIT page - correct dd offset calculation ---
  // Page 3aa0a000 from v29 maps. Use printf to calc exact byte offset
  var pid = process.pid;
  run('jit_maps_now', 'grep -E "rwxp.*00:00" /proc/' + pid + '/maps | head -5', 3000, 500);

  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe31-crash.txt',
    String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
