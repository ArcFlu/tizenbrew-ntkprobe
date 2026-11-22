// v30 - full writable-rootfs, sysman D-Bus introspect, dbus names full, sh label check
// Pull server: 8111
try {
  var fs   = require('fs');
  var cp   = require('child_process');
  var http = require('http');
  var OUT  = '/home/owner/share/tmp/sdk_tools/tbprobe30.txt';
  var PORT = 8111;
  var lines = ['=== probe v30 ===', 'started: ' + new Date().toISOString()];
  function save() {
    try { fs.writeFileSync(OUT, lines.join('\n') + '\n=== END ===\n'); } catch(e) {}
  }
  var srv = http.createServer(function(req, res) {
    // support ?key=X to fetch one entry
    var key = (req.url || '').replace('/?key=','').replace('/','');
    if (key && key.length > 2) {
      var found = '';
      lines.forEach(function(l){ if(l.indexOf('['+key+']')===0) found = l; });
      res.writeHead(200,{'Content-Type':'text/plain'});
      res.end(found || 'not yet\n');
    } else {
      res.writeHead(200,{'Content-Type':'text/plain'});
      res.end(lines.join('\n')+'\n=== LIVE ===\n');
    }
  });
  srv.listen(PORT,'127.0.0.1',function(){});
  srv.on('error',function(){});
  setInterval(function(){},60000);

  function run(label, cmd, timeout, limit) {
    limit = limit || 2000;
    cp.exec(cmd+' 2>&1',{timeout:timeout||8000},function(err,stdout){
      var out=(stdout||'').trim();
      if(!out&&err) out=String(err.message||err.code||'').substring(0,200);
      lines.push('['+label+']: '+out.substring(0,limit));
      save();
    });
  }

  // --- A: full writable rootfs dirs (2000 chars limit) ---
  run('writable_rootfs_full', 'find /bin /lib /usr /opt /sbin /etc /system /firmware -maxdepth 6 -type d -writable', 20000, 2000);
  run('writable_rootfs_root', 'find / -maxdepth 3 -type d -writable -not -path "/proc/*" -not -path "/sys/*"', 15000, 2000);

  // --- A2: Smack label of files created by child shell ---
  // If sh's SMACK64EXEC=_ then child-created files get _ label
  run('sh_smack_label', 'sh -c "cat /proc/$$/attr/current"', 3000, 200);
  run('cp_smack_check', 'cp /bin/sh /tmp/tbtest_cp_v30 2>&1; cat /proc/self/attr/fscreate; ls -la /tmp/tbtest_cp_v30; rm -f /tmp/tbtest_cp_v30', 5000, 300);

  // --- B: D-Bus full names list ---
  run('dbus_names_full', 'dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>&1', 8000, 3000);

  // --- C: sysman /Org introspect ---
  run('sysman_org', 'dbus-send --system --print-reply --type=method_call --dest=org.tizen.system.sysman /Org org.freedesktop.DBus.Introspectable.Introspect', 5000, 3000);
  // also try the root path
  run('sysman_root', 'dbus-send --system --print-reply --type=method_call --dest=org.tizen.system.sysman / org.freedesktop.DBus.Introspectable.Introspect', 5000, 3000);

  // --- C2: Samsung TVService D-Bus introspect ---
  run('tvs_root', 'dbus-send --system --print-reply --type=method_call --dest="com.samsung.TVService.Signal.tvs1.tvs321" / org.freedesktop.DBus.Introspectable.Introspect', 5000, 2000);

  // --- D: JIT page probe: read first 16 bytes of smallest rwx page ---
  // Page 3aa0a000-3aa0b000 (4KB): read first 16 bytes from /proc/self/mem
  run('jit_page_read', 'dd if=/proc/' + process.pid + '/mem bs=16 count=1 skip=$((0x3aa0a000/16)) 2>/dev/null | xxd | head -2', 5000, 200);

  save();
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe30-crash.txt',
    String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
