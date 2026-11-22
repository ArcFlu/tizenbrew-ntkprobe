// v36 - probe CallCommand type sigs + ps_umount full introspect
// Pull server: 8119
try {
  var cp = require('child_process');
  var http = require('http');
  var fs = require('fs');
  var res = {};
  var total = 0, done_count = 0;

  function finish(key, val) {
    res[key] = String(val).substring(0, 600);
    done_count++;
    if (done_count >= total) flush();
  }

  function flush() {
    var body = Object.keys(res).map(function(k){ return '[' + k + ']: ' + res[k]; }).join('\n') + '\n=== LIVE ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe36.txt', body); } catch(e) {}
    var srv = http.createServer(function(req, resp) {
      resp.writeHead(200, {'Content-Type': 'text/plain'});
      resp.end(body);
    });
    srv.listen(8119, '127.0.0.1', function(){});
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }

  function dbus(key, dest, path, method, args) {
    total++;
    var cmd = 'dbus-send --system --print-reply --dest=' + dest + ' "' + path + '" ' + method + (args ? ' ' + args : '') + ' 2>&1';
    cp.exec(cmd, {timeout: 10000}, function(err, out) {
      finish(key, out || String(err));
    });
  }

  var MKDEST = 'com.safe.ps_mknod';
  var MKPATH = '/com/safe/ps_mknod';
  var MKIFACE = 'com.safe.ps_mknod';

  var UMDEST = 'com.safe.ps_umount';

  // 1. ps_umount full path introspect
  dbus('um_root',       UMDEST, '/',                  'org.freedesktop.DBus.Introspectable.Introspect', '');
  dbus('um_com',        UMDEST, '/com',                'org.freedesktop.DBus.Introspectable.Introspect', '');
  dbus('um_com_safe',   UMDEST, '/com/safe',           'org.freedesktop.DBus.Introspectable.Introspect', '');
  dbus('um_full',       UMDEST, '/com/safe/ps_umount', 'org.freedesktop.DBus.Introspectable.Introspect', '');

  // 2. Try calling ps_umount methods (to understand framework pattern)
  dbus('um_cc_noargs',  UMDEST, '/com/safe/ps_umount', UMDEST + '.CallCommand',  '');
  dbus('um_cc_str1',    UMDEST, '/com/safe/ps_umount', UMDEST + '.CallCommand',  'string:"umount"');
  dbus('um_cc_2str',    UMDEST, '/com/safe/ps_umount', UMDEST + '.CallCommand',  'string:"umount" string:"/tmp"');

  // 3. CallCommand type sig variations on ps_mknod
  // Try: no args
  dbus('mk_cc_noargs',  MKDEST, MKPATH, MKIFACE + '.CallCommand', '');
  // Try: two strings (subcmd + arg)
  dbus('mk_cc_2str',    MKDEST, MKPATH, MKIFACE + '.CallCommand', 'string:"mknod" string:"/tmp/m36"');
  dbus('mk_cc_2str_b',  MKDEST, MKPATH, MKIFACE + '.CallCommand', 'string:"make_node" string:"/tmp/m36"');
  // Try: string + uint32 x3 (path, mode, major, minor)
  dbus('mk_cc_suu',     MKDEST, MKPATH, MKIFACE + '.CallCommand', 'string:"/tmp/m36c" uint32:33188 uint32:1 uint32:1');
  // Try: string + int32 x3
  dbus('mk_cc_sii',     MKDEST, MKPATH, MKIFACE + '.CallCommand', 'string:"/tmp/m36c" int32:33188 int32:1 int32:1');
  // Try: just 4 uint32s (no path, mode + major + minor + flags)
  dbus('mk_cc_4u',      MKDEST, MKPATH, MKIFACE + '.CallCommand', 'uint32:33188 uint32:1 uint32:1 uint32:0');
  // Try: uint32:0 (some index)
  dbus('mk_cc_u0',      MKDEST, MKPATH, MKIFACE + '.CallCommand', 'uint32:0');
  // Try: int32:0
  dbus('mk_cc_i0',      MKDEST, MKPATH, MKIFACE + '.CallCommand', 'int32:0');
  // Try: boolean
  dbus('mk_cc_bool',    MKDEST, MKPATH, MKIFACE + '.CallCommand', 'boolean:true');

  // 4. Try other unknown method names on ps_mknod
  dbus('mk_MakeNode',   MKDEST, MKPATH, MKIFACE + '.MakeNode',    'string:"/tmp/m36c" uint32:33188 uint32:1 uint32:1');
  dbus('mk_DeviceMake', MKDEST, MKPATH, MKIFACE + '.DeviceMake',  'string:"/tmp/m36c" uint32:33188 uint32:1 uint32:1');
  dbus('mk_NodeCreate', MKDEST, MKPATH, MKIFACE + '.NodeCreate',  'string:"/tmp/m36c" uint32:33188 uint32:1 uint32:1');
  dbus('mk_Do',         MKDEST, MKPATH, MKIFACE + '.Do',          'string:"id"');
  dbus('mk_Run',        MKDEST, MKPATH, MKIFACE + '.Run',         'string:"id"');
  dbus('mk_Exec',       MKDEST, MKPATH, MKIFACE + '.Exec',        'string:"id"');

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe36-crash.txt', String(e.stack||e.message).substring(0,500)); } catch(e2){}
}
