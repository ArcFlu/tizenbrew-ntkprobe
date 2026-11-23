(function() {
  'use strict';
  var fs  = require('fs');
  var http= require('http');
  var cp  = require('child_process');
  var PORT  = 8135;
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe48h.txt';
  function w(s){try{fs.appendFileSync(PROBE,s+'\n');}catch(e){}}
  try{fs.writeFileSync(PROBE,'v48h:start\n');}catch(e){}

  var CMDS = [
    'uname -a',
    'id',
    'ls -la /bin/wasutility',
    'cat /proc/self/smack 2>/dev/null || echo no_smack_self',
    'cat /proc/1/smack 2>/dev/null || echo no_smack_1',
    'cat /proc/self/attr/current 2>/dev/null || echo no_attr',
    'ls /proc/self/attr/ 2>/dev/null',
    'getfattr -n security.SMACK64 /bin/wasutility 2>/dev/null || echo no_smack_attr',
    'which python python3 python2 perl lua 2>/dev/null || echo no_scripting',
    'find /bin /usr/bin /usr/sbin /sbin -perm -4000 -type f 2>/dev/null | head -20',
    'ls -la /bin/ 2>/dev/null | head -30',
    'mount | grep " /bin"',
    'cat /proc/mounts | grep -E "(squash|read-only|ro[,)])"',
    'ls /dev/mem 2>/dev/null || echo no_devmem',
    'dd if=/bin/wasutility bs=1 skip=32331 count=4 2>/dev/null | xxd || echo dd_fail',
    'ls /proc/sys/kernel/dmesg_restrict 2>/dev/null && cat /proc/sys/kernel/dmesg_restrict'
  ];

  var results = {};
  var pending = CMDS.length;

  function done(key, val) {
    results[key] = val.trim();
    if (--pending === 0) flush();
  }

  CMDS.forEach(function(cmd) {
    cp.exec(cmd, {timeout: 5000}, function(err, out, err2) {
      done(cmd, (out||'') + (err2||'') + (err?' [exit:'+err.code+']':''));
    });
  });

  function flush() {
    var body = 'v48h:discovery\n';
    CMDS.forEach(function(cmd) { body += '$ ' + cmd + '\n' + results[cmd] + '\n---\n'; });
    body += '=== END ===\n';
    fs.writeFileSync(PROBE, body);
    var srv = http.createServer(function(req,res){res.end(body);});
    srv.listen(PORT,'127.0.0.1');
    srv.on('error',function(){});
    setInterval(function(){},60000);
  }
})();
