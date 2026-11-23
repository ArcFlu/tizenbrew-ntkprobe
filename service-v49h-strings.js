(function() {
  'use strict';
  var fs  = require('fs');
  var http= require('http');
  var cp  = require('child_process');
  var PORT  = 8137;
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe49h.txt';
  function w(s){try{fs.appendFileSync(PROBE,s+'\n');}catch(e){}}
  try{fs.writeFileSync(PROBE,'v49h:start\n');}catch(e){}

  // Extract printable strings from a binary (like strings(1))
  function extractStrings(path, minLen) {
    minLen = minLen || 6;
    var buf;
    try { buf = fs.readFileSync(path); } catch(e) { return 'READ_ERR:'+e.message; }
    var result = [];
    var current = '';
    for (var i = 0; i < buf.length; i++) {
      var c = buf[i];
      if (c >= 0x20 && c < 0x7f) {
        current += String.fromCharCode(c);
      } else {
        if (current.length >= minLen) result.push(current);
        current = '';
      }
    }
    if (current.length >= minLen) result.push(current);
    // Filter for interesting strings (args, commands, paths, format strings)
    return result.filter(function(s) {
      return /[-_\/]|%s|exec|cmd|root|sudo|shell|sh\b|argv|getenv|system|popen|fork|spawn|setuid|chown/i.test(s) ||
             s.indexOf('/') === 0 ||
             /^-+[a-z]/.test(s);
    }).slice(0, 200).join('\n');
  }

  var TOTAL = 5;
  var done = 0;
  var results = {};

  function finish(key, val) {
    results[key] = val;
    if (++done >= TOTAL) flush();
  }

  // 1. RunningAppsService strings
  finish('RAS_strings', extractStrings('/usr/bin/RunningAppsService', 6));

  // 2. wasutility strings (all, not just interesting)
  finish('was_strings', (function(){
    try{
      var buf=fs.readFileSync('/usr/bin/wasutility');
      var r=[];var cur='';
      for(var i=0;i<buf.length;i++){var c=buf[i];if(c>=0x20&&c<0x7f){cur+=String.fromCharCode(c);}else{if(cur.length>=5)r.push(cur);cur='';}}
      return r.join('\n');
    }catch(e){return 'ERR:'+e.message;}
  })());

  // 3. Run RunningAppsService with no args
  cp.exec('/usr/bin/RunningAppsService 2>&1; echo EXIT:$?', {timeout:5000}, function(e,o,err2){
    finish('RAS_noargs', (o||'')+(err2||''));
  });

  // 4. Run RunningAppsService --help
  cp.exec('/usr/bin/RunningAppsService --help 2>&1; echo EXIT:$?', {timeout:5000}, function(e,o,err2){
    finish('RAS_help', (o||'')+(err2||''));
  });

  // 5. Check /proc/1/cmdline and running root processes
  cp.exec('cat /proc/1/cmdline | tr "\\0" " "; echo; ls /proc/[0-9]*/exe 2>/dev/null | xargs -I{} sh -c "ls -la {} 2>/dev/null" | grep root | head -20', {timeout:5000}, function(e,o,err2){
    finish('root_procs', (o||'')+(err2||''));
  });

  function flush() {
    var body = 'v49h:strings+RAS\n';
    Object.keys(results).forEach(function(k){ body += '=== '+k+' ===\n'+results[k]+'\n'; });
    body += '=== END ===\n';
    fs.writeFileSync(PROBE, body);
    var srv = http.createServer(function(req,res){res.end(body);});
    srv.listen(PORT,'127.0.0.1');
    srv.on('error',function(){});
    setInterval(function(){},60000);
  }
})();
