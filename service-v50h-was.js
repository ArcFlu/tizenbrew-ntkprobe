(function() {
  'use strict';
  var fs  = require('fs');
  var http= require('http');
  var cp  = require('child_process');
  var PORT  = 8138;
  var PROBE = '/home/owner/share/tmp/sdk_tools/tbprobe50h.txt';
  function w(s){try{fs.appendFileSync(PROBE,s+'\n');}catch(e){}}
  try{fs.writeFileSync(PROBE,'v50h:start\n');}catch(e){}

  // Extract strings near offset 0x7e4b in wasutility
  function wasStringsNearTarget() {
    var buf; try{buf=fs.readFileSync('/usr/bin/wasutility');}catch(e){return 'err:'+e.message;}
    var OFFSET = 0x7e4b;
    // Find printable strings in a window around the target offset
    var start = Math.max(0, OFFSET - 0x200);
    var end = Math.min(buf.length, OFFSET + 0x200);
    var r = [], cur = '', curStart = -1;
    for (var i = start; i < end; i++) {
      var c = buf[i];
      if (c >= 0x20 && c < 0x7f) { if (curStart < 0) curStart = i; cur += String.fromCharCode(c); }
      else { if (cur.length >= 4) r.push('0x'+(curStart).toString(16)+': '+cur); cur=''; curStart=-1; }
    }
    // Also read the bytes 0x7e44-0x7e54 as hex
    var hexBytes = '';
    for (var j = OFFSET-7; j < OFFSET+8; j++) hexBytes += (buf[j]<16?'0':'')+buf[j].toString(16)+' ';
    return 'bytes[0x7e44..0x7e54]:'+hexBytes+'\n'+r.join('\n');
  }

  // All wasutility printable strings with length >= 5
  function wasAllStrings() {
    var buf; try{buf=fs.readFileSync('/usr/bin/wasutility');}catch(e){return 'err:'+e.message;}
    var r=[], cur='', curStart=-1;
    for(var i=0;i<buf.length;i++){
      var c=buf[i];
      if(c>=0x20&&c<0x7f){if(curStart<0)curStart=i;cur+=String.fromCharCode(c);}
      else{if(cur.length>=5){r.push('0x'+curStart.toString(16)+':'+cur);}cur='';curStart=-1;}
    }
    // Filter to interesting ones
    return r.filter(function(s){
      return /exec|cmd|root|shell|argv|getenv|system|popen|-[a-zA-Z]|%s|setuid|fork|\/bin|\/sbin|\/usr|\.sh|sql|db|SELECT|INSERT/i.test(s);
    }).join('\n');
  }

  var TOTAL = 6;
  var done = 0;
  var results = {};
  function finish(key, val) { results[key]=val; if(++done>=TOTAL) flush(); }

  finish('was_near_0x7e4b', wasStringsNearTarget());
  finish('was_interesting', wasAllStrings());

  cp.exec('/usr/bin/wasutility 2>&1; echo EXIT:$?', {timeout:4000}, function(e,o,e2){ finish('was_noargs',(o||'')+(e2||'')); });
  cp.exec('/usr/bin/wasutility --help 2>&1; echo EXIT:$?', {timeout:4000}, function(e,o,e2){ finish('was_help',(o||'')+(e2||'')); });
  cp.exec('/usr/bin/wasutility -h 2>&1; echo EXIT:$?', {timeout:4000}, function(e,o,e2){ finish('was_h',(o||'')+(e2||'')); });
  // Check writable dirs
  cp.exec('find /opt /home /tmp -writable -type d 2>/dev/null | head -20', {timeout:5000}, function(e,o,e2){ finish('writable_dirs',(o||'')+(e2||'')); });

  function flush() {
    var body = 'v50h:was+args\n';
    Object.keys(results).forEach(function(k){ body += '=== '+k+' ===\n'+results[k]+'\n'; });
    body += '=== END ===\n';
    fs.writeFileSync(PROBE, body);
    var srv = http.createServer(function(req,res){res.end(body);});
    srv.listen(PORT,'127.0.0.1');
    srv.on('error',function(){});
    setInterval(function(){},60000);
  }
})();
