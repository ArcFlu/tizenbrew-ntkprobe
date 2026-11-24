// service-verify-fs.js — verify filter state + find settings DB
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');

var PORT = 8183;
var results = {};
var total = 5;
var doneCount = 0;

function finish(key, val) {
  results[key] = typeof val === 'string' ? val.trim() : val;
  doneCount++;
  if (doneCount >= total) {
    var srv = http.createServer(function(req, res) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(results, null, 2));
    });
    srv.listen(PORT, '0.0.0.0');
  }
}

function run(key, cmd) {
  cp.exec(cmd, {timeout: 10000}, function(err, stdout, stderr) {
    finish(key, (err ? ('ERR:' + (stderr || err.message) + '\n') : '') + stdout);
  });
}

// 1. Verify installation filter type is still at 3 (didn't change from SetParameter)
run('filter_check', 'amixer -D hw:0 cget numid=68 2>&1 && amixer -D hw:0 cget numid=194 2>&1');

// 2. SetParameter(key,0) returned success for 0,3,9,12,19 — check what GetItem says for those
run('getitem_check', 'for k in 0 3 9 12 19; do echo -n "GetItem($k): "; gdbus call --system -d org.tizen.tv.factory-service -o /TIFacSerObj -m org.tizen.tv.factoryservice.GetItem $k 2>&1; done');

// 3. Find Samsung settings DB
run('find_settings',
  'find /opt/usr/apps -name "*.db" 2>/dev/null | head -20; ' +
  'find /opt/samsung -name "*.db" 2>/dev/null | head -20; ' +
  'find /usr/apps -name "*.db" 2>/dev/null | head -20; ' +
  'ls /opt/usr/apps/ 2>/dev/null | head -30');

// 4. Look specifically for DNSE/audio-related files anywhere accessible
run('find_dnse',
  'find / -name "*dnse*" -o -name "*installation*filter*" -o -name "*tv_setting*" -o -name "*SoundSetting*" 2>/dev/null | grep -v proc | grep -v sys | head -20');

// 5. Check /opt/usr/apps for Samsung settings apps
run('samsung_apps',
  'ls /opt/usr/apps/ 2>/dev/null; ' +
  'ls /usr/apps/ 2>/dev/null | grep -i "setting\\|sound\\|audio\\|config" | head -20');
