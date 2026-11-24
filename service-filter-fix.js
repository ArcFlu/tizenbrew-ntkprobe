// service-filter-fix.js — force installation filter type via numid + factory key scan
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');

var PORT = 8180;
var results = {};
var total = 6;
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

// Try setting by numid (68 = dnse filter, 194 = dtv filter)
run('cset_numid_dnse',  'amixer -D hw:0 cset numid=68 0 2>&1');
run('cset_numid_dtv',   'amixer -D hw:0 cset numid=194 0 2>&1');

// Verify after short delay
setTimeout(function() {
  run('verify_numid', 'amixer -D hw:0 cget numid=68 2>&1 && amixer -D hw:0 cget numid=194 2>&1');
}, 2000);

// Factory service: scan GetStrItem 0-50 for audio/installation keys
setTimeout(function() {
  var INNER = [
    'var cp = require("child_process");',
    'var out = [];',
    'for (var k = 0; k <= 50; k++) {',
    '  var r = cp.spawnSync("gdbus", ["call","--system","-d","org.tizen.tv.factory-service","-o","/TIFacSerObj","-m","org.tizen.tv.factoryservice.GetStrItem",String(k)], {timeout:2000});',
    '  var s = (r.stdout||new Buffer(0)).toString().trim();',
    '  if (s && s !== "(\\x27\\x27,)" && s !== "(\\'\\',)") out.push(k+":"+s);',
    '}',
    'process.stdout.write(JSON.stringify(out));'
  ].join('\n');
  cp.execFile(process.execPath, ['-e', INNER], {timeout: 15000}, function(err, stdout, stderr) {
    finish('factory_str_items', err ? ('ERR:' + (stderr || err.message)) : stdout);
  });
}, 500);

// Factory service: GetFString for display/audio related types
setTimeout(function() {
  run('factory_fstring', 'for t in 0 1 2 3 4 5 6 7 8 9 10; do echo -n "GetFString($t): "; gdbus call --system -d org.tizen.tv.factory-service -o /TIFacSerObj -m org.tizen.tv.factoryservice.GetFString $t 2>&1; done');
}, 1000);

// Also check org.tizen.tv.avoc (Audio/Video Output Control) - appeared in dbus listing
run('avoc_introspect', 'gdbus call --system -d org.tizen.tv.avoc -o / -m org.freedesktop.DBus.Introspect 2>&1 | head -c 2000');
