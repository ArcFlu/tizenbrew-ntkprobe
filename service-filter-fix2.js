// service-filter-fix2.js — numid cset + factory key scan (fixed escaping)
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');

var PORT = 8181;
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

// Try cset by numid (68=dnse filter, 194=dtv filter)
run('cset_numid_dnse',  'amixer -D hw:0 cset numid=68 0 2>&1');
run('cset_numid_dtv',   'amixer -D hw:0 cset numid=194 0 2>&1');

// Verify after delay
setTimeout(function() {
  run('verify', 'amixer -D hw:0 cget numid=68 2>&1 && amixer -D hw:0 cget numid=194 2>&1');
}, 2000);

// avoc introspect (org.tizen.tv.avoc appeared in D-Bus listing)
run('avoc', 'gdbus call --system -d org.tizen.tv.avoc -o / -m org.freedesktop.DBus.Introspect 2>&1 | head -c 3000');

// Factory GetStrItem 0-30 — avoids single-quote in INNER by using fromCharCode
// INNER code uses double-quotes only; compares via charCode
var L = [
  'var cp = require("child_process");',
  'var out = [];',
  'var SQ = String.fromCharCode(39);',
  'var EMPTY = "(" + SQ + SQ + ",)";',
  'for (var k = 0; k <= 30; k++) {',
  '  var r = cp.spawnSync("gdbus", ["call","--system","-d","org.tizen.tv.factory-service","-o","/TIFacSerObj","-m","org.tizen.tv.factoryservice.GetStrItem",String(k)], {timeout:2000});',
  '  var s = (r.stdout||new Buffer(0)).toString().trim();',
  '  if (s && s !== EMPTY) out.push(k + ":" + s);',
  '}',
  'process.stdout.write(JSON.stringify(out));'
];
var INNER = L.join('\n');
setTimeout(function() {
  cp.execFile(process.execPath, ['-e', INNER], {timeout: 20000}, function(err, stdout, stderr) {
    finish('factory_str_items', err ? ('ERR:' + (stderr || err.message)) : stdout);
  });
}, 500);
