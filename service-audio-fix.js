// service-audio-fix.js — Fix audio quality issues on QN55Q6FNA
// Issues: installation filter WALL3 on a stand TV; spdif gain=0
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');

var PORT = 8179;
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
  cp.exec(cmd, {timeout: 8000}, function(err, stdout, stderr) {
    finish(key, err ? ('ERR:' + (stderr || err.message)) : stdout);
  });
}

// Fix 1: Installation filter type — was WALL TYPE GROUP 3, should be GROUP 0 (stand/neutral)
run('fix_dnse_filter',  "amixer -D hw:0 cset name='dnse dtv installation filter type' 0 2>&1");
run('fix_dtv_filter',   "amixer -D hw:0 cset name='dtv installation filter type' 0 2>&1");

// Fix 2: SPDIF out gain — was 0, restore to default 9 (matches spdif raw gain)
run('fix_spdif_gain',   "amixer -D hw:0 cset name='spdif out gain' 9 2>&1");

// Verify: re-read all three after a short delay
setTimeout(function() {
  run('verify_filters',  "amixer -D hw:0 cget name='dnse dtv installation filter type' 2>&1 && amixer -D hw:0 cget name='dtv installation filter type' 2>&1");
  run('verify_spdif',   "amixer -D hw:0 cget name='spdif out gain' 2>&1");
  run('verify_speaker', "amixer -D hw:0 cget name='speaker out gain' 2>&1 && amixer -D hw:0 cget name='main out gain' 2>&1");
}, 1500);
