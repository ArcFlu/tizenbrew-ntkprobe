// service-soundjson.js — read sound JSON schemas + wbs settings table
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');
var fs = require('fs');

var PORT = 8185;
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
      setTimeout(function() { process.exit(0); }, 500);
    });
    srv.listen(PORT, '0.0.0.0');
    // safety exit after 60s even if never fetched
    setTimeout(function() { process.exit(0); }, 60000);
  }
}

function run(key, cmd) {
  cp.exec(cmd, {timeout: 10000}, function(err, stdout, stderr) {
    finish(key, (err ? ('ERR:' + (stderr || err.message) + '\n') : '') + stdout);
  });
}

var BASE = '/usr/apps/settings-datafw/res/jsons/tv/';

// Read sound-related JSON schema files directly
try { finish('sound_json',         fs.readFileSync(BASE + 'sound.json', 'utf8')); }
catch(e) { finish('sound_json', 'ERR:' + e.message); }

try { finish('sound_expert_json',  fs.readFileSync(BASE + 'sound-expert-settings.json', 'utf8')); }
catch(e) { finish('sound_expert_json', 'ERR:' + e.message); }

try { finish('system_json',        fs.readFileSync(BASE + 'system.json', 'utf8')); }
catch(e) { finish('system_json', 'ERR:' + e.message); }

// wbs settings table — look for audio/sound/install keys
run('wbs_settings',
  'sqlite3 /opt/usr/apps/wbs/data/.pref.db/Private.db "SELECT * FROM settings WHERE key LIKE \'%nse%\' OR key LIKE \'%install%\' OR key LIKE \'%mount%\' OR key LIKE \'%sound%\' OR key LIKE \'%filter%\' OR key LIKE \'%audio%\' OR key LIKE \'%dnse%\';" 2>&1; ' +
  'sqlite3 /usr/apps/wbs/data/.pref.db/DecisionMaking.db "SELECT * FROM settings WHERE key LIKE \'%nse%\' OR key LIKE \'%install%\' OR key LIKE \'%mount%\' OR key LIKE \'%sound%\' OR key LIKE \'%filter%\' OR key LIKE \'%audio%\' OR key LIKE \'%dnse%\';" 2>&1');

// wbs settings — dump all keys to see what's in there
run('wbs_all_keys',
  'sqlite3 /opt/usr/apps/wbs/data/.pref.db/Private.db "SELECT key FROM settings LIMIT 60;" 2>&1');

// system-expert-settings.json (may have TV placement / installation type)
try { finish('sys_expert_json', fs.readFileSync(BASE + 'system-expert-settings.json', 'utf8')); }
catch(e) {
  try { finish('sys_expert_json', fs.readFileSync(BASE + 'expert-settings.json', 'utf8')); }
  catch(e2) { finish('sys_expert_json', 'ERR:' + e2.message); }
}
