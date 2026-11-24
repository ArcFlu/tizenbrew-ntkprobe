// service-settingsdb.js — explore settings-datafw + wbs pref DB for DNSE/filter
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');

var PORT = 8184;
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

// 1. Find all files in settings-datafw (both paths)
run('settingsfw_ls',
  'ls -la /opt/usr/apps/settings-datafw/ 2>/dev/null; ' +
  'ls -la /usr/apps/settings-datafw/ 2>/dev/null; ' +
  'find /opt/usr/apps/settings-datafw -type f 2>/dev/null; ' +
  'find /usr/apps/settings-datafw -type f 2>/dev/null');

// 2. Check tvs-config which may hold system config including audio
run('tvsconfig_ls',
  'find /opt/usr/apps/tvs-config -type f 2>/dev/null | head -20; ' +
  'find /usr/apps/tvs-config -type f 2>/dev/null | head -20');

// 3. SQLite query on wbs Private.db — look for dnse/sound/install keys
run('wbs_db',
  'sqlite3 /opt/usr/apps/wbs/data/.pref.db/Private.db "SELECT * FROM pref WHERE key LIKE \'%nse%\' OR key LIKE \'%sound%\' OR key LIKE \'%install%\' OR key LIKE \'%mount%\' OR key LIKE \'%filter%\' OR key LIKE \'%audio%\';" 2>&1 | head -40; ' +
  'sqlite3 /usr/apps/wbs/data/.pref.db/DecisionMaking.db ".tables" 2>&1 | head -10');

// 4. Find SQLite DB files in settings-datafw or tvs areas and query them
run('tvs_db_query',
  'find /opt/usr/apps/tvs-config /opt/usr/apps/tvs-ht /opt/usr/apps/tvs-sospec -name "*.db" 2>/dev/null | while read f; do echo "=== $f ==="; sqlite3 "$f" ".tables" 2>/dev/null; done | head -40');

// 5. Look at what easysetup-UI stores (it runs the initial wizard that sets install type)
run('easysetup_data',
  'find /opt/usr/apps/org.tizen.easysetup-UI -type f 2>/dev/null | head -20; ' +
  'find /usr/apps/org.tizen.easysetup-UI -type f 2>/dev/null | head -20; ' +
  'ls /opt/usr/apps/ | grep -i "setting\\|config\\|tvs" 2>/dev/null');

// 6. Try sqlite3 on the homedatacontrol DB which may have all setting keys
run('homedatactl_db',
  'sqlite3 /opt/usr/apps/org.tizen.homedatacontrol-service/data/data.db ".tables" 2>&1; ' +
  'sqlite3 /opt/usr/apps/org.tizen.homedatacontrol-service/data/data.db "SELECT name FROM sqlite_master WHERE type=\'table\';" 2>&1; ' +
  'sqlite3 /opt/usr/apps/org.tizen.homedatacontrol-service/data/data.db "SELECT * FROM Data WHERE key LIKE \'%nse%\' OR key LIKE \'%install%\' OR key LIKE \'%mount%\' OR key LIKE \'%sound%\' OR key LIKE \'%filter%\';" 2>&1 | head -30');
