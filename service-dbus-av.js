// service-dbus-av.js — introspect Samsung AV+config D-Bus interfaces
// ES5 only: Node v4.4.3

var http = require('http');
var cp = require('child_process');

var PORT = 8182;
var results = {};
var total = 7;
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
    finish(key, (err ? ('ERR:' + (stderr || err.message) + '\n') : '') + stdout);
  });
}

// Samsung TV service interfaces — introspect the ones most likely to have DNSE/audio methods
run('avcontrol',  'gdbus call --system -d com.samsung.IAVControl -o / -m org.freedesktop.DBus.Introspect 2>&1 | head -c 4000');
run('configapp',  'gdbus call --system -d com.samsung.IConfigApp -o / -m org.freedesktop.DBus.Introspect 2>&1 | head -c 4000');
run('iservice',   'gdbus call --system -d com.samsung.IService -o / -m org.freedesktop.DBus.Introspect 2>&1 | head -c 4000');
run('iutil',      'gdbus call --system -d com.samsung.IUtil -o / -m org.freedesktop.DBus.Introspect 2>&1 | head -c 4000');

// Factory service SetParameter — sweep keys 0-20
// (GetItem keys 12,14-25 returned success; SetParameter may control install filter)
run('factory_setparam_read', 'for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do echo -n "SetParam($k,0): "; gdbus call --system -d org.tizen.tv.factory-service -o /TIFacSerObj -m org.tizen.tv.factoryservice.SetParameter $k 0 2>&1; done');

// Try GetLocalSetStr — may expose TV placement/installation settings
run('factory_localset', 'for k in 0 1 2 3 4 5 6 7 8 9 10; do echo -n "GetLocalSetStr($k): "; gdbus call --system -d org.tizen.tv.factory-service -o /TIFacSerObj -m org.tizen.tv.factoryservice.GetLocalSetStr $k 2>&1; done');

// Find any settings files for DNSE/audio config
run('settings_db', 'find /opt/usr/data -name "*.db" -o -name "*.conf" -o -name "*setting*" -o -name "*dnse*" -o -name "*audio*" 2>/dev/null | head -30; ls /opt/usr/data/ 2>/dev/null');
