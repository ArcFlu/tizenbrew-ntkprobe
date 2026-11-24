// service-audio.js — Audio quality probe for QN55Q6FNA
// ES5 only: Node v4.4.3; no const/let/arrow/template literals
var http = require('http');
var cp = require('child_process');

var PORT = 8178;
var results = {};
var total = 10;
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
    results._port = PORT;
  }
}

function run(key, cmd) {
  cp.exec(cmd, {timeout: 8000}, function(err, stdout, stderr) {
    finish(key, err ? ('ERR:' + (stderr || err.message)) : stdout);
  });
}

// PulseAudio state
run('pa_info',         'pactl info 2>&1');
run('pa_sinks',        'pactl list sinks 2>&1');
run('pa_sink_inputs',  'pactl list sink-inputs 2>&1');

// ALSA state
run('asound_cards',    'cat /proc/asound/cards 2>&1');
run('asound_pcm',      'cat /proc/asound/pcm 2>&1');
run('amixer',          'amixer contents 2>&1');

// D-Bus: list services that mention audio/sound/av/media
run('dbus_audio_svcs', 'gdbus call --system -d org.freedesktop.DBus -o /org/freedesktop/DBus -m org.freedesktop.DBus.ListNames 2>&1');

// D-Bus: AV manager introspection (may reveal volume/eq/mode methods)
run('dbus_avmgr',      'gdbus call --system -d org.tizen.tv.avmanager -o / -m org.freedesktop.DBus.Introspect 2>&1');

// Factory service: query a range of string items (sound mode, night mode, etc)
// Key 0 is often a menu-category root; key strings vary by firmware
run('factory_items',   'for k in 0 1 2 3 4 5 6 7 8 9 10 50 100; do echo -n "GetItem($k): "; gdbus call --system -d org.tizen.tv.factory-service -o /TIFacSerObj -m org.tizen.tv.factoryservice.GetItem $k 2>&1; done');

// Sound-related settings paths
run('settings_paths',  'ls /opt/usr/data/avmanager/ 2>/dev/null; ls /opt/usr/data/sound/ 2>/dev/null; ls /usr/etc/sound/ 2>/dev/null; find /opt/usr/data -name "*.conf" -o -name "*sound*" -o -name "*audio*" 2>/dev/null | head -20');
