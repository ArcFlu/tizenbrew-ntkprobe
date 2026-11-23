'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8151;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe63h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. Check if sqlite3 binary is available, then dump webappservice.db
  'try {',
  '  var r = cp.execSync("which sqlite3 2>&1 || find /usr/bin /usr/local/bin -name sqlite3 2>/dev/null | head -3", {timeout:3000});',
  '  result.sqlite3_path = r.toString().trim();',
  '} catch(e) { result.sqlite3_path_err = e.message; }',

  'try {',
  '  var r2 = cp.execSync("sqlite3 /opt/dbspace/.webappservice.db \'.tables\' 2>&1", {timeout:5000});',
  '  result.db_tables = r2.toString().trim();',
  '} catch(e) { result.db_tables_err = (e.stdout ? e.stdout.toString() : "") + e.message.slice(0,100); }',

  'try {',
  '  var r3 = cp.execSync("sqlite3 /opt/dbspace/.webappservice.db \'SELECT * FROM WASConfigTable LIMIT 20;\' 2>&1", {timeout:5000});',
  '  result.was_config = r3.toString().trim();',
  '} catch(e) { result.was_config_err = e.message.slice(0,100); }',

  'try {',
  '  var r4 = cp.execSync("sqlite3 /opt/dbspace/.webappservice.db \'SELECT ID,VERSION,APPID_LIST,IS_NATIVE FROM EmpsTable LIMIT 20;\' 2>&1", {timeout:5000});',
  '  result.emps_table = r4.toString().trim();',
  '} catch(e) { result.emps_table_err = e.message.slice(0,100); }',

  // Also try the AppBinaryManager DB
  'try {',
  '  var r5 = cp.execSync("sqlite3 /opt/dbspace/.AppBinaryManager.db \'.tables\' 2>&1", {timeout:5000});',
  '  result.appbinmgr_tables = r5.toString().trim();',
  '} catch(e) { result.appbinmgr_tables_err = e.message.slice(0,100); }',

  'try {',
  '  var r6 = cp.execSync("sqlite3 /opt/dbspace/.AppBinaryManager.db \'SELECT * FROM sqlite_master;\' 2>&1", {timeout:5000});',
  '  result.appbinmgr_schema = r6.toString().trim();',
  '} catch(e) { result.appbinmgr_schema_err = e.message.slice(0,100); }',

  // 2. ExecuteUserShell with different format inputs
  'var jcmds = ["0","1","2","10","100",',
  '  "SHELL:id","CMD:id","EXEC:id",',
  '  "{\\\"cmd\\\":\\\"id\\\"}",',
  '  "MIGRATE:1","STATUS","VERSION","PING"',
  '];',
  'result.jackpack_formats = {};',
  'jcmds.forEach(function(cmd){',
  '  try {',
  '    var r7 = cp.execSync(',
  '      "dbus-send --system --dest=com.jackpack.migration --type=method_call --print-reply /com/jackpack/migration com.jackpack.migration.ExecuteUserShell string:\'" + cmd + "\' 2>&1",',
  '      {timeout:5000}',
  '    );',
  '    result.jackpack_formats[cmd] = r7.toString().trim();',
  '  } catch(e) {',
  '    result.jackpack_formats[cmd+"_err"] = (e.stdout ? e.stdout.toString() : "") + (e.stderr ? e.stderr.toString() : "");',
  '  }',
  '});',

  // 3. ExecuteCommand with CORRECT interface name (no hyphen)
  'try {',
  '  var r8 = cp.spawnSync("dbus-send", [',
  '    "--system",',
  '    "--dest=org.tizen.tv.automation-service",',
  '    "--type=method_call",',
  '    "--print-reply",',
  '    "/TIFacAutoObj",',
  '    "org.tizen.tv.automationservice.ExecuteCommand",',
  '    "int32:0", "int32:0"',
  '  ], {timeout:5000});',
  '  result.exec_cmd_v2_out = r8.stdout ? r8.stdout.toString() : "";',
  '  result.exec_cmd_v2_err = r8.stderr ? r8.stderr.toString() : "";',
  '  result.exec_cmd_v2_status = r8.status;',
  '} catch(e) { result.exec_cmd_v2_err2 = e.message; }',

  // 4. Find more D-Bus services and their UIDs — specifically com.uifw, com.samsung.TVService, etc.
  'var svcCheck = ["com.uifw", "org.tizen.tv.litewebappservice.server", "org.pulseaudio.Server"];',
  'result.more_svc_uids = {};',
  'svcCheck.forEach(function(svc){',
  '  try {',
  '    var r9 = cp.execSync(',
  '      "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixUser string:" + svc + " 2>&1",',
  '      {timeout:4000}',
  '    );',
  '    result.more_svc_uids[svc] = r9.toString().trim();',
  '  } catch(e) { result.more_svc_uids[svc+"_err"] = e.message.slice(0,80); }',
  '});',

  // 5. Check if wasutility can be called from our context (it's setuid root)
  'try {',
  '  var r10 = cp.spawnSync("/usr/bin/wasutility", ["help"], {timeout:3000});',
  '  result.was_help_out = r10.stdout ? r10.stdout.toString() : "";',
  '  result.was_help_err = r10.stderr ? r10.stderr.toString() : "";',
  '  result.was_help_status = r10.status;',
  '} catch(e) { result.was_help_err2 = e.message; }',

  // 6. Find binary name of jackpack.migration process (PID 510)
  'try {',
  '  result.jackpack_exe = fs.readlinkSync("/proc/510/exe");',
  '} catch(e) { result.jackpack_exe_err = e.message; }',
  'try {',
  '  result.automation_exe = fs.readlinkSync("/proc/830/exe");',
  '} catch(e) { result.automation_exe_err = e.message; }',

  'var out = JSON.stringify(result, null, 2);',
  'try { require("fs").writeFileSync("' + PROBE_FILE + '", out); } catch(e) {}',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 60000 }, function(err, stdout, stderr) {
    var result;
    if (err) {
      result = JSON.stringify({ exec_error: err.message, stderr: stderr, stdout: stdout || '' });
    } else {
      result = stdout || '(empty)';
    }
    cb(result);
  });
}

var server = http.createServer(function(req, res) {
  runProbe(function(result) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(result);
  });
});

server.listen(PORT, function() {
  runProbe(function(result) {
    try { fs.writeFileSync(PROBE_FILE, result); } catch(e) {}
  });
});
