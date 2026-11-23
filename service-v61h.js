'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8149;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe61h.txt';

var INNER = [
  'var fs = require("fs");',
  'var cp = require("child_process");',
  'var result = {};',

  // 1. Read automation-service and jackpack process info (uid=0 processes)
  'var pids = ["830","510","267"];',
  'result.root_proc_info = {};',
  'pids.forEach(function(pid){',
  '  var info = {};',
  '  try { info.cmdline = fs.readFileSync("/proc/"+pid+"/cmdline","utf8").replace(/\\0/g," ").trim(); } catch(e) {}',
  '  try { info.exe = fs.readlinkSync("/proc/"+pid+"/exe"); } catch(e) {}',
  '  try {',
  '    var status = fs.readFileSync("/proc/"+pid+"/status","utf8");',
  '    info.uid = (status.match(/^Uid:\\s*(\\S+)/m)||[])[1];',
  '    info.gid = (status.match(/^Gid:\\s*(\\S+)/m)||[])[1];',
  '    info.capeff = (status.match(/^CapEff:\\s*(\\S+)/m)||[])[1];',
  '  } catch(e) {}',
  '  try { info.smack = fs.readFileSync("/proc/"+pid+"/attr/current","utf8").trim(); } catch(e) {}',
  '  result.root_proc_info[pid] = info;',
  '});',

  // 2. D-Bus ExecuteCommand — capture FULL stdout/stderr
  'try {',
  '  var r = cp.execSync(',
  '    "dbus-send --system --dest=org.tizen.tv.automation-service --type=method_call --print-reply /TIFacAutoObj org.tizen.tv.automation-service.TIFacAutoObj.ExecuteCommand int32:0 int32:0",',
  '    {timeout:5000}',
  '  );',
  '  result.exec_cmd_stdout = r.toString();',
  '} catch(e) {',
  '  result.exec_cmd_stdout = e.stdout ? e.stdout.toString() : "";',
  '  result.exec_cmd_stderr = e.stderr ? e.stderr.toString() : "";',
  '  result.exec_cmd_code = e.status || e.code;',
  '}',

  // 3. Introspect jackpack.migration deeper
  'var jPaths = ["/com", "/com/jackpack", "/com/jackpack/migration", "/com/jackpack/m", "/"];',
  'result.jackpack_introspect = {};',
  'jPaths.forEach(function(p){',
  '  try {',
  '    var r2 = cp.execSync(',
  '      "dbus-send --system --dest=com.jackpack.migration --type=method_call --print-reply " + p + " org.freedesktop.DBus.Introspectable.Introspect 2>&1",',
  '      {timeout:4000}',
  '    );',
  '    result.jackpack_introspect[p] = r2.toString().slice(0,2000);',
  '  } catch(e) {',
  '    result.jackpack_introspect[p] = "err:" + (e.stderr ? e.stderr.toString() : e.message).slice(0,100);',
  '  }',
  '});',

  // 4. wasutility strings (fix encoding — use Buffer directly)
  'try {',
  '  var wb = fs.readFileSync("/usr/bin/wasutility");',
  '  var sqls = [];',
  '  var i = 0, start = 0;',
  '  while(i < wb.length) {',
  '    if(wb[i] === 0) {',
  '      if(i - start > 8) {',
  '        var s = wb.slice(start, i).toString("ascii");',
  '        if(s.match(/SELECT|INSERT|UPDATE|sqlite|dbspace|\\.db$|^\\/opt|^\\/usr/i)) sqls.push(s);',
  '      }',
  '      start = i + 1;',
  '    }',
  '    i++;',
  '  }',
  '  result.wasutility_strings = sqls.slice(0,40);',
  '} catch(e) { result.wasutility_strings_err = e.message; }',

  // 5. Check if /opt/dbspace DBs are readable/writable by us
  'var dbs = [',
  '  "/opt/dbspace/.AppBinaryManager.db",',
  '  "/opt/dbspace/.security-manager.db",',
  '  "/opt/dbspace/.pkgmgr_parser.db",',
  '  "/opt/dbspace/.policy.db",',
  '  "/opt/dbspace/.webappservice.db"',
  '];',
  'result.db_access = {};',
  'dbs.forEach(function(db){',
  '  var info = {};',
  '  try { var st = fs.statSync(db); info.mode = st.mode.toString(8); info.uid = st.uid; info.gid = st.gid; info.size = st.size; } catch(e) { info.stat_err = e.message; }',
  '  try { var fd = fs.openSync(db, "r"); fs.closeSync(fd); info.readable = true; } catch(e) { info.readable = false; }',
  '  try { var fd2 = fs.openSync(db, "r+"); fs.closeSync(fd2); info.writable = true; } catch(e) { info.writable = false; }',
  '  result.db_access[db] = info;',
  '});',

  // 6. Check /run/factory files and kfactoryd symlinks
  'try {',
  '  var r3 = cp.execSync("ls -la /run/factory/ 2>&1", {timeout:3000});',
  '  result.factory_ls = r3.toString();',
  '} catch(e) { result.factory_ls_err = e.message; }',
  'try {',
  '  result.factory_src_info = fs.readFileSync("/run/factory/src_info_source","utf8");',
  '} catch(e) { result.factory_src_info_err = e.message; }',

  // 7. Check if com.jackpack.migration has interesting methods by looking at its binary
  'try {',
  '  var r4 = cp.execSync("cat /proc/510/cmdline 2>&1 | tr \'\\\\0\' \' \'", {timeout:3000});',
  '  result.jackpack_cmdline_direct = r4.toString();',
  '} catch(e) { result.jackpack_cmdline_direct_err = e.message; }',

  // 8. Check dbus Smack policy — are there dbus policy files?
  'try {',
  '  var r5 = cp.execSync("ls /etc/dbus-1/system.d/ 2>&1 | head -20", {timeout:3000});',
  '  result.dbus_policy_files = r5.toString();',
  '} catch(e) { result.dbus_policy_files_err = e.message; }',
  'try {',
  '  var r6 = cp.execSync("cat /etc/dbus-1/system.d/automation-service.conf 2>&1", {timeout:3000});',
  '  result.automation_dbus_conf = r6.toString().slice(0,2000);',
  '} catch(e) { result.automation_dbus_conf_err = e.message; }',

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
