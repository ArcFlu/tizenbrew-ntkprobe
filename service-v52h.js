'use strict';
var http = require('http');
var fs = require('fs');
var cp = require('child_process');

var PORT = 8140;
var PROBE_FILE = '/home/owner/share/tmp/sdk_tools/tbprobe52h.txt';

var INNER = [
  'var fs = require("fs");',
  'var result = {};',
  'try { var st = fs.statSync("/dev/ntksys"); result.ntksys_exists = true; result.ntksys_mode = "0" + (st.mode & 0xFFF).toString(8); } catch(e) { result.ntksys_exists = false; result.ntksys_err = e.message; }',
  'try { var fd = fs.openSync("/dev/ntksys", "r+"); fs.closeSync(fd); result.ntksys_open = true; } catch(e) { result.ntksys_open = false; result.ntksys_open_err = e.message; }',
  'try { var st2 = fs.statSync("/dev/ntkhdma"); result.ntkhdma_exists = true; result.ntkhdma_mode = "0" + (st2.mode & 0xFFF).toString(8); } catch(e) { result.ntkhdma_exists = false; result.ntkhdma_err = e.message; }',
  'try { result.cmdline = fs.readFileSync("/proc/cmdline", "utf8").trim(); } catch(e) { result.cmdline_err = e.message; }',
  'try { var devs = fs.readdirSync("/dev").filter(function(d){ return d.indexOf("ntk") === 0; }); result.ntk_devices = devs; } catch(e) { result.ntk_devices_err = e.message; }',
  'try { result.uid = process.getuid(); result.gid = process.getgid(); } catch(e) { result.uid_err = e.message; }',
  'var out = JSON.stringify(result, null, 2);',
  'var fs2 = require("fs");',
  'fs2.writeFileSync("/home/owner/share/tmp/sdk_tools/tbprobe52h.txt", out);',
  'process.stdout.write(out);'
].join('\n');

function runProbe(cb) {
  cp.execFile(process.execPath, ['-e', INNER], { timeout: 20000 }, function(err, stdout, stderr) {
    var result;
    if (err) {
      result = JSON.stringify({ exec_error: err.message, stderr: stderr, stdout: stdout });
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
    try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe52h.txt', result); } catch(e) {}
  });
});
