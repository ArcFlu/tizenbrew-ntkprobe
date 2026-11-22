// v26 - diagnose Smack exec block; find SUID binaries; try execFile (no shell)
// Pull server: 8106
try {
  var fs  = require('fs');
  var cp  = require('child_process');
  var http = require('http');
  var lines = ['=== smack-diag v26 ==='];

  // Step 1: our own Smack label
  try {
    lines.push('smack_self: ' + fs.readFileSync('/proc/self/attr/current', 'utf8').trim());
  } catch(e) { lines.push('smack_self: ' + String(e.code||e.message)); }

  // Step 2: Smack label on files we create
  try {
    var testf = '/tmp/smack_test_' + Date.now();
    fs.writeFileSync(testf, 'x', {mode: 0755});
    try {
      var label = cp.execSync('getfattr -n security.SMACK64 --only-values ' + testf + ' 2>/dev/null', {timeout:3000}).toString().trim();
      lines.push('new_file_smack64: "' + label + '"');
    } catch(e) {
      lines.push('getfattr: ' + String(e.message||e.code).substring(0,80));
    }
    // Try setfattr to _ (floor label)
    try {
      cp.execSync('setfattr -n security.SMACK64 -v _ ' + testf, {timeout:3000});
      lines.push('setfattr_to_floor: OK');
    } catch(e) {
      lines.push('setfattr_to_floor: ' + String(e.stderr||e.message||e.code).substring(0,100));
    }
    fs.unlinkSync(testf);
  } catch(e) { lines.push('smack_label_test: ' + String(e.message||e.code)); }

  // Step 3: try execFileSync (raw execve, no sh) on /tmp/dirtycow_was
  var DCOW = '/tmp/dirtycow_was';
  try {
    // ensure it exists
    var binData = fs.readFileSync('/home/owner/share/tmp/sdk_tools/dirtycow_was');
    fs.writeFileSync(DCOW, binData, {mode: 0755});
  } catch(e) {}

  try {
    var out = cp.execFileSync(DCOW, [], {timeout: 5000}).toString().trim();
    lines.push('execFile_direct: OK out=' + out.substring(0,100));
  } catch(e) {
    lines.push('execFile_direct: code=' + e.code + ' status=' + e.status + ' msg=' + String(e.message||'').substring(0,100));
  }

  // Step 4: list all SUID binaries
  try {
    var suidOut = cp.execSync('find /bin /sbin /usr/bin /usr/sbin /opt -perm -4000 -type f 2>/dev/null', {timeout: 15000}).toString().trim();
    lines.push('suid_bins: ' + suidOut.split('\n').join(', '));
  } catch(e) { lines.push('suid_find: ' + String(e.message||e.code).substring(0,100)); }

  // Step 5: check Smack policy - can our label exec anything?
  try {
    var smackLoad = fs.readFileSync('/sys/fs/smackfs/load2', 'utf8');
    var ourLabel = 'User::Pkg::xvvl3S1bvH';
    var execRules = smackLoad.split('\n').filter(function(l){
      return l.indexOf(ourLabel) !== -1 && l.indexOf(' x') !== -1;
    });
    lines.push('smack_exec_rules_for_us: ' + JSON.stringify(execRules.slice(0,10)));
  } catch(e) {
    lines.push('smack_policy: ' + String(e.code||e.message));
  }

  // Step 6: try to exec a known-good binary to verify exec works at all
  try {
    var idOut = cp.execSync('/usr/bin/id 2>&1', {timeout: 3000}).toString().trim();
    lines.push('id_exec: ' + idOut);
  } catch(e) { lines.push('id_exec: ' + String(e.message||e.code).substring(0,80)); }

  // Step 7: check if /proc/self/exe is executable label
  try {
    var exeLabel = cp.execSync('getfattr -n security.SMACK64 --only-values /proc/self/exe 2>/dev/null', {timeout:3000}).toString().trim();
    lines.push('node_exe_smack: "' + exeLabel + '"');
  } catch(e) {}
  try {
    var wasLabel = cp.execSync('getfattr -n security.SMACK64 --only-values /bin/wasutility 2>/dev/null', {timeout:3000}).toString().trim();
    lines.push('wasutility_smack: "' + wasLabel + '"');
  } catch(e) {}

  // Step 8: check if TizenBrew service process's parent exe is webappservice
  try {
    var ppid = fs.readFileSync('/proc/self/status', 'utf8').match(/^PPid:\s+(\d+)/m)[1];
    var pexe = fs.readlinkSync('/proc/' + ppid + '/exe');
    lines.push('parent_pid: ' + ppid + ' exe: ' + pexe);
    var gppid = fs.readFileSync('/proc/' + ppid + '/status', 'utf8').match(/^PPid:\s+(\d+)/m)[1];
    var gpexe = fs.readlinkSync('/proc/' + gppid + '/exe');
    lines.push('grandparent_pid: ' + gppid + ' exe: ' + gpexe);
  } catch(e) { lines.push('parent_check: ' + String(e.message||e.code)); }

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe26.txt', body); } catch(e3) {}
  var srv = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(body);
  });
  srv.listen(8106, '127.0.0.1', function() {});
  srv.on('error', function(e) {});
  setInterval(function() {}, 60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe26-crash.txt', String(e.stack||e.message).substring(0, 500)); } catch(e2) {}
}
