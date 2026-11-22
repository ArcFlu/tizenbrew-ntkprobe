// v24e - find actual addon load address by diffing maps before/after require
// Also scan anonymous executable mappings for ELF header
// Port 8103
try {
  var fs = require('fs');
  var http = require('http');
  var lines = ['=== addon-locate v24e ==='];

  var ADDON = '/home/owner/share/tmp/sdk_tools/timing-probe.node';

  function parseMaps(text) {
    var result = [];
    text.split('\n').forEach(function(l) {
      if (!l) return;
      var parts = l.split(/\s+/);
      var range = parts[0].split('-');
      result.push({
        start: parseInt(range[0], 16),
        end:   parseInt(range[1], 16),
        perm:  parts[1],
        file:  parts[5] || '',
        line:  l
      });
    });
    return result;
  }

  // ---- Maps BEFORE require ----
  var mapsBefore = parseMaps(fs.readFileSync('/proc/self/maps', 'utf8'));
  lines.push('maps_before_count: ' + mapsBefore.length);

  // ---- Require ----
  var requireErr = null;
  try { require(ADDON); } catch(e) { requireErr = String(e.message||e).substring(0,60); }
  lines.push('require_err: ' + requireErr);

  // ---- Maps AFTER require ----
  var mapsAfter = parseMaps(fs.readFileSync('/proc/self/maps', 'utf8'));
  lines.push('maps_after_count: ' + mapsAfter.length);

  // ---- Diff: new regions ----
  var beforeSet = {};
  mapsBefore.forEach(function(e){ beforeSet[e.start] = 1; });
  var newRegions = mapsAfter.filter(function(e){ return !beforeSet[e.start]; });
  lines.push('new_regions: ' + JSON.stringify(newRegions.map(function(e){return e.line;})));

  // ---- Find executable anonymous mappings ----
  var execAnon = mapsAfter.filter(function(e){
    return e.perm.indexOf('x') !== -1 && !e.file;
  });
  lines.push('exec_anon_maps: ' + JSON.stringify(execAnon.map(function(e){return e.line;})));

  // ---- Scan all executable mappings for ELF header ----
  var memFd = fs.openSync('/proc/self/mem', 'r');
  var hdrBuf = new Buffer(16);
  var elfCandidates = [];

  mapsAfter.forEach(function(e) {
    if (e.perm.indexOf('x') === -1) return;
    if (e.file.indexOf('node') !== -1 || e.file.indexOf('libc') !== -1 ||
        e.file.indexOf('libpthread') !== -1 || e.file.indexOf('ld-') !== -1) return;
    // Skip large known mappings, check anonymous+exe and unknown files
    try {
      var n = fs.readSync(memFd, hdrBuf, 0, 16, e.start);
      if (n >= 4 && hdrBuf[0]===0x7f && hdrBuf[1]===0x45 && hdrBuf[2]===0x4c && hdrBuf[3]===0x46) {
        elfCandidates.push({ start: '0x'+e.start.toString(16), size: (e.end-e.start),
                             perm: e.perm, file: e.file,
                             hdr: hdrBuf.slice(0,8).toString('hex') });
      }
    } catch(re) {}
  });
  lines.push('elf_candidates_in_exe_mappings: ' + JSON.stringify(elfCandidates));

  // ---- Also check RW anonymous mappings for ELF (addon might be rw-p if mmap'd) ----
  var rwAnon = mapsAfter.filter(function(e) {
    return e.perm.indexOf('r') !== -1 && !e.file && e.perm.indexOf('x') === -1;
  });
  var rwElfCandidates = [];
  rwAnon.slice(0, 20).forEach(function(e) {
    try {
      var n = fs.readSync(memFd, hdrBuf, 0, 16, e.start);
      if (n >= 4 && hdrBuf[0]===0x7f && hdrBuf[1]===0x45 && hdrBuf[2]===0x4c && hdrBuf[3]===0x46) {
        rwElfCandidates.push({ start: '0x'+e.start.toString(16), perm: e.perm,
                              hdr: hdrBuf.slice(0,16).toString('hex') });
      }
    } catch(re) {}
  });
  lines.push('elf_candidates_in_rw_anon: ' + JSON.stringify(rwElfCandidates));

  fs.closeSync(memFd);

  // ---- Full maps (all lines) for reference ----
  var allLines = mapsAfter.map(function(e){return e.line;});
  lines.push('full_maps_count: ' + allLines.length);
  // Serve full maps as separate file
  var fullMapsBody = allLines.join('\n');

  var body = lines.join('\n') + '\n=== END ===\n';
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24e.txt', body); } catch(e3) {}
  try { fs.writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24e-maps.txt', fullMapsBody); } catch(e3) {}

  var srv = http.createServer(function(req, res) {
    if (req.url === '/maps') {
      res.writeHead(200,{'Content-Type':'text/plain'}); res.end(fullMapsBody);
    } else {
      res.writeHead(200,{'Content-Type':'text/plain'}); res.end(body);
    }
  });
  srv.listen(8103, '127.0.0.1', function(){});
  srv.on('error', function(e){});
  setInterval(function(){},60000);
} catch(e) {
  try { require('fs').writeFileSync('/home/owner/share/tmp/sdk_tools/tbprobe24e-crash.txt',String(e.stack||e.message).substring(0,500)); } catch(e2) {}
}
