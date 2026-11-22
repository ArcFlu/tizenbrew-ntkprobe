// ping - bare minimum service to verify concurrent loading works
try {
  var http = require('http');
  var srv = http.createServer(function(req, res) {
    res.writeHead(200,{'Content-Type':'text/plain'});
    res.end('pong v1.0.39\n');
  });
  srv.listen(8115,'127.0.0.1',function(){});
  srv.on('error',function(){});
  setInterval(function(){},60000);
} catch(e) {}
