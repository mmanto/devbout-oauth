// Minimal static file server for the bundled @nangohq/connect-ui SPA.
// The "hosted" nango-server image ships packages/connect-ui/dist but never
// serves it — the API (port 8080) and the Connect UI are separate origins.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = '/app/nango/packages/connect-ui/dist';
const PORT = 3009;

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.gif': 'image/gif',
  '.woff2': 'font/woff2',
};

http
  .createServer((req, res) => {
    const reqPath = decodeURIComponent((req.url || '/').split('?')[0]);
    let filePath = path.join(ROOT, reqPath);

    fs.stat(filePath, (err, stat) => {
      if (err || stat.isDirectory()) {
        filePath = path.join(ROOT, 'index.html');
      }
      fs.readFile(filePath, (readErr, data) => {
        if (readErr) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        res.writeHead(200, {
          'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
        });
        res.end(data);
      });
    });
  })
  .listen(PORT, '0.0.0.0', () => {
    console.log(`connect-ui serving ${ROOT} on :${PORT}`);
  });
