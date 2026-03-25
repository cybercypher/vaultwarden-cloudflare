#!/usr/bin/env node
/**
 * Local static file server for testing the web vault + admin panel.
 * Proxies /api/*, /identity/*, /admin/* to the Worker on port 8787.
 * Serves static files from web-vault/build/ on port 8788.
 *
 * This mimics what CF Pages does in production with _redirects.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const STATIC_DIR = path.resolve('web-vault/build');
const WORKER_URL = 'http://localhost:8787';
const PORT = 8788;

const MIME_TYPES = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff': 'font/woff',
  '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.map': 'application/json',
};

const PROXY_PREFIXES = ['/api/', '/identity/', '/notifications/', '/alive', '/attachments/'];
const ADMIN_API_PREFIXES = ['/admin/users', '/admin/organizations', '/admin/diagnostics',
  '/admin/invite', '/admin/test/', '/admin/config', '/admin/logout'];

function shouldProxy(url, method) {
  if (PROXY_PREFIXES.some(p => url.startsWith(p))) return true;
  // POST /admin is the login API
  if (url === '/admin' && method === 'POST') return true;
  // Admin API endpoints
  if (ADMIN_API_PREFIXES.some(p => url.startsWith(p))) return true;
  return false;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Device-Type, Bitwarden-Client-Name, Bitwarden-Client-Version, Auth-Email');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Proxy API requests to Worker
  if (shouldProxy(pathname, req.method)) {
    try {
      const targetUrl = `${WORKER_URL}${req.url}`;
      const headers = { ...req.headers, host: 'localhost:8787' };
      delete headers['content-length']; // Let fetch recalculate

      const body = await new Promise((resolve) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => resolve(chunks.length ? Buffer.concat(chunks) : undefined));
      });

      // Strip encoding headers to avoid mismatch
      const fetchHeaders = {};
      for (const [k, v] of Object.entries(headers)) {
        const lk = k.toLowerCase();
        if (!['host','connection','transfer-encoding','accept-encoding','content-length'].includes(lk)) {
          fetchHeaders[k] = v;
        }
      }

      const proxyRes = await fetch(targetUrl, {
        method: req.method,
        headers: fetchHeaders,
        body: body && body.length > 0 ? body : undefined,
      });

      // Forward response but strip transfer-encoding/content-encoding to avoid decode issues
      const resHeaders = {};
      for (const [k, v] of proxyRes.headers.entries()) {
        const lk = k.toLowerCase();
        if (!['transfer-encoding', 'content-encoding', 'content-length'].includes(lk)) {
          resHeaders[k] = v;
        }
      }
      const resBody = Buffer.from(await proxyRes.arrayBuffer());
      resHeaders['content-length'] = String(resBody.length);
      res.writeHead(proxyRes.status, resHeaders);
      res.end(resBody);
    } catch (e) {
      res.writeHead(502);
      res.end(`Proxy error: ${e.message}`);
    }
    return;
  }

  // Serve static files
  let filePath = path.join(STATIC_DIR, pathname);

  // Directory → index.html
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  }

  // SPA fallback for web vault routes
  if (!fs.existsSync(filePath)) {
    filePath = path.join(STATIC_DIR, 'index.html');
  }

  if (fs.existsSync(filePath)) {
    const ext = path.extname(filePath);
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(PORT, () => {
  console.log(`\x1b[34m╔═══════════════════════════════════════════════════╗\x1b[0m`);
  console.log(`\x1b[34m║  Local Pages Server                               ║\x1b[0m`);
  console.log(`\x1b[34m║  Web Vault:  http://localhost:${PORT}/                ║\x1b[0m`);
  console.log(`\x1b[34m║  Admin:      http://localhost:${PORT}/admin            ║\x1b[0m`);
  console.log(`\x1b[34m║  Worker API: ${WORKER_URL.padEnd(37)}║\x1b[0m`);
  console.log(`\x1b[34m╚═══════════════════════════════════════════════════╝\x1b[0m`);
});
