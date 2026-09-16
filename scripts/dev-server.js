'use strict';
/**
 * Serveur de développement local (aucune dépendance, aucun npm requis).
 *
 *   node scripts/dev-server.js            -> http://localhost:3000
 *   node scripts/dev-server.js 4000       -> autre port
 *
 * Sert index.html sur / et les routes api/* sur /api/*, exactement comme Vercel.
 * Lit .env.local s'il existe (SUPABASE_URL, SUPABASE_SECRET_KEY, VIRUSTOTAL_API_KEY).
 * Ce fichier ne contient AUCUN secret : il ne fait que lire l'environnement.
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PORT = parseInt(process.argv[2], 10) || 3000;

loadEnvFile(path.join(ROOT, '.env.local'));
loadEnvFile(path.join(ROOT, '.env'));

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const key = match[1];
    let value = match[2].trim().replace(/^["']|["']$/g, '');
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

const ROUTES = {
  '/api/analyze': require('../api/analyze.js'),
  '/api/history': require('../api/history.js')
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  // Route API ?
  const handler = ROUTES[pathname];
  if (handler) {
    const query = Object.fromEntries(url.searchParams.entries());
    let raw = '';
    for await (const chunk of req) raw += chunk;
    let body = null;
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch {
        body = null;
      }
    }
    const fakeReq = { method: req.method, query, body, headers: req.headers };
    const fakeRes = {
      statusCode: 200,
      headers: {},
      status(code) { this.statusCode = code; return this; },
      setHeader(name, value) { this.headers[name] = value; return this; },
      json(payload) {
        res.writeHead(this.statusCode, { 'Content-Type': 'application/json; charset=utf-8', ...this.headers });
        res.end(JSON.stringify(payload, null, 2));
        return this;
      }
    };
    try {
      await handler(fakeReq, fakeRes);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
    return;
  }

  // Fichiers statiques (index.html en priorité)
  const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
  const target = path.join(ROOT, relative);
  if (!target.startsWith(ROOT) || !fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('404');
    return;
  }
  const ext = path.extname(target);
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.txt': 'text/plain' };
  res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
  res.end(fs.readFileSync(target));
});

server.listen(PORT, () => {
  console.log(`Email Domain Security — serveur local sur http://localhost:${PORT}`);
  console.log(`Supabase configuré : ${process.env.SUPABASE_URL && (process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY) ? 'oui' : 'non'}`);
  console.log(`VirusTotal activé  : ${process.env.VIRUSTOTAL_API_KEY ? 'oui' : 'non (facultatif)'}`);
});
