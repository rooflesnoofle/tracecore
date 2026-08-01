/*
 * OSINTDog proxy — local bridge between the TraceCore panel and https://osintdog.com
 *
 * Why: osintdog.com sends no CORS headers, so browsers block direct calls.
 * This tiny server holds your API key server-side and forwards requests.
 *
 * Usage:
 *   node proxy.js
 *   (optional) set env: OSINTDOG_API_KEY=xxx  PORT=8787
 *
 * Then open panel.html — the panel calls http://localhost:8787/api/...
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const PORT = process.env.PORT || 8787;
const UPSTREAM = 'osintdog.com';
const API_KEY = process.env.OSINTDOG_API_KEY || 'fd568d8d-4aa4-4608-aa52-2adf78b1800a';

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
}

function send(res, status, payload, type) {
  cors(res);
  res.writeHead(status, { 'Content-Type': type || 'application/json' });
  res.end(payload);
}

function forward(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const headers = {
    'X-API-Key': API_KEY,
    'Content-Type': 'application/json',
  };
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const payload = Buffer.concat(chunks);
    if (payload.length) headers['Content-Length'] = payload.length;

    const upstream = https.request({
      hostname: UPSTREAM,
      path: url.pathname + url.search,
      method: req.method,
      headers,
    }, (upstreamRes) => {
      const body = [];
      upstreamRes.on('data', (c) => body.push(c));
      upstreamRes.on('end', () => {
        const data = Buffer.concat(body);
        const contentType = upstreamRes.headers['content-type'] || 'application/json';
        send(res, upstreamRes.statusCode || 502, data, contentType);
      });
    });

    upstream.on('error', (err) => {
      send(res, 502, JSON.stringify({ error: 'Proxy -> upstream failed', detail: err.message }));
    });

    if (payload.length) upstream.write(payload);
    upstream.end();
  });
}

http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    cors(res);
    res.writeHead(204);
    return res.end();
  }
  forward(req, res);
}).listen(PORT, () => {
  console.log(`OSINTDog proxy running  ->  http://localhost:${PORT}`);
  console.log(`Forwarding to upstream  ->  https://${UPSTREAM}/api/...`);
  console.log(`Using API key           ->  ...${API_KEY.slice(-6)}`);
  console.log('Open panel.html and traces will resolve through this proxy.');
});
