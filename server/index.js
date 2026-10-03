// server/index.js — binthere Node server (self-hosted VPS port).
//
// Zero-dependency port of the CF Worker (src/index.js). Serves:
//   /api/*     — the paste API (format v1, wire-compatible; SPEC.md §10)
//   /api/file* — chunk upload/download for file pastes (this port's
//                extension: 'f' id class — see server/README.md)
//   /*         — static assets from ../public (SPA, index.html fallback)
//
// The zero-knowledge model is unchanged: encryption happens in the client,
// the server only stores opaque ciphertext + non-secret metadata.
//
// Env:
//   BINTHERE_PORT       listen port (default 8788)
//   BINTHERE_HOST       bind address (default 127.0.0.1 — put nginx in front)
//   BINTHERE_DATA_DIR   storage root (default ./data)
//   BINTHERE_RL_CREATE  paste creates per IP per minute (default 30)
//   BINTHERE_RL_PUT     chunk PUTs per IP per minute (default 120)

import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream';
import { promisify } from 'node:util';
import { validatePaste, FormatError, MAX_CT_B64, EXPIRE_SECONDS } from '../public/js/format.js';
import { genId, parseId, genDeleteToken, hashToken, verifyToken } from './ids.js';
import * as store from './store.js';
import { allowCreate, clientIp } from './ratelimit.js';
import { routeFile } from './files.js';
import { ResponseLike, FileResponse, json, err } from './respond.js';

const pipe = promisify(pipeline);

const PORT = Number(process.env.BINTHERE_PORT ?? 8788);
const HOST = process.env.BINTHERE_HOST ?? '127.0.0.1';
const DATA_DIR = process.env.BINTHERE_DATA_DIR ?? path.join(process.cwd(), 'data');
const PUBLIC_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'public');

const GONE = 'Document does not exist, has expired or has been deleted.';
const BURNED = 'This document was single-use and has already been read, or has expired.';

// ── body reading (mirror of the Worker's readCappedBody) ────────────────────

async function readBody(req, max) {
  const cl = Number(req.headers['content-length']);
  if (Number.isFinite(cl) && cl > max) {
    req.resume();
    return null;
  }
  const chunks = [];
  let received = 0;
  for await (const c of req) {
    received += c.length;
    if (received > max) return null;
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

function contentTypeIs(req, want) {
  return (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() === want;
}

// ── create (POST /api/paste, POST /api/file) ─────────────────────────────────

async function validateCreateBody(req) {
  if (!contentTypeIs(req, 'application/json')) {
    return { error: err('Content-Type must be application/json.', 415) };
  }
  if (!allowCreate(clientIp(req))) {
    return { error: err('Rate limit exceeded. Try again shortly.', 429) };
  }
  const bytes = await readBody(req, 4 * 1024 * 1024);
  if (bytes === null) return { error: err('Document is too large.', 413) };

  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    return { error: err('Invalid JSON body.', 400) };
  }
  // An oversized `ct` is a size problem, not a format one (SPEC §6 → 413).
  if (parsed && typeof parsed === 'object' && typeof parsed.ct === 'string'
      && parsed.ct.length > MAX_CT_B64) {
    return { error: err('Document is too large.', 413) };
  }
  let clean;
  try {
    clean = validatePaste(parsed);
  } catch (e) {
    if (e instanceof FormatError) return { error: err(e.message, 400) };
    throw e;
  }
  return { clean };
}

async function storePaste(clean, idClass) {
  const ttl = EXPIRE_SECONDS[clean.meta.expire] ?? 0;
  const deleteToken = genDeleteToken();
  const dth = await hashToken(deleteToken);
  const created = Math.floor(Date.now() / 1000);
  // The stored/returned paste carries meta.created but never the token hash.
  const paste = {
    v: clean.v, ct: clean.ct, wk: clean.wk, adata: clean.adata,
    meta: { expire: clean.meta.expire, created },
  };

  let id;
  for (let attempt = 0; ; attempt++) {
    id = genId(idClass);
    if (await store.createPasteMeta(id, paste, dth, ttl)) break;
    if (attempt >= 4) return err('Could not allocate a paste id, please retry.', 500);
  }
  return json({ id, deletetoken: deleteToken }, 201);
}

async function createTextPaste(req) {
  const { clean, error } = await validateCreateBody(req);
  if (error) return error;
  // adata rides alongside ct as *associated data* — visible to the server
  // (SPEC §3); `bar` picks the storage class exactly like the Worker does.
  return storePaste(clean, clean.adata.bar === true ? 'b' : 'k');
}

async function createFilePaste(req) {
  const { clean, error } = await validateCreateBody(req);
  if (error) return error;
  return storePaste(clean, 'f');
}

// ── read / consume / delete ──────────────────────────────────────────────────

async function readPaste(id, peekOnly) {
  const info = parseId(id);
  // 'f' (file) pastes are READ here like normal pastes — the decrypted
  // plaintext is the chunk manifest. Only consume (below) is restricted to 'b'.
  if (!info) return err(GONE, 404);

  if (info.burn) {
    // GET on a burn id NEVER consumes (SPEC §8): head only, without `ct`.
    const rec = await store.consumeBurnPeek(id);
    if (!rec) return err(BURNED, 410);
    const p = rec.p;
    return json({ v: p.v, wk: p.wk, adata: p.adata, meta: p.meta }, 200);
  }

  const rec = await store.getPasteMeta(id);
  if (!rec) return err(GONE, 404);
  if (peekOnly) {
    // ?meta=1 returns a head for every storage class — ct never rides along.
    const p = rec.p;
    return json({ v: p.v, wk: p.wk, adata: p.adata, meta: p.meta }, 200);
  }
  return json(rec.p, 200);
}

// The single destructive read for burn pastes. The custom header makes this a
// CORS non-simple request (no CORS headers on the API → cross-origin preflight
// fails before the consume); Fetch Metadata rejects cross-site senders as
// defense in depth. Mirrors src/index.js consumePaste.
async function consumePaste(id, req) {
  if ((req.headers['x-burn-intent'] || '').trim().toLowerCase() !== 'consume') {
    return err('Burn consumption requires the "X-Burn-Intent: consume" header.', 400);
  }
  const site = (req.headers['sec-fetch-site'] || '').toLowerCase();
  if (site === 'cross-site') {
    return err('Cross-site burn consumption is not allowed.', 403);
  }
  const info = parseId(id);
  if (!info) return err(GONE, 404);
  if (!info.burn) return err('Only one-time-view pastes can be consumed.', 404);

  const rec = await store.consumeBurn(id);
  if (!rec) return err(BURNED, 410);
  return json(rec.p, 200);
}

async function deletePaste(id, req) {
  // Token travels in a header, never the URL (URLs land in logs; SPEC §10).
  const token = req.headers['x-delete-token'];
  if (!token) return err('Missing deletion token.', 400);
  const info = parseId(id);
  if (!info) return err(GONE, 404);

  const rec = await store.getPasteMeta(id);
  if (!rec) return err(GONE, 404);
  if (!(await verifyToken(token, rec.dth))) {
    return err('Wrong deletion token. Document was not deleted.', 403);
  }
  await store.deletePaste(id);
  return json({ status: 'deleted', id }, 200);
}

// ── static assets ────────────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function plain(text, status) {
  return new ResponseLike(text, status, { 'content-type': 'text/plain; charset=utf-8' });
}

async function serveStatic(pathname) {
  let rel = (pathname === '/' ? '/index.html' : pathname).replace(/\.\./g, '').replace(/\/+/g, '/');
  let file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR)) return plain('Not found', 404);
  let s = await stat(file).catch(() => null);
  if (s?.isDirectory()) {
    file = path.join(file, 'index.html');
    s = await stat(file).catch(() => null);
  }
  if (!s) {
    if (path.extname(rel)) return plain('Not found', 404);
    // SPA fallback: extension-less routes (e.g. /p/<id>) get the app shell.
    file = path.join(PUBLIC_DIR, 'index.html');
    s = await stat(file).catch(() => null);
    if (!s) return plain('Not found', 404);
  }
  const stream = createReadStream(file);
  const type = MIME[path.extname(file).toLowerCase()] ?? 'application/octet-stream';
  return new FileResponse(stream, 200, {
    'content-type': type,
    'content-length': String(s.size),
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    // Same strict CSP as public/_headers (the XSS→key-theft defense).
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
  });
}

// ── routing ──────────────────────────────────────────────────────────────────

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
  const { pathname } = url;

  if (pathname === '/api/paste') {
    if (req.method === 'POST') return createTextPaste(req);
    return err('Method not allowed', 405, { allow: 'POST' });
  }

  if (pathname === '/api/file') {
    if (req.method === 'POST') return createFilePaste(req);
    return err('Method not allowed', 405, { allow: 'POST' });
  }

  const mc = pathname.match(/^\/api\/paste\/([^/]+)\/consume$/);
  if (mc) {
    if (req.method !== 'POST') return err('Method not allowed', 405, { allow: 'POST' });
    return consumePaste(decodeId(mc[1]), req);
  }

  const mf = pathname.match(/^\/api\/file\/([^/]+)\/(\d+)$/);
  if (mf) return routeFile(req, res, url, decodeId(mf[1]));

  const m = pathname.match(/^\/api\/(paste|file)\/([^/]+)$/);
  if (m) {
    const id = decodeId(m[2]);
    if (m[1] === 'file') return routeFile(req, res, url, id);
    if (req.method === 'GET') return readPaste(id, url.searchParams.get('meta') === '1');
    if (req.method === 'DELETE') return deletePaste(id, req);
    return err('Method not allowed', 405, { allow: 'GET, DELETE' });
  }

  if (pathname === '/api/stars') {
    // Private deployment: no upstream repo badge. Stable null, cacheable.
    return json({ stars: null }, 200, { 'cache-control': 'public, max-age=3600' });
  }

  if (pathname.startsWith('/api/')) return err('Not found', 404);

  return serveStatic(pathname);
}

function decodeId(raw) {
  try {
    return decodeURIComponent(raw);
  } catch {
    return '\u0000-invalid'; // malformed encoding → fails parseId → 404
  }
}

// ── server ───────────────────────────────────────────────────────────────────

export async function main() {
  await store.initDataStore(DATA_DIR);
  const server = createServer((req, res) => {
    route(req, res).then((r) => {
      if (r instanceof FileResponse) {
        res.writeHead(r.status, r.headers);
        pipe(r.stream, res).catch(() => res.destroy());
      } else {
        res.writeHead(r.status, r.headers);
        res.end(r.body);
      }
    }).catch((e) => {
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'Internal server error.' }));
      } else {
        res.destroy();
      }
      console.error('[binthere]', req.method, req.url, e);
    });
  });
  await new Promise((res) => server.listen(PORT, HOST, res));
  console.log(`binthere node server listening on http://${HOST}:${PORT} (data: ${DATA_DIR})`);
  return server;
}

// Run directly: `node server/index.js`
const invokedDirectly = process.argv[1]
  && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href;
if (invokedDirectly) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
