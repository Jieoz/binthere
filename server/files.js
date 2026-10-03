// server/files.js — chunk upload/download for file pastes ('f' id class).
//
// This port's extension to the frozen v1 protocol (see server/README.md).
// A file paste = a normal format-v1 paste whose encrypted plaintext is a small
// JSON manifest:
//   { "binthere": "file/v1", "name": "<utf8>", "size": <bytes>,
//     "mime": "<utf8>", "chunks": <count>, "ivs": ["<b64 iv0>", ...] }
// The manifest rides in `ct` (encrypted, opaque to the server). The file BYTES
// live as independently-encrypted chunks: chunk i = AES-256-GCM(CEK, ivs[i],
// aad = utf8(`<id>:<i>`)). The CEK is the paste's content key derived from the
// URL fragment exactly as for text pastes — possession of the share URL (with
// #key) is the only capability a reader needs. The server sees neither key.
//
// Routes (mounted from index.js):
//   PUT /api/file/:id/:n   — upload chunk n (application/octet-stream,
//                            X-Delete-Token required; ≤ CHUNK_MAX bytes)
//   GET /api/file/:id/:n   — download chunk n

import { Readable } from 'node:stream';
import { parseId, verifyToken } from './ids.js';
import * as store from './store.js';
import { allowPut, clientIp } from './ratelimit.js';
import { FileResponse, json, err } from './respond.js';

// Per-chunk cap: MiB setting + 16 bytes of GCM tag headroom. The tag rides on
// every ciphertext, so a full-MiB plaintext chunk is 16 bytes larger than the
// MiB value — a cap without headroom 413s the common "exactly 8 MiB" case.
const CHUNK_MAX = Number(process.env.BINTHERE_CHUNK ?? 8) * 1024 * 1024 + 16;
const FILE_MAX = Number(process.env.BINTHERE_MAX_FILE ?? 512) * 1024 * 1024;  // total ciphertext budget
const MAX_CHUNKS = Math.ceil(FILE_MAX / (CHUNK_MAX - 16));

export { MAX_CHUNKS, CHUNK_MAX, FILE_MAX };

function decodeId(raw) {
  try {
    return decodeURIComponent(raw);
  } catch {
    return '\u0000-invalid'; // malformed encoding → fails parseId → 404
  }
}

/** Validate id class + existence. Returns the meta record or null (→ 404). */
async function loadFileMeta(id) {
  const info = parseId(id);
  if (!info || !info.file) return null;
  return store.getPasteMeta(id);
}

export async function routeFile(req, res, url, rawId) {
  // rawId comes pre-decoded from index.js; the chunk index is ASCII digits.
  const seg = url.pathname.match(/^\/api\/file\/([^/]+)\/(\d+)$/);
  if (!seg) return err('Not found', 404);

  const n = Number(seg[2]);
  if (!Number.isInteger(n) || n < 0 || n >= MAX_CHUNKS) {
    return err(`Chunk index out of range (0–${MAX_CHUNKS - 1}).`, 400);
  }

  const id = decodeId(seg[1]);
  if (req.method === 'PUT') return putChunk(req, id, n);
  if (req.method === 'GET') return getChunk(id, n);
  return err('Method not allowed', 405, { allow: 'GET, PUT' });
}

async function putChunk(req, id, n) {
  if (!allowPut(clientIp(req))) {
    return err('Rate limit exceeded. Try again shortly.', 429);
  }
  const rec = await loadFileMeta(id);
  if (!rec) {
    return err('Document does not exist, has expired or has been deleted.', 404);
  }

  // Authorization: the uploader must present the delete token issued at
  // manifest creation. Without this, anyone who learned a bare id (no #key)
  // could poison an orphaned manifest's chunks. Readers never need the token.
  const token = req.headers['x-delete-token'];
  if (!token) return err('Missing x-delete-token.', 401);
  if (!(await verifyToken(token, rec.dth))) {
    return err('Wrong deletion token.', 403);
  }

  const bytes = await readBody(req, CHUNK_MAX);
  if (bytes === null || bytes.length === 0) {
    return err(`Chunk must be 1–${CHUNK_MAX} bytes.`, 413);
  }

  const stored = await store.putChunk(id, n, bytes);
  if (stored === null) return err('Chunk already uploaded.', 409);
  return json({ status: 'ok', chunk: n, stored }, 200);
}

async function getChunk(id, n) {
  const rec = await loadFileMeta(id);
  if (!rec) {
    return err('Document does not exist, has expired or has been deleted.', 404);
  }

  const bytes = await store.getChunk(id, n);
  if (bytes === null) return err('Chunk not (yet) uploaded.', 404);

  return new FileResponse(Readable.from(bytes), 200, {
    'content-type': 'application/octet-stream',
    'content-length': String(bytes.length),
  });
}

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
