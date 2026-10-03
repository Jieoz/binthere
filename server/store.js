// server/store.js — filesystem storage for the Node port.
//
// Layout (everything under BINTHERE_DATA_DIR):
//   <dir>/meta/<id>.json   — { p: pasteObject, dth: deleteTokenHash, exp: expiryEpochSeconds|0 }
//   <dir>/blob/<id>/<n>    — ciphertext chunks for file pastes (id prefix f)
//   <dir>/tmp/             — staging for atomic writes (same filesystem → rename is atomic)
//
// Zero-knowledge preserved: the server only ever holds opaque ciphertext and
// non-secret metadata, exactly like the CF KV/DO originals. All writes land in
// tmp/ first and rename() into place — a crash never leaves a half-written
// paste visible. Deletion is unlink-then-rmdir, safe to retry.

import { mkdir, readFile, writeFile, rename, unlink, rm, readdir } from 'node:fs/promises';
import path from 'node:path';

let dataDir = null;

/** Initialize (idempotent) and return the data directory. Throws if unusable. */
export async function initDataStore(dir) {
  dataDir = dir;
  for (const sub of ['meta', 'blob', 'tmp']) {
    await mkdir(path.join(dir, sub), { recursive: true });
  }
  return dataDir;
}

function metaPath(id) {
  return path.join(dataDir, 'meta', `${id}.json`);
}
export function blobDir(id) {
  return path.join(dataDir, 'blob', id);
}
function tmpPath(name) {
  // Random suffix so concurrent creators never collide in tmp/.
  return path.join(dataDir, 'tmp', `${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.${name}`);
}

/** Atomic JSON write: tmp file + rename. */
export async function putJson(file, obj) {
  const tmp = tmpPath('w.json');
  await writeFile(tmp, JSON.stringify(obj));
  await rename(tmp, file);
}

export async function getJson(file) {
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
  try {
    const rec = JSON.parse(raw);
    if (rec && typeof rec === 'object' && rec.p) return rec;
  } catch { /* corrupt → treated as missing */ }
  return null;
}

/** Create (or fail) a paste: writes meta, returns true if the id was free. */
export async function createPasteMeta(id, paste, dth, ttl) {
  if (await getJson(metaPath(id)) !== null) return false;
  const exp = ttl > 0 ? Math.floor(Date.now() / 1000) + ttl : 0;
  await putJson(metaPath(id), { p: paste, dth, exp });
  return true;
}

/** Returns { p, dth, exp } or null. Expired records are treated as missing and swept. */
export async function getPasteMeta(id) {
  const rec = await getJson(metaPath(id));
  if (!rec) return null;
  if (rec.exp > 0 && rec.exp <= Date.now() / 1000) {
    await deletePaste(id).catch(() => {});
    return null;
  }
  return rec;
}

export async function deletePaste(id) {
  await unlink(metaPath(id)).catch(() => {});
  await rm(blobDir(id), { recursive: true, force: true });
}

// ── File-paste blobs (chunked ciphertext on disk) ────────────────────────────

/**
 * Append one chunk to a file paste. Chunks are written as individual files
 * named by index; size is enforced here (authoritative, beyond headers).
 * Returns the number of chunks now stored, or null if the chunk index was
 * already occupied (client bug / retry confusion → caller answers 409).
 */
export async function putChunk(id, index, bytes) {
  const dir = blobDir(id);
  await mkdir(dir, { recursive: true });
  const target = path.join(dir, String(index));
  let exists = false;
  try {
    await readFile(target);
    exists = true;
  } catch { /* free */ }
  if (exists) return null;
  const tmp = tmpPath('chunk');
  await writeFile(tmp, bytes);
  await rename(tmp, target);
  return (await readdir(dir)).length;
}

/** Read one chunk. Returns Buffer or null. */
export async function getChunk(id, index) {
  try {
    return await readFile(path.join(blobDir(id), String(index)));
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

/** Total chunks stored for a file paste (for the finalize check). */
export async function chunkCount(id) {
  try {
    return (await readdir(blobDir(id))).length;
  } catch {
    return 0;
  }
}

/**
 * Atomic consume for burn-after-read pastes: rename the meta file away first —
 * whichever concurrent request renames it wins, the loser gets ENOENT → 410 —
 * then read+delete. Replaces the Durable Object's blockConcurrencyWhile.
 */
export async function consumeBurn(id) {
  const meta = metaPath(id);
  const tmp = tmpPath('consume');
  try {
    await rename(meta, tmp);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
  const rec = await getJson(tmp);
  await unlink(tmp).catch(() => {});
  await rm(blobDir(id), { recursive: true, force: true }).catch(() => {});
  if (!rec) return null;
  if (rec.exp > 0 && rec.exp <= Date.now() / 1000) return null;
  return rec;
}

/** Non-consuming head read for burn pastes (never returns ct). */
export async function consumeBurnPeek(id) {
  const rec = await getJson(metaPath(id));
  if (!rec) return null;
  if (rec.exp > 0 && rec.exp <= Date.now() / 1000) {
    await deletePaste(id).catch(() => {});
    return null;
  }
  return rec;
}

