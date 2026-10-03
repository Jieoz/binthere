// files-ui.js — client-side large-file upload/download for self-host mounts.
//
// A file paste is a normal format-v1 paste whose encrypted plaintext is a
// manifest JSON: { name, size, chunkSize, chunks, ivs[] }. The raw bytes are
// split into 8 MiB chunks, each encrypted with the SAME content key but its own
// random IV, bound via GCM AAD `<id>:<n>` so a chunk cannot be swapped between
// slots or pastes. The server only ever sees ciphertext (zero-knowledge holds).
//
// Upload is resumable in the trivial sense: duplicate PUTs are idempotent (200
// {duplicate:true}), so a failed transfer can simply be retried.

import { randomBytes, b64urlFromBytes, bytesFromB64url } from './bytes.js';
import { buildAAD } from './format.js';
import { aesGcmEncrypt, aesGcmDecrypt } from './crypto.js';
import { btUrl } from './base.js';

export const CHUNK_SIZE = 8 * 1024 * 1024;      // plaintext bytes per chunk
export const MAX_FILE = 512 * 1024 * 1024;      // 512 MiB overall budget
const MAX_CHUNKS = 64;

function api(path) { return btUrl('/api') + path; }

async function j(res, what) {
  let data = null;
  try { data = await res.json(); } catch { /* fall through */ }
  if (!res.ok || !data) {
    const msg = data && typeof data.error === 'string' ? data.error : null;
    throw new Error(msg || `${what}失败（HTTP ${res.status}）`);
  }
  return data;
}

/**
 * Encrypt + upload a File. onProgress(done, total) fires after each chunk.
 * Returns { id, deletetoken, fragment } — fragment is the share secret (#…).
 */
export async function uploadFile(file, { onProgress } = {}) {
  if (file.size > MAX_FILE) {
    throw new Error(`文件过大（上限 ${Math.floor(MAX_FILE / 1024 / 1024)} MiB）。`);
  }
  const chunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
  if (chunks > MAX_CHUNKS) throw new Error('文件过大（分块数超限）。');

  // Keys: same envelope as a text paste (CEK content key, F fragment secret).
  const CEK = randomBytes(32);
  const F = randomBytes(32);
  const ivc = randomBytes(12);
  const ivw = randomBytes(12);
  const ivs = Array.from({ length: chunks }, () => b64urlFromBytes(randomBytes(12)));

  const adata = {
    alg: 'A256GCM', kdf: 'hkdf', iter: 0, comp: 'none', fmt: 'plaintext',
    bar: false, ivc: b64urlFromBytes(ivc), ivw: b64urlFromBytes(ivw), skdf: '',
  };
  const aad = buildAAD(adata);

  const kekK = await crypto.subtle.importKey('raw', F, { name: 'HKDF' }, false, ['deriveBits']);
  const kekBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('binthere/v1 kek') },
    kekK, 256);
  const kek = await crypto.subtle.importKey('raw', kekBits, { name: 'AES-GCM' }, false, ['encrypt']);
  const contentKey = await crypto.subtle.importKey('raw', CEK, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

  const wk = await aesGcmEncrypt(kek, ivw, CEK, aad);
  const manifest = { name: file.name, size: file.size, chunkSize: CHUNK_SIZE, chunks, ivs };
  const ct = await aesGcmEncrypt(contentKey, ivc,
    new TextEncoder().encode(JSON.stringify(manifest)), aad);

  // File pastes are KV-class (idempotent reads — the receiver may download
  // repeatedly within the TTL), so bar stays false throughout: the manifest is
  // encrypted with the same AAD that will authenticate it on read.
  const body = {
    v: 1, ct: b64urlFromBytes(ct), wk: b64urlFromBytes(wk),
    adata, meta: { expire: '1day' },
  };
  const created = await j(await fetch(api('/file'), {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }), '创建文件');

  // Sequential PUTs keep memory flat; each chunk reads a fresh slice.
  for (let n = 0; n < chunks; n++) {
    const slice = file.slice(n * CHUNK_SIZE, Math.min((n + 1) * CHUNK_SIZE, file.size));
    const plain = new Uint8Array(await slice.arrayBuffer());
    const iv = bytesFromB64url(ivs[n]);
    const ctn = await aesGcmEncrypt(contentKey, iv, plain, new TextEncoder().encode(`${created.id}:${n}`));
    const res = await fetch(api(`/file/${created.id}/${n}`), {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream', 'x-delete-token': created.deletetoken },
      body: ctn,
    });
    if (!res.ok) {
      let msg = null;
      try { msg = (await res.json()).error; } catch { /* ignore */ }
      throw new Error(msg || `上传第 ${n + 1} 块失败（HTTP ${res.status}）`);
    }
    if (onProgress) onProgress(n + 1, chunks);
  }
  return { id: created.id, deletetoken: created.deletetoken, fragment: b64urlFromBytes(F) };
}

/**
 * Fetch + decrypt a file paste. Returns { name, size, bytes, mime }.
 * The manifest paste must still exist (KV-class, idempotent read).
 */
export async function downloadFile(id, fragment) {
  const res = await fetch(api(`/paste/${encodeURIComponent(id)}`), { cache: 'no-store' });
  const paste = await j(res, '读取文件');
  const F = bytesFromB64url(fragment);
  if (F.length !== 32) throw new Error('链接密钥无效。');

  const kekK = await crypto.subtle.importKey('raw', F, { name: 'HKDF' }, false, ['deriveBits']);
  const kekBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('binthere/v1 kek') },
    kekK, 256);
  const kek = await crypto.subtle.importKey('raw', kekBits, { name: 'AES-GCM' }, false, ['decrypt']);
  const contentKey = await aesGcmDecrypt(kek, bytesFromB64url(paste.adata.ivw),
    bytesFromB64url(paste.wk), buildAAD(paste.adata));
  const ck = await crypto.subtle.importKey('raw', contentKey, { name: 'AES-GCM' }, false, ['decrypt']);

  const man = JSON.parse(new TextDecoder().decode(await aesGcmDecrypt(ck,
    bytesFromB64url(paste.adata.ivc), bytesFromB64url(paste.ct), buildAAD(paste.adata))));
  if (!man || typeof man.size !== 'number' || !Array.isArray(man.ivs)) throw new Error('文件信息无效。');

  const out = new Uint8Array(man.size);
  for (let n = 0; n < man.chunks; n++) {
    const r = await fetch(api(`/file/${id}/${n}`), { cache: 'no-store' });
    if (!r.ok) throw new Error(`下载第 ${n + 1} 块失败（HTTP ${r.status}）`);
    const cb = new Uint8Array(await r.arrayBuffer());
    const plain = await aesGcmDecrypt(ck, bytesFromB64url(man.ivs[n]), cb, new TextEncoder().encode(`${id}:${n}`));
    out.set(plain, n * man.chunkSize);
  }
  return { name: String(man.name || 'file'), size: man.size, bytes: out };
}

/** Trigger a browser save dialog for decrypted bytes. */
export function saveAs({ name, bytes }) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 30000);
}
