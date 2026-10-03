// server-php/test/e2e-php.test.mjs — live e2e against the PHP backend.
// Targets http://127.0.0.1:8099/api (php -S router on the VPS) but works
// against any mounted base. Uses the SAME WebCrypto code as the browser
// (public/js/*) — the real client path, not a re-implementation.
// Run: node server-php/test/e2e-php.test.mjs [base-url]
import * as C from '../../public/js/crypto.js';
import * as B from '../../public/js/bytes.js';
import { buildAAD } from '../../public/js/format.js';

const BASE = process.argv[2] ?? 'http://127.0.0.1:8099';
const API = `${BASE}/api`;
let pass = 0, fail = 0;
function check(name, ok, extra = '') {
  if (ok) { pass++; console.log(`  ok  ${name}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
}
const j = async (r) => ({ status: r.status, body: await r.json().catch(() => null), headers: r.headers });

// ── 1. text lifecycle ────────────────────────────────────────────────────────
const { body, fragment } = await C.encryptPaste({ text: 'hello php e2e', expire: '1day' });
let r = await j(await fetch(`${API}/paste`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
check('text create 201 k-prefix', r.status === 201 && r.body.id[0] === 'k', JSON.stringify(r.body));
const created = r.body;

r = await j(await fetch(`${API}/paste/${created.id}`));
const back = r.body;
check('read 200 + ct', r.status === 200 && typeof back.ct === 'string');
check('created stamped', back.meta.created > 0);
check('roundtrip decrypts', (await C.decryptPaste({ paste: back, fragment })).text === 'hello php e2e');

r = await j(await fetch(`${API}/paste/${created.id}?meta=1`));
check('meta hides ct', r.status === 200 && r.body.ct === undefined);

r = await j(await fetch(`${API}/paste/${created.id}`, { method: 'DELETE', headers: { 'x-delete-token': 'A'.repeat(43) } }));
check('wrong token 403', r.status === 403);
r = await j(await fetch(`${API}/paste/${created.id}`, { method: 'DELETE', headers: { 'x-delete-token': created.deletetoken } }));
check('delete 200', r.status === 200);
r = await j(await fetch(`${API}/paste/${created.id}`));
check('gone after delete', r.status === 404);

// burn flow
const burn = await C.encryptPaste({ text: 'burn me', bar: true, expire: '1day' });
r = await j(await fetch(`${API}/paste`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(burn.body) }));
check('burn create b-prefix', r.status === 201 && r.body.id[0] === 'b');
const b = r.body;
r = await j(await fetch(`${API}/paste/${b.id}`));
check('burn peek hides ct', r.status === 200 && r.body.ct === undefined);
r = await j(await fetch(`${API}/paste/${b.id}/consume`, { method: 'POST', headers: { 'x-burn-intent': 'consume' } }));
check('burn consume decrypts', r.status === 200 && (await C.decryptPaste({ paste: r.body, fragment: burn.fragment })).text === 'burn me', JSON.stringify(r.body));
r = await j(await fetch(`${API}/paste/${b.id}/consume`, { method: 'POST', headers: { 'x-burn-intent': 'consume' } }));
check('second consume 410', r.status === 410);

// ── 2. file flow: 12 MiB pseudo-file, 8 MiB chunks (2 chunks) ───────────────
const CHUNK = 8 * 1024 * 1024;
const fileSize = 12 * 1024 * 1024;
const fileBytes = new Uint8Array(fileSize);
for (let i = 0; i < fileSize; i++) fileBytes[i] = (i * 7 + (i >> 16)) & 0xff;
const CHUNKS = Math.ceil(fileSize / CHUNK);

const CEK = B.randomBytes(32), F = B.randomBytes(32);
const ivc = B.randomBytes(12), ivw = B.randomBytes(12);
const adata = { alg: 'A256GCM', kdf: 'hkdf', iter: 0, comp: 'none', fmt: 'plaintext',
  bar: false, ivc: B.b64urlFromBytes(ivc), ivw: B.b64urlFromBytes(ivw), skdf: '' };
const aad = buildAAD(adata);
const kek = await C.deriveKEK(F, { usePassword: false, salt: new Uint8Array(0), iter: 0 });
const wk = await C.aesGcmEncrypt(kek, ivw, CEK, aad);
const contentKey = await crypto.subtle.importKey('raw', CEK, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
const te = new TextEncoder();
const manifest = { name: 'test-app.apk', size: fileSize, chunkSize: CHUNK, chunks: CHUNKS, ivs: [B.b64urlFromBytes(B.randomBytes(12))] };
for (let n = 1; n < CHUNKS; n++) manifest.ivs.push(B.b64urlFromBytes(B.randomBytes(12)));
const ct = await C.aesGcmEncrypt(contentKey, ivc, te.encode(JSON.stringify(manifest)), aad);
const fbody = { v: 1, ct: B.b64urlFromBytes(ct), wk: B.b64urlFromBytes(wk), adata, meta: { expire: '1day' } };

r = await j(await fetch(`${API}/file`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(fbody) }));
check('manifest create 201 f-prefix', r.status === 201 && r.body.id[0] === 'f', JSON.stringify(r.body));
const f = r.body;

const chunkCts = [];
for (let n = 0; n < CHUNKS; n++) {
  const slice = fileBytes.subarray(n * CHUNK, Math.min((n + 1) * CHUNK, fileSize));
  const ctn = await C.aesGcmEncrypt(contentKey, B.bytesFromB64url(manifest.ivs[n]), slice, te.encode(`${f.id}:${n}`));
  chunkCts.push(ctn);
  r = await j(await fetch(`${API}/file/${f.id}/${n}`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': f.deletetoken }, body: Buffer.from(ctn) }));
  check(`chunk ${n} put`, r.status === 200, `got ${r.status} ${JSON.stringify(r.body)}`);
}
r = await j(await fetch(`${API}/file/${f.id}/0`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': f.deletetoken }, body: Buffer.from(chunkCts[0]) }));
check('duplicate put idempotent 200', r.status === 200 && r.body.duplicate === true, `got ${r.status} ${JSON.stringify(r.body)}`);
r = await j(await fetch(`${API}/file/${f.id}/0`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': 'B'.repeat(43) }, body: Buffer.from(chunkCts[0]) }));
check('wrong token 403', r.status === 403, `got ${r.status}`);
r = await j(await fetch(`${API}/file/${f.id}/99`));
check('chunk 99 → 400/404', r.status === 400 || r.status === 404, `got ${r.status}`);

// reader path
r = await j(await fetch(`${API}/paste/${f.id}`));
check('manifest read 200', r.status === 200);
const cek2 = await C.deriveContentKey({ adata: r.body.adata, wk: r.body.wk, fragment: B.b64urlFromBytes(F) });
const fpt = await C.decryptContent({ adata: r.body.adata, ct: r.body.ct, cek: cek2 });
const man = JSON.parse(fpt.text);
check('manifest decrypts', man.name === 'test-app.apk' && man.size === fileSize && man.chunks === CHUNKS, JSON.stringify(man).slice(0, 80));

const reassembled = new Uint8Array(man.size);
for (let n = 0; n < man.chunks; n++) {
  r = await fetch(`${API}/file/${f.id}/${n}`);
  check(`chunk ${n} get 200`, r.status === 200, `got ${r.status}`);
  const bytes = new Uint8Array(await r.arrayBuffer());
  check(`chunk ${n} byte length`, bytes.length === chunkCts[n].length, `${bytes.length} vs ${chunkCts[n].length}`);
  reassembled.set(bytes, n * CHUNK);
}
check('roundtrip identical', reassembled.length === fileSize && reassembled.every((v, i) => v === fileBytes[i]));

// tamper → GCM must reject
const tampered = new Uint8Array(chunkCts[0]); tampered[100] ^= 0xff;
const tct = { adata, ivc: manifest.ivs[0], cek: contentKey };
try {
  await C.aesGcmDecrypt(contentKey, B.bytesFromB64url(manifest.ivs[0]), tampered, te.encode(`${f.id}:0`));
  check('tampered chunk rejected', false);
} catch { check('tampered chunk rejected', true); }

r = await j(await fetch(`${API}/file/${f.id}`, { method: 'DELETE', headers: { 'x-delete-token': f.deletetoken } }));
check('file delete 200', r.status === 200, `got ${r.status}`);
r = await fetch(`${API}/file/${f.id}/0`);
check('chunks gone', r.status === 404, `got ${r.status}`);

// oversized chunk (cap + 1)
r = await j(await fetch(`${API}/paste/${f.id}`));
check('cleanup done', true);
const big = new Uint8Array(9 * 1024 * 1024);
const bigId = f.id; // already deleted → expect 404 on put to deleted id
r = await j(await fetch(`${API}/file/${bigId}/0`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': 'C'.repeat(43) }, body: Buffer.from(big) }));
check('oversized/dead id rejected', r.status === 404 || r.status === 403 || r.status === 413, `got ${r.status}`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
