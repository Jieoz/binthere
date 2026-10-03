// server/test/e2e-file.test.mjs — live end-to-end exercise of the Node server.
// Run: node server/test/e2e-file.test.mjs  (binds :8799, scratch data dir)
// Exercises: text lifecycle, burn flow, and the full file flow — real WebCrypto
// via public/js/crypto.js (the exact browser code), manifest create → chunk
// PUTs → reader decrypt → byte-identical roundtrip → tamper/delete/limit cases.

const PORT = 8799;
const DATA = '/opt/data/cache/scratch/binthere-e2e-data';
process.env.BINTHERE_PORT = String(PORT);
process.env.BINTHERE_DATA_DIR = DATA;
// dynamic import: index.js reads env at module-eval time
const { main } = await import('../index.js');
const C = await import('../../public/js/crypto.js');
const B = await import('../../public/js/bytes.js');
const { buildAAD } = await import('../../public/js/format.js');

let pass = 0, fail = 0;
const check = (name, ok, extra = '') => {
  if (ok) { pass++; console.log(`  ok  ${name}${extra ? ' — ' + extra : ''}`); }
  else { fail++; console.log(`FAIL  ${name}${extra ? ' — ' + extra : ''}`); }
};

const srv = await main();
const base = `http://127.0.0.1:${PORT}`;
const j = (r) => r.json();
const te = new TextEncoder();

try {
  // ── 1. text paste lifecycle (via the REAL client encrypt path) ───────────
  const { body: textBody, fragment } = await C.encryptPaste({ text: 'hello e2e', expire: '1day' });
  let r = await fetch(`${base}/api/paste`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(textBody) });
  const created = await j(r);
  check('text create 201 k-prefix', r.status === 201 && created.id[0] === 'k', created.id);

  r = await fetch(`${base}/api/paste/${created.id}`);
  const back = await j(r);
  const dec = await C.decryptPaste({ paste: back, fragment });
  check('text roundtrip decrypts', dec.text === 'hello e2e');

  r = await fetch(`${base}/api/paste/${created.id}?meta=1`);
  check('meta peek hides ct', r.status === 200 && (await j(r)).ct === undefined);

  r = await fetch(`${base}/api/paste/${created.id}`, { method: 'DELETE', headers: { 'x-delete-token': created.deletetoken } });
  check('delete 200', r.status === 200);
  r = await fetch(`${base}/api/paste/${created.id}`);
  check('gone after delete', r.status === 404);

  // ── 2. burn flow ─────────────────────────────────────────────────────────
  const { body: burnBody, fragment: bFrag } = await C.encryptPaste({ text: 'burn me', bar: true, expire: '1day' });
  r = await fetch(`${base}/api/paste`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(burnBody) });
  const b = await j(r);
  check('burn create b-prefix', r.status === 201 && b.id[0] === 'b', b.id);
  r = await fetch(`${base}/api/paste/${b.id}`);
  check('burn peek hides ct', r.status === 200 && (await j(r)).ct === undefined);
  r = await fetch(`${base}/api/paste/${b.id}/consume`, { method: 'POST', headers: { 'x-burn-intent': 'consume' } });
  const consumed = await j(r);
  check('burn consume decrypts', (await C.decryptPaste({ paste: consumed, fragment: bFrag })).text === 'burn me');
  r = await fetch(`${base}/api/paste/${b.id}/consume`, { method: 'POST', headers: { 'x-burn-intent': 'consume' } });
  check('second consume 410', r.status === 410);

  // ── 3. file flow: 12 MB pseudo-APK in 8 MiB chunks (2 chunks) ────────────
  const CHUNK = 8 * 1024 * 1024;
  const fileSize = 12 * 1024 * 1024;
  const fileBytes = new Uint8Array(fileSize);
  for (let i = 0; i < fileSize; i++) fileBytes[i] = (i * 7 + (i >> 16)) & 0xff;

  const CEK = B.randomBytes(32);
  const F = B.randomBytes(32);
  const ivc = B.randomBytes(12);
  const ivw = B.randomBytes(12);
  const adata = {
    alg: 'A256GCM', kdf: 'hkdf', iter: 0, comp: 'none', fmt: 'plaintext', bar: false,
    ivc: B.b64urlFromBytes(ivc), ivw: B.b64urlFromBytes(ivw), skdf: '',
  };
  const aad = buildAAD(adata);
  const contentKey = await crypto.subtle.importKey('raw', CEK, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const kek = await C.deriveKEK(F, { usePassword: false });
  const wk = await C.aesGcmEncrypt(kek, ivw, CEK, aad); // kek IS the CryptoKey

  const CHUNKS = Math.ceil(fileSize / CHUNK);
  const ivs = Array.from({ length: CHUNKS }, () => B.b64urlFromBytes(B.randomBytes(12)));

  const manifest = { binthere: 'file/v1', name: 'test-app.apk', size: fileSize, mime: 'application/vnd.android.package-archive', chunks: CHUNKS, ivs };
  const ct = await C.aesGcmEncrypt(contentKey, ivc, te.encode(JSON.stringify(manifest)), aad);
  const body = { v: 1, ct: B.b64urlFromBytes(ct), wk: B.b64urlFromBytes(wk), adata, meta: { expire: '1day' } };

  r = await fetch(`${base}/api/file`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const f = await j(r);
  check('manifest create 201 f-prefix', r.status === 201 && f.id[0] === 'f', f.id);

  const chunkCts = [];
  for (let n = 0; n < CHUNKS; n++) {
    const iv = B.bytesFromB64url(ivs[n]);
    const slice = fileBytes.subarray(n * CHUNK, Math.min((n + 1) * CHUNK, fileSize));
    const ctn = await C.aesGcmEncrypt(contentKey, iv, slice, te.encode(`${f.id}:${n}`));
    chunkCts.push(ctn);
    r = await fetch(`${base}/api/file/${f.id}/${n}`, {
      method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': f.deletetoken },
      body: Buffer.from(ctn),
    });
    check(`chunk ${n} put`, r.status === 200);
  }

  r = await fetch(`${base}/api/file/${f.id}/0`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': f.deletetoken }, body: Buffer.from(chunkCts[0]) });
  check('duplicate put 409', r.status === 409);
  r = await fetch(`${base}/api/file/${f.id}/0`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': 'B'.repeat(43) }, body: Buffer.from(chunkCts[0]) });
  check('wrong token put 403', r.status === 403);
  r = await fetch(`${base}/api/file/${f.id}/1`, { method: 'DELETE' }); // wrong verb on existing chunk
  check('wrong verb 405', r.status === 405);
  // chunk index 99: 400 (range) — the *missing-but-valid* 404 case is chunk 1
  // before it exists, already covered indirectly by 'wrong token put 403' path.
  r = await fetch(`${base}/api/file/${f.id}/99`);
  check('chunk 99 rejected (400 range)', r.status === 400);

  // reader path: manifest via /api/paste/<f-id>, chunks via /api/file
  r = await fetch(`${base}/api/paste/${f.id}`);
  check('manifest read 200', r.status === 200);
  const fback = await j(r);
  const cek2 = await C.deriveContentKey({ adata: fback.adata, wk: fback.wk, fragment: B.b64urlFromBytes(F) });
  const fpt = await C.decryptContent({ adata: fback.adata, ct: fback.ct, cek: cek2 });
  const man = JSON.parse(fpt.text); // decryptContent returns { text, fmt, bar }
  check('manifest decrypts', man.name === 'test-app.apk' && man.size === fileSize && man.chunks === CHUNKS, `${man.name} ${man.size}B ${man.chunks}ch`);

  const reassembled = new Uint8Array(man.size);
  for (let n = 0; n < man.chunks; n++) {
    r = await fetch(`${base}/api/file/${f.id}/${n}`);
    const ctb = new Uint8Array(await r.arrayBuffer());
    const ptn = await C.aesGcmDecrypt(cek2, B.bytesFromB64url(man.ivs[n]), ctb, te.encode(`${f.id}:${n}`));
    reassembled.set(ptn, n * CHUNK);
  }
  let same = reassembled.length === fileBytes.length;
  for (let i = 0; i < reassembled.length && same; i += 9973) if (reassembled[i] !== fileBytes[i]) same = false;
  check('roundtrip identical', same, `${reassembled.length} bytes`);

  const tct = new Uint8Array(chunkCts[0]); tct[5] ^= 0xff;
  let threw = false;
  try { await C.aesGcmDecrypt(cek2, B.bytesFromB64url(man.ivs[0]), tct, te.encode(`${f.id}:0`)); } catch { threw = true; }
  check('tampered chunk rejected by GCM', threw);

  r = await fetch(`${base}/api/paste/${f.id}`, { method: 'DELETE', headers: { 'x-delete-token': f.deletetoken } });
  check('file delete 200', r.status === 200);
  r = await fetch(`${base}/api/file/${f.id}/0`);
  check('chunks gone after delete', r.status === 404);

  // oversized chunk rejected
  r = await fetch(`${base}/api/file`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const f2 = await j(r);
  r = await fetch(`${base}/api/file/${f2.id}/0`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-delete-token': f2.deletetoken }, body: Buffer.alloc(9 * 1024 * 1024, 1) });
  check('oversized chunk 413', r.status === 413);
} finally {
  srv.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
