# binthere-node — self-hosted VPS server

Zero-dependency Node.js port of the binthere Cloudflare Worker, plus a large-file
extension the Worker cannot offer (CF caps request bodies at 100 MB and KV values
at 25 MB; a VPS has neither cap). The v1 wire protocol is untouched — text
pastes interoperate with the official CLI and the upstream test vectors.

## Run

```
node server/index.js
```

Requires Node ≥ 20 (uses only built-ins: `node:http`, `node:crypto`, `node:fs`).
No `npm install`. Static assets are served from `../public` — the same UI as the
hosted version.

Nginx in front (TLS + body size + streaming):

```
location / {
    proxy_pass http://127.0.0.1:8788;
    proxy_http_version 1.1;
    client_max_body_size 520m;   # BINTHERE_MAX_FILE + headroom
    proxy_request_buffering off; # stream big uploads to disk
}
```

## Environment

| Variable              | Default    | Meaning                                   |
|-----------------------|------------|-------------------------------------------|
| `BINTHERE_PORT`       | `8788`     | Listen port                                |
| `BINTHERE_HOST`       | `127.0.0.1`| Bind address (keep loopback behind nginx)  |
| `BINTHERE_DATA_DIR`   | `./data`   | Storage root (meta/ + blob/ + tmp/)        |
| `BINTHERE_CHUNK`      | `8`        | Chunk size in MiB (ciphertext cap +16 B GCM tag headroom) |
| `BINTHERE_MAX_FILE`   | `512`      | Total file size cap in MiB                 |
| `BINTHERE_RL_CREATE`  | `30`       | Paste creates per IP per minute            |
| `BINTHERE_RL_PUT`     | `60`       | Chunk PUTs per IP per minute               |

## Storage layout

```
<BINTHERE_DATA_DIR>/
  meta/<id>.json    paste record: { p, dth (delete-token SHA-256), exp }
  blob/<id>/<n>     chunk n ciphertext of file paste <id>
  tmp/              staging area; writes land here, rename() into place
```

Nothing is ever stored in plaintext: the server sees only ciphertext, wrapped
keys, and non-secret metadata (SPEC.md §2–3 still holds).

## API

Text paste API — identical to upstream (SPEC.md §6–9): `POST /api/paste`,
`GET /api/paste/:id[?meta=1]`, `POST /api/paste/:id/consume` (burn, requires
`X-Burn-Intent: consume`), `DELETE /api/paste/:id` (`X-Delete-Token`), stars.

File extension (this fork; documented here as the authoritative reference):

- `POST /api/file` — create a file paste. Body: a format-v1 paste whose
  encrypted plaintext is the manifest JSON:
  `{ binthere: "file/v1", name, size, mime, chunks, ivs: [b64url per chunk] }`.
  The name/mime ride encrypted — the server never sees the filename.
  Returns `{ id, deletetoken }` (id prefixed `f`).
- `PUT /api/file/:id/:n` — upload chunk `n` ciphertext (raw bytes,
  `application/octet-stream`, `X-Delete-Token` required). AES-256-GCM with
  AAD = `<id>:<n>` binds each chunk to its position. Idempotency: re-PUT of an
  identical chunk → 200; different bytes for an existing chunk → 409.
- `GET /api/file/:id/:n` — download chunk `n` (streamed from disk).
- File pastes delete/expire like any paste; delete also wipes all chunks.
- Burn-after-read is not combined with file pastes (`bar:true` on a manifest →
  behaves as a normal paste; the manifest flag decides nothing here).

Client crypto responsibilities (same trust model as text): the client generates
a fresh 32-byte content key per chunk IV set, encrypts each chunk locally, and
only then uploads; the key travels in the URL fragment, never to the server.

## Tests

```
node server/test/e2e-file.test.mjs
```

23 checks: text lifecycle, burn flow, manifest create/decrypt, chunk
upload/download/duplicate/tamper(GCM)/range/oversize, full roundtrip of a
12 MiB two-chunk file (byte-identical), and delete cleanup. A separate
50 MB / 7-chunk exercise measured 0.8 s end-to-end locally with SHA-256 match.
