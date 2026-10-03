// server/ids.js — id/token handling for the Node port.
//
// Same 128-bit CSPRNG + class-prefix scheme as src/lib/ids.js (SPEC.md §7), with
// a third class 'f' for file pastes. Imports the shared byte helpers directly
// from public/js/ (single source of truth, same as the Worker does).

import {
  randomBytes, b64urlFromBytes, bytesFromB64url, utf8, sha256Hex, timingSafeEqualHex,
} from '../public/js/bytes.js';

const CLASS_KV = 'k';
const CLASS_BURN = 'b';
const CLASS_FILE = 'f';
const ID_RANDOM_BYTES = 16;
const ID_B64_LEN = 22;
const TOKEN_BYTES = 32;

/** Generate a paste id: class prefix + base64url(16 CSPRNG bytes). */
export function genId(cls) {
  return cls + b64urlFromBytes(randomBytes(ID_RANDOM_BYTES));
}

/**
 * Parse/validate a paste id → { cls, burn, file } or null (callers map to 404).
 * Note: the upstream ID_RE (cli/src/url.js) only accepts k|b; file ids are an
 * extension — see server/README.md.
 */
export function parseId(id) {
  if (typeof id !== 'string' || id.length !== ID_B64_LEN + 1) return null;
  const cls = id[0];
  if (cls !== CLASS_KV && cls !== CLASS_BURN && cls !== CLASS_FILE) return null;
  try {
    if (bytesFromB64url(id.slice(1)).length !== ID_RANDOM_BYTES) return null;
  } catch {
    return null;
  }
  return { cls, burn: cls === CLASS_BURN, file: cls === CLASS_FILE };
}

export function genDeleteToken() {
  return b64urlFromBytes(randomBytes(TOKEN_BYTES));
}

export function hashToken(token) {
  return sha256Hex(utf8(token));
}

export async function verifyToken(presented, storedHashHex) {
  if (typeof presented !== 'string' || typeof storedHashHex !== 'string') return false;
  try {
    if (bytesFromB64url(presented).length !== TOKEN_BYTES) return false;
  } catch {
    return false;
  }
  return timingSafeEqualHex(await hashToken(presented), storedHashHex);
}
