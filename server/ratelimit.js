// server/ratelimit.js — in-process token bucket, keyed by client IP.
//
// Port of src/lib/ratelimit.js (CF native ratelimits). A single Node process
// replaces the edge network: buckets live in a Map, swept lazily. This is
// abuse mitigation per-instance, not authentication — same trust level as the
// original (which was also best-effort). Fails open on internal errors.

const WINDOW_MS = 60_000;
const CREATE_LIMIT = Number(process.env.BINTHERE_RL_CREATE ?? 30);   // per IP / minute
const PUT_LIMIT = Number(process.env.BINTHERE_RL_PUT ?? 60);         // chunk PUTs / minute

const buckets = new Map(); // key: `${kind}|${ip}` → { tokens, last }

function take(kind, ip, limit) {
  const key = `${kind}|${ip}`;
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now - b.last >= WINDOW_MS) {
    b = { tokens: limit, last: now };
  }
  b.last = now;
  if (b.tokens <= 0) {
    buckets.set(key, b);
    return false;
  }
  b.tokens -= 1;
  buckets.set(key, b);
  // Opportunistic sweep so abandoned IPs don't leak memory.
  if (buckets.size > 10_000) {
    for (const [k, v] of buckets) {
      if (now - v.last >= WINDOW_MS) buckets.delete(k);
    }
  }
  return true;
}

/** Extract the client IP: X-Forwarded-For first hop (nginx in front), else socket. */
export function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

export const allowCreate = (ip) => take('create', ip, CREATE_LIMIT);
export const allowPut = (ip) => take('put', ip, PUT_LIMIT);
