<?php
// ids.php — id/token handling. Port of server/ids.js: 128-bit CSPRNG + class
// prefix (k=KV, b=burn, f=file), 256-bit delete tokens stored only as SHA-256,
// constant-time comparison via hash_equals.

const ID_RANDOM_BYTES = 16;   // 128-bit entropy
const ID_B64_LEN = 22;        // b64url length of 16 bytes (unpadded)
const TOKEN_BYTES = 32;       // 256-bit delete token
const CLASS_KV = 'k';
const CLASS_BURN = 'b';
const CLASS_FILE = 'f';

function b64url_encode(string $bytes): string {
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

/** Generate a paste id: class prefix + base64url(16 CSPRNG bytes). */
function gen_id(string $cls): string {
    return $cls . b64url_encode(random_bytes(ID_RANDOM_BYTES));
}

/**
 * Parse/validate a paste id → ['cls'=>..., 'burn'=>bool, 'file'=>bool] or null
 * (callers map to 404).
 */
function parse_id($id) {
    if (!is_string($id) || strlen($id) !== ID_B64_LEN + 1) return null;
    $cls = $id[0];
    if ($cls !== CLASS_KV && $cls !== CLASS_BURN && $cls !== CLASS_FILE) return null;
    $bin = b64url_decode(substr($id, 1));
    if ($bin === null || strlen($bin) !== ID_RANDOM_BYTES) return null;
    return ['cls' => $cls, 'burn' => $cls === CLASS_BURN, 'file' => $cls === CLASS_FILE];
}

function gen_delete_token(): string {
    return b64url_encode(random_bytes(TOKEN_BYTES));
}

/** SHA-256 (hex) of a token string — the only stored form. */
function hash_token(string $token): string {
    return hash('sha256', $token);
}

/** Constant-time token verification; fails closed on malformed input. */
function verify_token($presented, string $storedHashHex): bool {
    if (!is_string($presented)) return false;
    $bin = b64url_decode($presented);
    if ($bin === null || strlen($bin) !== TOKEN_BYTES) return false;
    return hash_equals($storedHashHex, hash_token($presented));
}
