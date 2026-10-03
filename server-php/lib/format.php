<?php
// format.php — port of public/js/format.js (format v1 validation + AAD).
// The PHP server must validate exactly what the Worker validates: this file is
// a line-faithful port of the JS logic. Keep in sync with upstream format.js.

const FORMAT_VERSION = 1;

const EXPIRE_SECONDS = [
    '5min' => 300, '10min' => 600, '1hour' => 3600, '1day' => 86400,
    '1week' => 604800, '1month' => 2592000, '1year' => 31536000, 'never' => 0,
];

const ITER_V1 = 310000;
const ITER_MIN = 100000;
const ITER_MAX = 1000000;

const MAX_CT_B64 = 3000000; // ~2.25 MiB of ciphertext
const MAX_WK_B64 = 128;     // wrapped CEK is 48 bytes → ~64 b64url chars

const ADATA_KEYS = ['alg', 'kdf', 'iter', 'comp', 'fmt', 'bar', 'ivc', 'ivw', 'skdf'];
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

const KDFS = ['hkdf', 'pbkdf2-hkdf'];
const COMP = ['gzip', 'none'];
const FORMATS = ['plaintext', 'code', 'markdown'];

/** Thrown for any format violation; callers map to HTTP 400. */
class FormatError extends Exception {}

function is_plain_object($v): bool {
    return is_array($v) && !isset($v[0]) === false ? array_values($v) === $v ? false : true : false;
}

/** PHP arrays merge the list/map concepts; a JSON object must decode to a map. */
function is_json_object($v): bool {
    return is_array($v) && (count($v) === 0 || array_keys($v) !== range(0, count($v) - 1));
}

function assert_no_dangerous_keys(array $obj, string $where) {
    foreach (DANGEROUS_KEYS as $k) {
        if (array_key_exists($k, $obj)) {
            throw new FormatError("illegal key \"{$k}\" in {$where}");
        }
    }
}

/** Exact key-set check: obj must have exactly $allowed keys, no more, no less. */
function assert_exact_keys(array $obj, array $allowed, string $where) {
    assert_no_dangerous_keys($obj, $where);
    foreach (array_keys($obj) as $k) {
        if (!in_array($k, $allowed, true)) {
            throw new FormatError("unknown field \"{$k}\" in {$where}");
        }
    }
    foreach ($allowed as $k) {
        if (!array_key_exists($k, $obj)) {
            throw new FormatError("missing field \"{$k}\" in {$where}");
        }
    }
}

/**
 * Strict base64url decode (RFC 4648 §3.5 canonical form). Returns byte string
 * or null. Mirrors public/js/bytes.js bytesFromB64url: rejects non-alphabet
 * chars, wrong padding, and non-zero unused low bits in the final character.
 */
function b64url_decode(string $s) {
    if (!preg_match('/^[A-Za-z0-9_-]*$/', $s) || strlen($s) % 4 === 1) return null;
    $rem = strlen($s) % 4;
    if ($rem !== 0) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $v = strpos($alphabet, $s[strlen($s) - 1]);
        if ($v === false) return null;
        if ($rem === 2) { if (($v & 0b1111) !== 0) return null; }
        else /* rem 3 */ { if (($v & 0b11) !== 0) return null; }
    }
    $b64 = strtr($s, '-_', '+/');
    if ($rem === 2) $b64 .= '=='; elseif ($rem === 3) $b64 .= '=';
    $bin = base64_decode($b64, true);
    return $bin === false ? null : $bin;
}

function b64url_byte_length(string $s, string $where): int {
    $bin = b64url_decode($s);
    if ($bin === null) throw new FormatError("invalid base64url in {$where}");
    return strlen($bin);
}

function validate_wk(string $wk) {
    if (strlen($wk) === 0 || strlen($wk) > MAX_WK_B64) {
        throw new FormatError('wk 无效');
    }
    if (b64url_byte_length($wk, 'wk') !== 48) throw new FormatError('wk 长度无效');
}

/** Validate adata, return allowlisted copy. Throws FormatError. */
function validate_adata(array $a): array {
    assert_exact_keys($a, ADATA_KEYS, 'adata');

    if ($a['alg'] !== 'A256GCM') throw new FormatError('不支持的加密算法');
    if (!in_array($a['kdf'], KDFS, true)) throw new FormatError('不支持的密钥派生方式');
    if (!in_array($a['comp'], COMP, true)) throw new FormatError('不支持的压缩方式');
    if (!in_array($a['fmt'], FORMATS, true)) throw new FormatError('不支持的格式');
    if (!is_bool($a['bar'])) throw new FormatError('bar 必须为布尔值');

    // JSON ints arrive as PHP int/float; require a true integer (JS Number.isInteger).
    if (!is_int($a['iter'])) throw new FormatError('iter 必须为整数');
    if ($a['kdf'] === 'hkdf') {
        if ($a['iter'] !== 0) throw new FormatError('hkdf 的 iter 必须为 0');
    } else {
        if ($a['iter'] < ITER_MIN || $a['iter'] > ITER_MAX) throw new FormatError('iter 超出范围');
    }

    if (!is_string($a['ivc']) || b64url_byte_length($a['ivc'], 'ivc') !== 12) {
        throw new FormatError('ivc 无效');
    }
    if (!is_string($a['ivw']) || b64url_byte_length($a['ivw'], 'ivw') !== 12) {
        throw new FormatError('ivw 无效');
    }
    if (!is_string($a['skdf'])) throw new FormatError('skdf 无效');
    if ($a['kdf'] === 'pbkdf2-hkdf') {
        if (b64url_byte_length($a['skdf'], 'skdf') !== 16) throw new FormatError('skdf 长度无效');
    } elseif ($a['skdf'] !== '') {
        throw new FormatError('hkdf 的 skdf 必须为空');
    }

    return [
        'alg' => $a['alg'], 'kdf' => $a['kdf'], 'iter' => $a['iter'], 'comp' => $a['comp'],
        'fmt' => $a['fmt'], 'bar' => $a['bar'], 'ivc' => $a['ivc'], 'ivw' => $a['ivw'],
        'skdf' => $a['skdf'],
    ];
}

/** Validate meta, return clean copy. Throws FormatError. */
function validate_meta(array $m): array {
    assert_no_dangerous_keys($m, 'meta');
    foreach (array_keys($m) as $k) {
        if ($k !== 'expire' && $k !== 'created') {
            throw new FormatError("unknown field \"{$k}\" in meta");
        }
    }
    if (!isset($m['expire']) || !is_string($m['expire']) || !array_key_exists($m['expire'], EXPIRE_SECONDS)) {
        throw new FormatError('expire 无效');
    }
    if (array_key_exists('created', $m)) {
        if (!is_int($m['created']) || $m['created'] < 0) throw new FormatError('created 无效');
        return ['expire' => $m['expire'], 'created' => $m['created']];
    }
    return ['expire' => $m['expire']];
}

/**
 * Validate a paste object against format v1; return clean allowlisted copy.
 * Throws FormatError. Mirrors validatePaste.
 */
function validate_paste(array $input): array {
    assert_exact_keys($input, ['v', 'ct', 'wk', 'adata', 'meta'], 'paste');

    if ($input['v'] !== FORMAT_VERSION) throw new FormatError('不支持的版本');

    $ct = $input['ct'];
    if (!is_string($ct) || strlen($ct) === 0 || strlen($ct) > MAX_CT_B64) {
        throw new FormatError('ct 无效');
    }
    b64url_byte_length($ct, 'ct');
    validate_wk($input['wk']);

    return [
        'v' => FORMAT_VERSION, 'ct' => $ct, 'wk' => $input['wk'],
        'adata' => validate_adata($input['adata']), 'meta' => validate_meta($input['meta']),
    ];
}
