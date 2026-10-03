<?php
// api.php — binthere PHP backend, single entry point.
// nginx maps <base>/api/* here (see server-php/README.md for the location
// blocks). Wire format is identical to the CF Worker / the Node port:
//
//   POST   /api/paste                create text paste (format v1 JSON)
//   GET    /api/paste/<id>           read (burn: never consumes; ?meta=1 = head)
//   POST   /api/paste/<id>/consume   destructive burn read (X-Burn-Intent: consume)
//   DELETE /api/paste/<id>           delete (X-Delete-Token)
//   POST   /api/file                 create file paste (manifest = format v1 JSON)
//   PUT    /api/file/<id>/<n>        upload ciphertext chunk (X-Delete-Token)
//   GET    /api/file/<id>/<n>        download ciphertext chunk (X-Accel-Redirect)
//   GET    /api/stars                private deployment → {"stars":null}
//
// Responses/headers mirror upstream exactly: {id, deletetoken} on create,
// 410 for burned, 403 wrong token, 415 wrong content type, 429 rate limited.

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0'); // never leak paths/stack to the wire
// Don't let php.ini's 512M post cap abort us before our own 413 — chunk bodies
// are read with a hard in-code cap; meta JSON is capped by MAX_CT_B64 checks.

require_once __DIR__ . '/lib/format.php';
require_once __DIR__ . '/lib/ids.php';
require_once __DIR__ . '/lib/store.php';
require_once __DIR__ . '/lib/files.php';

const BT_DATA_DIR = '/home/btdata'; // ciphertext store (env BT_DATA_DIR)

// ── response helpers ─────────────────────────────────────────────────────────

/** Send a JSON error and exit. */
function json_error(int $status, string $message, array $headers = []) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    foreach ($headers as $k => $v) header("{$k}: {$v}");
    echo json_encode(['error' => $message]);
    exit;
}

/** Send a JSON body and exit. */
function json_out(array $body, int $status = 200, array $headers = []) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    foreach ($headers as $k => $v) header("{$k}: {$v}");
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

// ── shared create flow (text k/b + file f) ───────────────────────────────────

/**
 * Read the JSON body (capped at MAX_CT_B64 + slack) and validate it as a
 * format-v1 paste. Exits with the mapped error on any violation.
 */
function read_and_validate_paste(): array {
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $ctype = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '', 2)[0]));
    if ($ctype !== 'application/json') {
        json_error(415, 'Content-Type must be application/json.');
    }
    if (!rl_take('create', client_ip(), BT_RL_CREATE)) {
        json_error(429, 'Rate limit exceeded. Try again shortly.');
    }

    // Body cap: the largest legal ct (b64) + wk + adata + slack.
    $cap = MAX_CT_B64 + 4096;
    if (isset($_SERVER['CONTENT_LENGTH']) && (int)$_SERVER['CONTENT_LENGTH'] > $cap) {
        json_error(413, 'Document is too large.');
    }
    $raw = read_capped_body($cap);
    if ($raw === null) json_error(413, 'Document is too large.');

    $parsed = json_decode($raw, true);
    if (!is_array($parsed)) json_error(400, 'Invalid JSON body.');
    // Mirror the JS pre-check so an oversized ct reports a clean 413 (a PHP
    // warning on string offsets would otherwise 500).
    if (isset($parsed['ct']) && is_string($parsed['ct']) && strlen($parsed['ct']) > MAX_CT_B64) {
        json_error(413, 'Document is too large.');
    }
    // JSON objects decode to PHP arrays; reject list-shaped bodies early.
    if (count($parsed) > 0 && array_keys($parsed) === range(0, count($parsed) - 1)) {
        json_error(400, 'paste must be an object');
    }
    try {
        return validate_paste($parsed);
    } catch (FormatError $e) {
        json_error(400, $e->getMessage());
    }
}

/**
 * Stamp created, allocate an id of $cls, persist. Returns via json_out with
 * the exact upstream shape {id, deletetoken} (201).
 */
function store_paste(array $clean, string $cls, string $dataDir) {
    $expire = $clean['meta']['expire'];
    $ttl = EXPIRE_SECONDS[$expire] ?? 0;
    $deleteToken = gen_delete_token();
    $dth = hash_token($deleteToken);
    $created = time();
    // The stored/returned paste carries meta.created but never the token hash.
    $meta = ['expire' => $expire, 'created' => $created];
    $paste = [
        'v' => FORMAT_VERSION, 'ct' => $clean['ct'], 'wk' => $clean['wk'],
        'adata' => $clean['adata'], 'meta' => $meta,
    ];
    $exp = $ttl > 0 ? $created + $ttl : 0;
    $id = store_alloc_id($dataDir, $cls);
    store_put_meta($dataDir, $id, ['p' => $paste, 'dth' => $dth, 'exp' => $exp]);
    json_out(['id' => $id, 'deletetoken' => $deleteToken], 201);
}

// ── read / consume / delete ──────────────────────────────────────────────────

const GONE_MSG = 'Document does not exist, has expired or has been deleted.';

function head_of(array $p): array {
    return ['v' => $p['v'], 'wk' => $p['wk'], 'adata' => $p['adata'], 'meta' => $p['meta']];
}

function read_paste(string $id, bool $peekOnly, string $dataDir) {
    $info = parse_id($id);
    // 'f' pastes read here like normal pastes — the decrypted plaintext is
    // the chunk manifest. Only consume (below) is restricted to 'b'.
    if ($info === null) json_error(404, GONE_MSG);

    if ($info['burn']) {
        // GET on a burn id NEVER consumes: head only, without `ct`.
        $rec = store_consume_burn_peek($dataDir, $id);
        if ($rec === null) json_error(410, 'This document was single-use and has already been read, or has expired.');
        json_out(head_of($rec['p']), 200);
    }

    $rec = store_get_meta($dataDir, $id);
    if ($rec === null) json_error(404, GONE_MSG);
    if ($peekOnly) {
        json_out(head_of($rec['p']), 200);
    }
    json_out($rec['p'], 200);
}

/**
 * The single destructive read for burn pastes. The custom header makes this a
 * CORS non-simple request (no CORS headers here → preflight fails before the
 * consume); same guard as the Worker.
 */
function consume_paste(string $id, string $dataDir) {
    $intent = trim(strtolower($_SERVER['HTTP_X_BURN_INTENT'] ?? ''));
    if ($intent !== 'consume') {
        json_error(400, 'Burn consumption requires the "X-Burn-Intent: consume" header.');
    }
    $info = parse_id($id);
    if ($info === null) json_error(404, GONE_MSG);
    if (!$info['burn']) json_error(404, 'Only one-time-view pastes can be consumed.');

    $rec = store_consume_burn($dataDir, $id);
    if ($rec === null) json_error(410, 'This document was single-use and has already been read, or has expired.');
    json_out($rec['p'], 200);
}

function delete_paste(string $id, string $dataDir) {
    $token = $_SERVER['HTTP_X_DELETE_TOKEN'] ?? null;
    if (!$token) json_error(400, 'Missing deletion token.');
    $info = parse_id($id);
    if ($info === null) json_error(404, GONE_MSG);

    $rec = store_get_meta($dataDir, $id);
    if ($rec === null) json_error(404, GONE_MSG);
    if (!verify_token($token, $rec['dth'])) {
        json_error(403, 'Wrong deletion token. Document was not deleted.');
    }
    store_delete($dataDir, $id);
    json_out(['status' => 'deleted', 'id' => $id], 200);
}

// ── routing ──────────────────────────────────────────────────────────────────

function main() {
    $dataDir = getenv('BT_DATA_DIR') ?: BT_DATA_DIR;
    store_init($dataDir);

    // PATH_INFO carries <base>/api.php/<rest> when nginx uses the fastcgi
    // split form; fall back to parsing REQUEST_URI against our known mount.
    $path = $_SERVER['PATH_INFO'] ?? '';
    if ($path === '') {
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        // Strip everything up to and including '/api' — works under any base.
        $pos = strpos($uri, '/api/');
        $path = $pos === false ? '' : substr($uri, $pos + 4);
        if ($path === false || $path === '') {
            // exact /api (no trailing slash)
            $path = ($uri === substr_replace($uri, '', -0) && preg_match('#/api$#', $uri)) ? '' : $path;
        }
    }
    $path = '/' . ltrim($path, '/');
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    // Opportunistic expiry sweep (~0.3% of requests) keeps the store clean
    // without a cron job.
    if (random_int(0, 299) === 0) store_sweep_expired($dataDir);

    if ($path === '/paste' || $path === '/file') {
        if ($method !== 'POST') json_error(405, 'Method not allowed.', ['Allow' => 'POST']);
        $clean = read_and_validate_paste();
        store_paste($clean, $path === '/file' ? CLASS_FILE
            : (($clean['adata']['bar'] ?? false) ? CLASS_BURN : CLASS_KV), $dataDir);
    }

    if ($path === '/stars') {
        // Private deployment: no upstream repo badge. Stable null, cacheable.
        json_out(['stars' => null], 200, ['Cache-Control' => 'public, max-age=3600']);
    }

    if (preg_match('#^/paste/([^/]+)/consume$#', $path, $m)) {
        if ($method !== 'POST') json_error(405, 'Method not allowed.', ['Allow' => 'POST']);
        consume_paste(urldecode($m[1]), $dataDir);
    }

    if (preg_match('#^/file(/.+)$#', $path, $m)) {
        route_file($method, ltrim($m[1], '/'), $dataDir); // exits
    }

    if (preg_match('#^/(paste|file)/([^/]+)$#', $path, $m)) {
        $id = urldecode($m[2]);
        if ($method === 'GET') read_paste($id, isset($_GET['meta']) && $_GET['meta'] === '1', $dataDir);
        if ($method === 'DELETE') delete_paste($id, $dataDir);
        json_error(405, 'Method not allowed.', ['Allow' => 'GET, DELETE']);
    }

    if (preg_match('#^/file/[^/]+/\d+$#', $path)) {
        route_file($method, substr($path, 6), $dataDir); // exits
    }

    json_error(404, 'Not found');
}

main();
