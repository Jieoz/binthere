<?php
// files.php — chunk upload/download for file pastes ('f' class).
// Port of server/files.js. Protocol (all under the deployment's base path):
//   PUT  /api/file/<id>/<n>   body = raw ciphertext chunk (≤ CHUNK_MAX),
//                             header X-Delete-Token: <creation token>
//   GET  /api/file/<id>/<n>   → raw chunk bytes (no auth — knowledge of the
//                             unguessable id IS the auth; content is ciphertext)
// Download uses X-Accel-Redirect so nginx streams the file from disk and PHP
// holds no bytes in memory.

const BT_CHUNK_MIB   = 8;    // per-chunk plaintext MiB (env BT_CHUNK_MIB)
const BT_FILE_MIB    = 512;  // total file MiB (env BT_FILE_MIB)

function bt_chunk_max(): int {
    $mib = (int)(getenv('BT_CHUNK_MIB') ?: BT_CHUNK_MIB);
    return $mib * 1024 * 1024 + 16; // +16 = GCM tag headroom (8388624 > 8 MiB!)
}

function bt_file_max(): int {
    $mib = (int)(getenv('BT_FILE_MIB') ?: BT_FILE_MIB);
    return $mib * 1024 * 1024;
}

function bt_max_chunks(): int {
    return (int)ceil(bt_file_max() / (bt_chunk_max() - 16));
}

/**
 * Route /api/file/... requests. $path is the part after /api/file/.
 * Returns true if the response was sent.
 */
function route_file(string $method, string $path, string $dataDir): bool {
    if (!preg_match('#^([^/]+)(?:/(\d+))?$#', $path, $m)) {
        json_error(404, 'Document does not exist, has expired or has been deleted.');
    }
    $id = urldecode($m[1]);
    $info = parse_id($id);
    if ($info === null || !$info['file']) {
        json_error(404, 'Document does not exist, has expired or has been deleted.');
    }

    if ($method === 'PUT') {
        if (!isset($m[2])) json_error(405, 'Method not allowed.', ['Allow' => 'PUT /api/file/<id>/<n>, GET /api/file/<id>/<n>']);
        put_chunk($method, $id, (int)$m[2], $dataDir);
        return true;
    }
    if ($method === 'GET') {
        if (!isset($m[2])) json_error(405, 'Method not allowed.', ['Allow' => 'PUT /api/file/<id>/<n>, GET /api/file/<id>/<n>']);
        get_chunk($id, (int)$m[2], $dataDir);
        return true;
    }
    json_error(405, 'Method not allowed.', ['Allow' => 'PUT, GET']);
}

/** PUT one ciphertext chunk. Idempotent: re-uploading the identical index is
 *  a no-op success (the bytes land once); this makes client retries safe and
 *  neutralizes double-dispatch quirks of some SAPIs (php -S re-runs the
 *  router for large bodies, which surfaced as spurious 409s). */
function put_chunk(string $method, string $id, int $n, string $dataDir) {
    if (!rl_take('put', client_ip(), BT_RL_PUT)) {
        json_error(429, 'Rate limit exceeded. Try again shortly.');
    }
    if ($n < 0 || $n >= bt_max_chunks()) {
        json_error(400, 'Chunk index out of range (0–' . (bt_max_chunks() - 1) . ').');
    }
    $rec = store_get_meta($dataDir, $id);
    if ($rec === null) {
        json_error(404, 'Document does not exist, has expired or has been deleted.');
    }
    if ($rec['exp'] > 0 && $rec['exp'] <= time()) {
        store_delete($dataDir, $id);
        json_error(404, 'Document does not exist, has expired or has been deleted.');
    }
    $presented = $_SERVER['HTTP_X_DELETE_TOKEN'] ?? null;
    if (!verify_token($presented, $rec['dth'])) {
        json_error(403, 'Wrong deletion token. Chunk was not accepted.');
    }

    // Idempotency: if the chunk is already on disk, accept the request as
    // success without rewriting (see the function docblock).
    $cap = bt_chunk_max();
    $final = store_blob_dir($dataDir, $id) . "/{$n}";
    if (is_file($final)) {
        header('Content-Type: application/json');
        http_response_code(200);
        echo json_encode(['status' => 'ok', 'chunk' => $n, 'duplicate' => true]);
        exit;
    }
    $body = read_capped_body($cap);
    if ($body === null) {
        json_error(413, 'Chunk is too large.');
    }
    if (strlen($body) === 0) {
        json_error(400, 'Chunk body is empty.');
    }
    if (!store_put_chunk($dataDir, $id, $n, $body)) {
        // Raced with a concurrent identical PUT — the bytes are there, accept.
        header('Content-Type: application/json');
        http_response_code(200);
        echo json_encode(['status' => 'ok', 'chunk' => $n, 'duplicate' => true]);
        exit;
    }
    header('Content-Type: application/json');
    http_response_code(200);
    echo json_encode(['status' => 'ok', 'chunk' => $n]);
}

/** GET one ciphertext chunk. Under nginx: X-Accel-Redirect (zero-copy stream).
 *  Without nginx (BT_SELF_STREAM=1, dev): PHP streams the file itself. */
function get_chunk(string $id, int $n, string $dataDir) {
    $file = store_blob_dir($dataDir, $id) . "/{$n}";
    clearstatcache(true, $file);
    if (!is_file($file)) {
        json_error(404, 'Chunk not found.');
    }
    header('Content-Type: application/octet-stream');
    if (getenv('BT_SELF_STREAM')) {
        header('Content-Length: ' . filesize($file));
        readfile($file); // 8 MiB chunks stream in 256 KB reads; fine for dev
    } else {
        header('X-Accel-Redirect: /_bt_internal' . $file);
    }
    // Nothing else is echoed — nginx (or readfile) takes over.
}

/**
 * Read php://input up to $cap bytes. Returns the byte string, or null when the
 * body exceeds the cap (caller answers 413). Chunks arrive as raw PUT bodies,
 * not multipart, so post_max_size does not interfere.
 */
function read_capped_body(int $cap) {
    // Fast reject on the declared length.
    if (isset($_SERVER['CONTENT_LENGTH']) && (int)$_SERVER['CONTENT_LENGTH'] > $cap) {
        return null;
    }
    $fh = fopen('php://input', 'rb');
    if ($fh === false) return null;
    $buf = '';
    while (!feof($fh)) {
        $chunk = fread($fh, 262144);
        if ($chunk === false) break;
        $buf .= $chunk;
        if (strlen($buf) > $cap) {
            fclose($fh);
            return null;
        }
    }
    fclose($fh);
    return $buf;
}
