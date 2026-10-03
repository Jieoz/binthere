<?php
// store.php — filesystem storage. Same layout as the Node/Worker ports:
//   <data>/meta/<id>.json  — { p: pasteObject, dth: deleteTokenHash, exp: expiry }
//   <data>/blob/<id>/<n>   — one file per ciphertext chunk (files only)
//   <data>/tmp/            — staging for atomic rename() into place
// All writes land in tmp/ first; a crash never leaves a half-written paste.

// ── event log & tombstones ───────────────────────────────────────────────────
// A consumed/expired/abandoned paste leaves a TOMBSTONE meta record behind (no
// paste body, no blobs): { state, dth, exp, events, consumedAt?, meta,
// origExp }. The sender (deletetoken holder) reads it via
// GET /api/<kind>/<id>/status; content links answer 410 as before. Tombstones
// expire after BT_TOMBSTONE_TTL. Events are metadata only (time + type) —
// never IPs or UAs; this stays a zero-knowledge product, not a visitor tracker.

const BT_EVENT_CAP = 100;        // max events kept per paste
const BT_EVENT_WINDOW = 30;      // same-type events within N s collapse into one
const BT_TOMBSTONE_TTL = 604800; // tombstone retention: 7 days
const BT_ZOMBIE_SECONDS = 86400; // chunk-0 fetched but download never finished

const BT_RL_CREATE = 30;  // paste creates per IP per minute
const BT_RL_PUT = 60;     // chunk PUTs per IP per minute

/** Initialize (create if missing) the storage tree; returns the data root. */
function store_init(string $dataDir): string {
    foreach (["$dataDir/meta", "$dataDir/blob", "$dataDir/tmp"] as $d) {
        if (!is_dir($d) && !mkdir($d, 0700, true) && !is_dir($d)) {
            http_error(500, '存储不可写。');
        }
    }
    return $dataDir;
}

function store_meta_path(string $dataDir, string $id): string {
    return "{$dataDir}/meta/{$id}.json";
}

function store_blob_dir(string $dataDir, string $id): string {
    return "{$dataDir}/blob/{$id}";
}

/** Read+decode a meta record, or null. */
function store_get_meta(string $dataDir, string $id) {
    $raw = @file_get_contents(store_meta_path($dataDir, $id));
    if ($raw === false) return null;
    $rec = json_decode($raw, true);
    return is_array($rec) ? $rec : null;
}

/** Atomically write a meta record (tmp file + rename). */
function store_put_meta(string $dataDir, string $id, array $rec) {
    $final = store_meta_path($dataDir, $id);
    if (file_exists($final)) return; // id collision — caller retries with a new id
    $tmp = "{$dataDir}/tmp/" . bin2hex(random_bytes(8)) . '.json';
    file_put_contents($tmp, json_encode($rec, JSON_UNESCAPED_SLASHES), LOCK_EX);
    rename($tmp, $final);
}

/** Atomically overwrite an EXISTING meta record (download counter, …). */
function store_update_meta(string $dataDir, string $id, array $rec) {
    $tmp = "{$dataDir}/tmp/" . bin2hex(random_bytes(8)) . '.json';
    file_put_contents($tmp, json_encode($rec, JSON_UNESCAPED_SLASHES), LOCK_EX);
    rename($tmp, store_meta_path($dataDir, $id));
}

/** Append an event to a live paste's log. Same-type events within
 *  BT_EVENT_WINDOW collapse (page reloads, parallel chunk fetches), the log is
 *  capped at BT_EVENT_CAP. Best-effort: a lost read-modify-write race drops one
 *  event, never content. No-op on tombstones and missing pastes. */
function store_log_event(string $dataDir, string $id, string $type) { // prod PHP 7.0: no void return type
    $rec = store_get_meta($dataDir, $id);
    if ($rec === null || !isset($rec['p'])) return; // gone or tombstone
    $now = time();
    $events = $rec['events'] ?? [];
    foreach (array_reverse($events) as $last) {
        if (($last['e'] ?? '') === $type) {
            if ($now - (int)($last['t'] ?? 0) <= BT_EVENT_WINDOW) return; // same session
            break;
        }
    }
    $events[] = ['t' => $now, 'e' => $type];
    if (count($events) > BT_EVENT_CAP) $events = array_slice($events, -BT_EVENT_CAP);
    $rec['events'] = $events;
    store_update_meta($dataDir, $id, $rec);
}

/** Convert a live paste into a tombstone: keep the token hash, meta, event log;
 *  drop the paste body and every blob. Idempotent; returns the tombstone, or
 *  null when there is nothing to tombstone (never existed). */
function store_tombstone(string $dataDir, string $id, string $state) {
    $rec = store_get_meta($dataDir, $id);
    if ($rec === null) return null;
    if (!isset($rec['p'])) return $rec; // already a tombstone
    $tomb = [
        'state' => $state,
        'dth' => $rec['dth'],
        'exp' => time() + BT_TOMBSTONE_TTL,
        'events' => $rec['events'] ?? [],
        'consumedAt' => $state === 'consumed' ? time() : null,
        'meta' => $rec['p']['meta'] ?? null,
        'origExp' => $rec['exp'],
    ];
    if ($tomb['consumedAt'] === null) unset($tomb['consumedAt']);
    store_update_meta($dataDir, $id, $tomb);
    $dir = store_blob_dir($dataDir, $id);
    if (is_dir($dir)) {
        foreach (glob("{$dir}/*") ?: [] as $f) @unlink($f);
        @rmdir($dir);
    }
    return $tomb;
}

/** Allocate a fresh id of $cls (retries on the astronomically rare collision). */
function store_alloc_id(string $dataDir, string $cls): string {
    for ($i = 0; $i < 4; $i++) {
        $id = gen_id($cls);
        if (!file_exists(store_meta_path($dataDir, $id))) return $id;
    }
    http_error(500, '无法分配内容 ID，请重试。');
}

/** Delete a paste: unlink meta, then its blob dir if any. Idempotent. */
function store_delete(string $dataDir, string $id) {
    @unlink(store_meta_path($dataDir, $id));
    $dir = store_blob_dir($dataDir, $id);
    if (is_dir($dir)) {
        foreach (glob("{$dir}/*") ?: [] as $f) @unlink($f);
        @rmdir($dir);
    }
}

/** One chunk ciphertext; null if absent. */
function store_get_chunk(string $dataDir, string $id, int $n) {
    $raw = @file_get_contents(store_blob_dir($dataDir, $id) . "/{$n}");
    return $raw === false ? null : $raw;
}

/** Store a chunk atomically; false if it already exists (409). */
function store_put_chunk(string $dataDir, string $id, int $n, string $bytes): bool {
    $dir = store_blob_dir($dataDir, $id);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        http_error(500, '存储不可写。');
    }
    $final = "{$dir}/{$n}";
    if (file_exists($final)) return false;
    $tmp = "{$dataDir}/tmp/" . bin2hex(random_bytes(8));
    file_put_contents($tmp, $bytes, LOCK_EX);
    rename($tmp, $final);
    return true;
}

/** Number of chunks stored (finalize check). */
function store_chunk_count(string $dataDir, string $id): int {
    $files = glob(store_blob_dir($dataDir, $id) . '/*') ?: [];
    return count($files);
}

/**
 * Atomic consume for burn pastes: rename the meta file away first — whichever
 * concurrent request wins, the loser sees ENOENT → 410 — then read+delete.
 * Replaces the Durable Object's blockConcurrencyWhile.
 */
function store_consume_burn(string $dataDir, string $id) {
    $meta = store_meta_path($dataDir, $id);
    // Tombstones must survive repeated consume attempts (the sender reads the
    // status afterwards; a second consume must not destroy the record). So
    // peek FIRST — only a live paste goes through the rename race below.
    $existing = store_get_meta($dataDir, $id);
    if ($existing !== null && !isset($existing['p'])) return null; // tombstone: 410, keep record
    $tmp = "{$dataDir}/tmp/" . bin2hex(random_bytes(8)) . '.consume';
    if (!@rename($meta, $tmp)) return null; // already consumed or gone
    $raw = @file_get_contents($tmp);
    @unlink($tmp);
    $dir = store_blob_dir($dataDir, $id);
    if (is_dir($dir)) {
        foreach (glob("{$dir}/*") ?: [] as $f) @unlink($f);
        @rmdir($dir);
    }
    if ($raw === false) return null;
    $rec = json_decode($raw, true);
    if (!is_array($rec)) return null;
    if (!isset($rec['p'])) return null; // raced into a tombstone → nothing to consume
    if ($rec['exp'] > 0 && $rec['exp'] <= time()) return null;
    return $rec;
}

/** Non-consuming head read for burn pastes (never returns ct). */
function store_consume_burn_peek(string $dataDir, string $id) {
    $rec = store_get_meta($dataDir, $id);
    if ($rec === null) return null;
    if ($rec['exp'] > 0 && $rec['exp'] <= time()) {
        store_delete($dataDir, $id);
        return null;
    }
    return $rec;
}

/** Remove every expired paste's meta (and blobs). Called opportunistically. */
function store_sweep_expired(string $dataDir) {
    $now = time();
    foreach (glob("{$dataDir}/meta/*.json") ?: [] as $f) {
        $rec = json_decode((string)@file_get_contents($f), true);
        if (!is_array($rec)) continue;
        $id = basename($f, '.json');
        if (isset($rec['p'])) {
            // Zombie guard: chunks were being pulled but the transfer never
            // completed — reclaim the storage after the window.
            if (isset($rec['firstdl']) && $now - (int)$rec['firstdl'] > BT_ZOMBIE_SECONDS) {
                store_tombstone($dataDir, $id, 'abandoned');
                continue;
            }
            // A receiver's keep window ran out → tombstone as a natural expiry.
            if (isset($rec['keepUntil']) && $rec['keepUntil'] <= $now) {
                store_tombstone($dataDir, $id, 'expired');
                continue;
            }
        }
        if ($rec['exp'] > 0 && $rec['exp'] <= $now) {
            if (isset($rec['p'])) store_tombstone($dataDir, $id, 'expired');
            else store_delete($dataDir, $id); // tombstone past its retention
        }
    }
}

// ── rate limiting (in-process token bucket, mirrors server/ratelimit.js) ─────

function rl_take(string $kind, string $ip, int $limit): bool {
    $path = sys_get_temp_dir() . "/binthere-rl-" . md5("{$kind}|{$ip}");
    $now = time();
    $state = ['tokens' => $limit, 'last' => $now];
    $fh = @fopen($path, 'c+');
    if ($fh === false) return true; // fail open, same trust level as upstream
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    if ($raw) {
        $prev = json_decode($raw, true);
        if (is_array($prev) && ($now - (int)$prev['last']) < 60) {
            $state = $prev;
        }
    }
    if ($state['tokens'] <= 0) {
        flock($fh, LOCK_UN);
        fclose($fh);
        return false;
    }
    $state['tokens'] -= 1;
    $state['last'] = $now;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($state));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return true;
}

/** Client IP: X-Forwarded-For first hop (nginx in front), else REMOTE_ADDR. */
function client_ip(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}
