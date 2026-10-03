// server/respond.js — shared response shapes for the Node server.
// Mirrors the Worker's Response API just enough that handler code reads the
// same: handlers return ResponseLike (buffered JSON/text) or FileResponse
// (streamed file), and index.js writes them out to node:http.

export const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

export class ResponseLike {
  constructor(body, status, extra) {
    this.body = body;              // string (or Buffer for raw bytes)
    this.status = status;
    this.headers = extra ? { ...JSON_HEADERS, ...extra } : { ...JSON_HEADERS };
  }
}

export class FileResponse {
  constructor(stream, status, headers) {
    this.stream = stream;          // Node Readable — piped, never buffered
    this.status = status;
    this.headers = headers;
  }
}

export const json = (obj, status = 200, extra) =>
  new ResponseLike(JSON.stringify(obj), status, extra);

export const err = (message, status, extra) => json({ error: message }, status, extra);
