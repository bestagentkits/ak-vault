/**
 * Idempotency for every mutation (spec §5): the same device + key + identical
 * request returns the stored response; a different request under the same key is
 * `422 idempotency_mismatch`. Only completed handler results are stored (success
 * and preserved-conflict 409s); thrown refusals are not, so a retry re-evaluates
 * them. Raw keys are never stored, only `sha256(did "\n" key)`.
 */
import { concatBytes, sha256b64, utf8Encode } from '@ak-vault/protocol';
import { ApiError, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import type { VaultRequest } from './vault-request.js';

const KEY_PATTERN = /^[A-Za-z0-9_.:-]+$/;

export function validateIdempotencyKey(key: string | null): string {
  if (!key || key.length > LIMITS.idempotency_key_max_length || !KEY_PATTERN.test(key)) throw new ApiError('bad_request', { message: 'a valid Idempotency-Key header is required' });
  return key;
}

function keyHash(req: VaultRequest): string {
  return sha256b64(utf8Encode(`${req.claims.did}\n${validateIdempotencyKey(req.idempotencyKey)}`));
}

function requestHash(req: VaultRequest): string {
  return sha256b64(concatBytes(utf8Encode(`${req.method} ${req.path}\n`), req.body));
}

/** Stored result for a retried request, or null when the key is new. */
export function lookupIdempotent(sql: SqlStorage, req: VaultRequest): ApiResult | null {
  sql.exec('DELETE FROM idempotency WHERE expires_at < ?', req.nowMs);
  const row = sql
    .exec<{ request_hash: string; status: number; body_json: string }>('SELECT request_hash, status, body_json FROM idempotency WHERE key_hash = ?', keyHash(req))
    .toArray()[0];
  if (!row) return null;
  if (row.request_hash !== requestHash(req)) throw new ApiError('idempotency_mismatch');
  return { status: row.status, body: JSON.parse(row.body_json) as unknown, headers: { 'Idempotent-Replayed': 'true' } };
}

/**
 * True when a live stored result exists for this device, key and identical
 * request, so `lookupIdempotent` will replay it. Never throws on a bad key.
 */
export function hasIdempotentResult(sql: SqlStorage, req: VaultRequest): boolean {
  let key: string;
  try {
    key = keyHash(req);
  } catch {
    return false;
  }
  const row = sql.exec<{ request_hash: string }>('SELECT request_hash FROM idempotency WHERE key_hash = ? AND expires_at >= ?', key, req.nowMs).toArray()[0];
  return row !== undefined && row.request_hash === requestHash(req);
}

/** Store a completed result inside the mutation's transaction. */
export function storeIdempotent(sql: SqlStorage, req: VaultRequest, result: ApiResult): void {
  sql.exec(
    'INSERT INTO idempotency (key_hash, request_hash, status, body_json, expires_at) VALUES (?, ?, ?, ?, ?)',
    keyHash(req),
    requestHash(req),
    result.status,
    JSON.stringify(result.body),
    req.nowMs + LIMITS.idempotency_ttl_seconds * 1000,
  );
}
