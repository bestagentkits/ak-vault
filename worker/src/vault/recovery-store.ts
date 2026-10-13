/**
 * Opaque recovery bundle (spec §3.4, §11), owner devices only. The server checks
 * the wire structure with `parseRecoveryBundleWire` (it cannot open it), binds it
 * to this vault, bounds its size, and requires `bundle_seq` to increase on every
 * replacement: an equal seq is a lost-update `conflict`, a lower one `rollback`.
 * A `recovery_rotate` membership append stores its resealed bundle through the
 * same checks in the same transaction.
 */
import { cjson, parseRecoveryBundleWire, type JsonObject } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';

/** Validate and store a replacement bundle; returns its bundle_seq. Caller holds the transaction. */
export function storeRecoveryBundle(sql: SqlStorage, vaultId: string, body: unknown): number {
  const bundle = parseRecoveryBundleWire(body);
  if (bundle.vault_id !== vaultId) throw new ApiError('bad_request', { message: 'bundle belongs to another vault' });
  const json = cjson(bundle as unknown as JsonObject);
  if (json.length > LIMITS.recovery_blob_max_bytes) throw new ApiError('quota_exceeded');
  const current = sql.exec<{ revision: number }>('SELECT revision FROM recovery_blob WHERE id = 1').toArray()[0];
  if (current && bundle.bundle_seq < current.revision) throw new ApiError('rollback', { message: 'bundle_seq is behind the stored bundle' });
  if (current && bundle.bundle_seq === current.revision) throw new ApiError('conflict', { message: 'bundle_seq must increase' });
  sql.exec(
    'INSERT INTO recovery_blob (id, revision, bundle) VALUES (1, ?, ?) ON CONFLICT (id) DO UPDATE SET revision = excluded.revision, bundle = excluded.bundle',
    bundle.bundle_seq,
    json,
  );
  return bundle.bundle_seq;
}

export function putRecovery(sql: SqlStorage, vaultId: string, body: unknown): ApiResult {
  return okResult({ bundle_seq: storeRecoveryBundle(sql, vaultId, body) });
}

export function getRecovery(sql: SqlStorage): ApiResult {
  const row = sql.exec<{ bundle: string }>('SELECT bundle FROM recovery_blob WHERE id = 1').toArray()[0];
  if (!row) throw new ApiError('not_found');
  return okResult({ bundle: JSON.parse(row.bundle) as unknown });
}
