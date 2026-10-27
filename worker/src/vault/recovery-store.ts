/**
 * Opaque recovery bundle (spec §3.4, §11), owner devices only. The server checks
 * the wire structure with `parseRecoveryBundleWire` (it cannot open it), binds it
 * to this vault, bounds its size, and requires `bundle_seq` to increase on every
 * replacement: an equal seq is a lost-update `conflict`, a lower one `rollback`.
 * A `recovery_rotate` membership append stores its resealed bundle through the
 * same checks in the same transaction.
 *
 * `PUT /recovery` is `{"bundle", "membership_seq"}`: the membership position the
 * sealing device had verified. The server cannot open the bundle, so it cannot
 * see which recovery key it holds; it refuses a bundle sealed at a position
 * before the latest `recovery_rotate` (`conflict`: replay the chain, reseal with
 * the current recovery key), so a stale owner device cannot silently replace a
 * fresh bundle with one the chain no longer trusts.
 */
import { cjson, parseRecoveryBundleWire, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { requireInt, requireKeys } from './request-body.js';

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

/** Meta key holding the membership seq of the latest `recovery_rotate`. */
const RECOVERY_ROTATED_SEQ_KEY = 'recovery_rotated_seq';

/** Record that the `recovery_rotate` at `seq` was appended. Caller holds the transaction. */
export function recordRecoveryRotate(sql: SqlStorage, seq: number): void {
  sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v', RECOVERY_ROTATED_SEQ_KEY, String(seq));
}

/** Membership seq of the latest `recovery_rotate`, or 0 when there was none (genesis set the recovery key). */
function latestRecoveryRotateSeq(sql: SqlStorage): number {
  const row = sql.exec<{ v: string }>('SELECT v FROM meta WHERE k = ?', RECOVERY_ROTATED_SEQ_KEY).toArray()[0];
  if (!row) return 0;
  const seq = Number(row.v);
  // Fail closed on a corrupt value: refuse every PUT rather than accept a stale bundle.
  if (!Number.isSafeInteger(seq) || seq < 0) throw new ApiError('internal');
  return seq;
}

/** True once any recovery bundle is stored for this vault. */
export function hasRecoveryBundle(sql: SqlStorage): boolean {
  return sql.exec('SELECT 1 FROM recovery_blob WHERE id = 1').toArray().length > 0;
}

/**
 * `PUT /recovery`. With `firstOnly` (a non-human session, spec §9.4) only the
 * genesis seal is accepted: a stored bundle is never replaced. Re-checked here,
 * inside the transaction, so no interleaving can turn the seal into a replacement.
 */
export function putRecovery(sql: SqlStorage, state: MembershipState, vaultId: string, body: JsonObject, firstOnly = false): ApiResult {
  if (firstOnly && hasRecoveryBundle(sql)) throw new ApiError('forbidden');
  requireKeys(body, ['bundle', 'membership_seq']);
  const sealedAt = requireInt(body['membership_seq']);
  if (sealedAt > state.seq) throw new ApiError('bad_request', { message: 'membership_seq is ahead of the membership log' });
  if (sealedAt < latestRecoveryRotateSeq(sql)) throw new ApiError('conflict', { message: 'bundle was sealed before the latest recovery_rotate' });
  return okResult({ bundle_seq: storeRecoveryBundle(sql, vaultId, body['bundle']) });
}

export function getRecovery(sql: SqlStorage): ApiResult {
  const row = sql.exec<{ bundle: string }>('SELECT bundle FROM recovery_blob WHERE id = 1').toArray()[0];
  if (!row) throw new ApiError('not_found');
  return okResult({ bundle: JSON.parse(row.bundle) as unknown });
}
