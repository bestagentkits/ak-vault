/**
 * Sealed-operation queue (spec §3.6, §9.6). Operations arrive only through the
 * `enqueueSealed` RPC from the Worker's MCP handler; no route creates one. The
 * server stores the wire opaquely (it cannot open it), serves each operation only
 * to devices of the account named in its `origin`, and drops it `sealed_ttl_s`
 * after its `ts`. Acknowledging clears the ciphertext but keeps the ID until it
 * expires, so a replayed `sealed_id` is refused for its whole lifetime; those
 * kept IDs count toward `sealed_queue_max` with the pending operations.
 */
import { SEALED_MAX_FUTURE_MS, cjson, parseSealedOp, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { REMOTE_ACCESS_LIMITS } from '../limits.js';
import { queryInt, requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

/** Outcome of `enqueueSealed`. `refused` covers every input the queue does not accept. */
export type EnqueueSealedResult = 'queued' | 'sealed_queue_full' | 'refused';

const TTL_MS = REMOTE_ACCESS_LIMITS.sealed_ttl_s * 1000;

function prune(sql: SqlStorage, nowMs: number): void {
  sql.exec('DELETE FROM sealed_ops WHERE expires_at <= ?', nowMs);
}

/**
 * Queue a sealed operation (spec §3.6 "Who seals"): only for this vault, only to
 * the current key epoch, never while a rekey is pending, only when the origin
 * account is an `owner` or `editor` member, with a `ts` inside the drain window,
 * and never a `sealed_id` the queue already holds. Caller holds the transaction.
 */
export function enqueueSealedOp(sql: SqlStorage, state: MembershipState, wire: unknown, tokenIat: number, nowMs: number): EnqueueSealedResult {
  let op;
  try {
    op = parseSealedOp(wire);
  } catch {
    return 'refused';
  }
  if (op.vault_id !== state.vault_id || op.key_epoch !== state.key_epoch || state.rekey_required) return 'refused';
  const role = state.members.find((m) => m.account === op.origin.account)?.role;
  if (role !== 'owner' && role !== 'editor') return 'refused';
  if (op.ts > nowMs + SEALED_MAX_FUTURE_MS || nowMs - op.ts >= TTL_MS) return 'refused';
  prune(sql, nowMs);
  if (sql.exec('SELECT 1 FROM sealed_ops WHERE sealed_id = ?', op.sealed_id).toArray().length > 0) return 'refused';
  // Acknowledged rows are kept (without ciphertext) until they expire so a replay is
  // refused; they count toward the cap too, which bounds the table per vault.
  const held = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM sealed_ops').one().n;
  if (held >= REMOTE_ACCESS_LIMITS.sealed_queue_max) return 'sealed_queue_full';
  sql.exec(
    'INSERT INTO sealed_ops (sealed_id, account, wire, outcome, created_at, expires_at, grant_id, token_iat) VALUES (?, ?, ?, NULL, ?, ?, ?, ?)',
    op.sealed_id,
    op.origin.account,
    cjson(op as unknown as JsonObject),
    nowMs,
    op.ts + TTL_MS,
    op.origin.grant_id,
    tokenIat,
  );
  return 'queued';
}

/** A pending operation's MCP grant and the `iat` of the token that queued it. */
export interface SealedGrant {
  sid: string;
  iat: number;
}

/**
 * The distinct grants behind the account's pending, unexpired operations. A row queued before
 * the grant columns existed has no grant to check, so it is never cancelled by grant (it
 * still expires on its own).
 */
export function pendingSealedGrants(sql: SqlStorage, account: string, nowMs: number): SealedGrant[] {
  return sql
    .exec<{ sid: string; iat: number }>(
      'SELECT DISTINCT grant_id AS sid, token_iat AS iat FROM sealed_ops WHERE account = ? AND outcome IS NULL AND expires_at > ? AND grant_id IS NOT NULL AND token_iat IS NOT NULL',
      account,
      nowMs,
    )
    .toArray();
}

/**
 * Cancel the account's pending operations queued under a grant the Worker found revoked
 * (spec §3.6 "Draining"). The ciphertext is cleared and the ID kept until expiry, as for an
 * acknowledged one, so the operation is never served and a replay is still refused.
 */
export function cancelRevokedSealedOps(sql: SqlStorage, account: string, grant: SealedGrant, nowMs: number): void {
  prune(sql, nowMs);
  sql.exec("UPDATE sealed_ops SET wire = NULL, outcome = 'cancelled' WHERE account = ? AND grant_id = ? AND token_iat = ? AND outcome IS NULL", account, grant.sid, grant.iat);
}

function requireOnlyParams(req: VaultRequest, allowed: readonly string[]): void {
  const names = req.queryList.map(([name]) => name);
  if (names.some((n) => !allowed.includes(n)) || new Set(names).size !== names.length) throw new ApiError('bad_request', { message: 'unknown or repeated query parameter' });
}

/** `GET /sealed?after=&limit=`: the caller's account's pending, unexpired operations in `seq` order. */
export function listSealedOps(sql: SqlStorage, req: VaultRequest): ApiResult {
  requireOnlyParams(req, ['after', 'limit']);
  const after = queryInt(req.query, 'after', 0);
  const max = REMOTE_ACCESS_LIMITS.sealed_page_max;
  const limit = queryInt(req.query, 'limit', max, max);
  if (limit < 1) throw new ApiError('bad_request');
  const rows = sql
    .exec<{ seq: number; wire: string }>(
      'SELECT seq, wire FROM sealed_ops WHERE account = ? AND outcome IS NULL AND seq > ? AND expires_at > ? ORDER BY seq LIMIT ?',
      req.claims.sub,
      after,
      req.nowMs,
      limit + 1,
    )
    .toArray();
  const page = rows.slice(0, limit);
  const next = rows.length > limit ? page[page.length - 1]!.seq : null;
  return okResult({ sealed: page.map((r) => ({ seq: r.seq, op: JSON.parse(r.wire) as unknown })), next });
}

/**
 * `POST /sealed/{sealed_id}/ack` with `{"outcome":"applied"|"refused"}`. An
 * unknown, expired, already acknowledged or other-account `sealed_id` is
 * `not_found` (the device treats it as done). Caller holds the transaction.
 */
export function ackSealedOp(sql: SqlStorage, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, ['outcome']);
  const outcome = body['outcome'];
  if (outcome !== 'applied' && outcome !== 'refused') throw new ApiError('bad_request');
  prune(sql, req.nowMs);
  const updated = sql
    .exec('UPDATE sealed_ops SET wire = NULL, outcome = ? WHERE sealed_id = ? AND account = ? AND outcome IS NULL RETURNING seq', outcome, req.sealedId!, req.claims.sub)
    .toArray();
  if (updated.length === 0) throw new ApiError('not_found');
  return okResult({});
}
