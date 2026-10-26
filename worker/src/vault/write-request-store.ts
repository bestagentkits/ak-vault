/**
 * Human write requests (spec §3.8, ADR 0002 D8). An MCP client that must not see a
 * secret value asks the Worker for a write request; the person then types the value
 * into the dashboard, an enrolled browser device seals and signs the record, and the
 * Worker sees ciphertext only.
 *
 * The row holds no secret name or value: the target is inside the sealed write intent
 * (`intent`), which only a device holding `VK[e]` can open and which is cleared as
 * soon as the request closes or expires. The id alone authorizes nothing: every
 * route needs a `browser` session of the same account whose device proves possession
 * of its key. The server enforces account, vault, operation, single use, expiry and
 * the requesting grant's liveness; the browser device enforces the name binding,
 * because only it can derive a name tag.
 *
 * A request ends in exactly one of `completed`, `conflict`, `cancelled`, `failed`, or
 * lapses to `expired`. Completion is the same transaction as the item PUT, so a
 * request is never consumed without its record or the record written twice.
 */
import { SEALED_MAX_FUTURE_MS, cjson, parseWriteIntent, randomId, type JsonObject, type MembershipState, type WriteIntentWire } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { REMOTE_ACCESS_LIMITS as L } from '../limits.js';
import { requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

export const WRITE_REQUEST_STATES = ['pending_user', 'completed', 'conflict', 'cancelled', 'expired', 'failed'] as const;
export type WriteRequestState = (typeof WRITE_REQUEST_STATES)[number];

/** Sanitized, closed reason set: never free text, never a name or value. */
export const WRITE_REQUEST_REASONS = ['user_cancelled', 'grant_revoked', 'already_exists', 'not_found', 'revision_conflict', 'device_error'] as const;
export type WriteRequestReason = (typeof WRITE_REQUEST_REASONS)[number];

/** Outcomes a browser may report with `…/close`. */
const DEVICE_CLOSE: Record<string, readonly WriteRequestReason[]> = {
  cancelled: ['user_cancelled'],
  failed: ['already_exists', 'not_found', 'device_error'],
};

/** Outcome of `createWriteRequest`. `refused` covers every input the store does not accept. */
export type CreateWriteRequestResult = 'created' | 'too_many' | 'refused';

/** Who asked, as the MCP handler authenticated it (token `sub`, `client_id`, `grant_id`). */
export interface WriteRequestOrigin {
  account: string;
  client_id: string;
  grant_id: string;
}

export interface WriteRequestStatus {
  state: WriteRequestState;
  reason?: WriteRequestReason;
  receipt?: string;
  expires_at: number;
}

interface Row {
  request_id: string;
  account: string;
  client_id: string;
  grant_id: string;
  token_iat: number;
  operation: 'create' | 'replace';
  state: Exclude<WriteRequestState, 'expired'> | 'expired';
  intent: string | null;
  reason: WriteRequestReason | null;
  receipt: string | null;
  created_at: number;
  expires_at: number;
}

const COLUMNS = 'request_id, account, client_id, grant_id, token_iat, operation, state, intent, reason, receipt, created_at, expires_at';
const RETENTION_MS = L.write_request_retention_s * 1000;

/** Lapse overdue open requests (clearing their ciphertext) and purge rows past retention. */
function prune(sql: SqlStorage, nowMs: number): void {
  sql.exec("UPDATE write_requests SET state = 'expired', intent = NULL, closed_at = ? WHERE state = 'pending_user' AND expires_at <= ?", nowMs, nowMs);
  sql.exec('DELETE FROM write_requests WHERE closed_at IS NOT NULL AND closed_at + ? <= ?', RETENTION_MS, nowMs);
}

function load(sql: SqlStorage, requestId: string): Row | undefined {
  return sql.exec<Row & Record<string, string | number | null>>(`SELECT ${COLUMNS} FROM write_requests WHERE request_id = ?`, requestId).toArray()[0];
}

/**
 * Store a request built by the MCP handler (spec §3.8 "Who requests"): only for this
 * vault, only to the current key epoch, never while a rekey is pending, only when the
 * origin account is an `owner` or `editor` member, with a lifetime inside the allowed
 * range, never a `request_id` already held, and within the per-account and per-vault
 * caps. Caller holds the transaction.
 */
export function createWriteRequest(sql: SqlStorage, state: MembershipState, wire: unknown, tokenIat: number, nowMs: number): CreateWriteRequestResult {
  let intent: WriteIntentWire;
  try {
    intent = parseWriteIntent(wire);
  } catch {
    return 'refused';
  }
  if (intent.vault_id !== state.vault_id || intent.key_epoch !== state.key_epoch || state.rekey_required) return 'refused';
  const role = state.members.find((m) => m.account === intent.origin.account)?.role;
  if (role !== 'owner' && role !== 'editor') return 'refused';
  if (!Number.isSafeInteger(tokenIat) || tokenIat < 0) return 'refused';
  const lifetime = intent.expires_at - intent.ts;
  if (Math.abs(intent.ts - nowMs) > SEALED_MAX_FUTURE_MS || lifetime < L.write_request_min_ttl_s * 1000 || lifetime > L.write_request_ttl_s * 1000 || intent.expires_at <= nowMs) return 'refused';
  prune(sql, nowMs);
  if (load(sql, intent.request_id)) return 'refused';
  const pending = sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM write_requests WHERE account = ? AND state = 'pending_user'", intent.origin.account).one().n;
  const held = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM write_requests').one().n;
  if (pending >= L.write_requests_pending_per_account || held >= L.write_requests_per_vault) return 'too_many';
  sql.exec(
    `INSERT INTO write_requests (${COLUMNS}, closed_at) VALUES (?, ?, ?, ?, ?, ?, 'pending_user', ?, NULL, NULL, ?, ?, NULL)`,
    intent.request_id,
    intent.origin.account,
    intent.origin.client_id,
    intent.origin.grant_id,
    tokenIat,
    intent.operation,
    cjson(intent as unknown as JsonObject),
    nowMs,
    intent.expires_at,
  );
  return 'created';
}

/**
 * Status for the MCP client that created the request: the same account, client and
 * grant, else null (unknown and another client's request answer alike).
 */
export function writeRequestStatus(sql: SqlStorage, requestId: string, origin: WriteRequestOrigin, nowMs: number): WriteRequestStatus | null {
  prune(sql, nowMs);
  const row = load(sql, requestId);
  if (!row || row.account !== origin.account || row.client_id !== origin.client_id || row.grant_id !== origin.grant_id) return null;
  return {
    state: row.state,
    ...(row.reason ? { reason: row.reason } : {}),
    ...(row.receipt ? { receipt: row.receipt } : {}),
    expires_at: row.expires_at,
  };
}

/** The grant behind an open request, so the Worker can re-check its revocation; null when none is open. */
export function openWriteRequestGrant(sql: SqlStorage, requestId: string, nowMs: number): { sub: string; sid: string; iat: number } | null {
  const row = load(sql, requestId);
  if (!row || row.state !== 'pending_user' || row.expires_at <= nowMs) return null;
  return { sub: row.account, sid: row.grant_id, iat: row.token_iat };
}

/** Close an open request whose grant was revoked. A request that is no longer open is left alone. */
export function cancelRevokedWriteRequest(sql: SqlStorage, requestId: string, nowMs: number): void {
  sql.exec("UPDATE write_requests SET state = 'cancelled', reason = 'grant_revoked', intent = NULL, closed_at = ? WHERE request_id = ? AND state = 'pending_user'", nowMs, requestId);
}

/** The caller's own open request, else `not_found` (unknown, another account's) or `bad_request` (closed, expired). */
function openRow(sql: SqlStorage, req: VaultRequest): Row {
  prune(sql, req.nowMs);
  const row = load(sql, req.writeRequestId!);
  if (!row || row.account !== req.claims.sub) throw new ApiError('not_found');
  if (row.state !== 'pending_user') throw new ApiError('bad_request', { message: 'write request is not open' });
  return row;
}

function closeRow(sql: SqlStorage, requestId: string, state: WriteRequestState, reason: WriteRequestReason | null, receipt: string | null, nowMs: number): void {
  sql.exec('UPDATE write_requests SET state = ?, reason = ?, receipt = ?, intent = NULL, closed_at = ? WHERE request_id = ?', state, reason, receipt, nowMs, requestId);
}

/**
 * `GET …/write-requests/{id}` by a browser device of the requesting account: the
 * sealed intent while the request is open. Closed and expired requests answer 400
 * `bad_request`, another account's or an unknown one 404, with no intent.
 */
export function getWriteRequest(sql: SqlStorage, req: VaultRequest): ApiResult {
  const row = openRow(sql, req);
  return okResult({
    request_id: row.request_id,
    operation: row.operation,
    client_id: row.client_id,
    expires_at: row.expires_at,
    intent: JSON.parse(row.intent!) as unknown,
  });
}

/**
 * `POST …/write-requests/{id}/close` with `{"outcome":"cancelled"|"failed","reason":…}`:
 * the person cancelled, or the browser device could not complete (the name already
 * exists for `create`, does not exist for `replace`, or a local failure). Caller holds
 * the transaction.
 */
export function closeWriteRequest(sql: SqlStorage, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, ['outcome', 'reason']);
  const outcome = body['outcome'];
  const reason = body['reason'];
  const allowed = typeof outcome === 'string' ? DEVICE_CLOSE[outcome] : undefined;
  if (!allowed || typeof reason !== 'string' || !(allowed as readonly string[]).includes(reason)) throw new ApiError('bad_request');
  const row = openRow(sql, req);
  closeRow(sql, row.request_id, outcome as WriteRequestState, reason as WriteRequestReason, null, req.nowMs);
  return okResult({ state: outcome });
}

/**
 * Run an item PUT that completes a write request, in the caller's transaction. The
 * request must be open and the caller's own, from a `browser` session, and the
 * target item must match the operation (`create`: no live item; `replace`: a live
 * item). A compare-and-swap conflict keeps the preserved branch (spec §5) and closes
 * the request as `conflict`; any other failure rolls everything back and leaves the
 * request open so the person can retry or cancel.
 */
export function completeWithItemPut(sql: SqlStorage, req: VaultRequest, itemId: string, put: () => ApiResult): ApiResult {
  if (req.claims.kind !== 'browser') throw new ApiError('forbidden');
  const row = openRow(sql, req);
  const live = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM items WHERE item_id = ? AND tombstone = 0', itemId).one().n > 0;
  if (row.operation === 'create' && live) throw new ApiError('bad_request', { message: 'write request targets a new secret' });
  if (row.operation === 'replace' && !live) throw new ApiError('bad_request', { message: 'write request targets an existing secret' });
  const result = put();
  if (result.status === 200) {
    const receipt = randomId();
    closeRow(sql, row.request_id, 'completed', null, receipt, req.nowMs);
    return okResult({ ...(result.body as JsonObject), write_request: { state: 'completed', receipt } });
  }
  if (result.code === 'conflict') closeRow(sql, row.request_id, 'conflict', 'revision_conflict', null, req.nowMs);
  return result;
}
