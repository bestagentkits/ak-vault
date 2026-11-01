/**
 * Human write requests (spec §3.10, ADR 0002 D8) and device-sealed input requests
 * (spec §3.11, ADR 0004). An MCP client that must not see a secret value asks the
 * Worker for a request; the person then types the value into a form, a device of the
 * requesting account seals and signs the record, and the Worker sees ciphertext only.
 *
 * Two flows share one table, one lifetime and one set of caps:
 * - `dashboard`: the target is inside the sealed write intent (`intent`), which only a
 *   device holding `VK[e]` can open and which is cleared as soon as the request closes
 *   or expires. Every route needs a `browser` session of the same account whose device
 *   proves possession of its key.
 * - `device`: an online device of the account issued a one-time input key; the row
 *   keeps that device's ID and the public half (`input_pub`), never the name, the
 *   sealed value or the secret half. The `/input` form's `input` session of the same
 *   account submits once (`pending_user` -> `submitted`), the Worker relays the
 *   ciphertext to that device without storing it, and the device's item PUT completes
 *   the request.
 *
 * The id alone authorizes nothing. The server enforces account, vault, operation,
 * single use, expiry and the requesting grant's liveness; the device enforces the name
 * binding, because only it can derive a name tag or open the seal.
 *
 * A request ends in exactly one of `completed`, `conflict`, `cancelled`, `failed`, or
 * lapses to `expired`. Completion is the same transaction as the item PUT, so a
 * request is never consumed without its record or the record written twice.
 */
import { SEALED_MAX_FUTURE_MS, b64decodeLength, cjson, parseWriteIntent, randomId, type JsonObject, type MembershipState, type WriteIntentWire } from '@ak-vault/protocol';
import { ApiError, errorResult, okResult, toApiError, type ApiResult } from '../http/errors.js';
import { REMOTE_ACCESS_LIMITS as L } from '../limits.js';
import { parseItemPutBody } from './lookup-store.js';
import { requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

/** `submitted` is a device-flow request whose sealed value is on its way to the device. */
export const WRITE_REQUEST_STATES = ['pending_user', 'submitted', 'completed', 'conflict', 'cancelled', 'expired', 'failed'] as const;
export type WriteRequestState = (typeof WRITE_REQUEST_STATES)[number];

/** Sanitized, closed reason set: never free text, never a name or value. */
export const WRITE_REQUEST_REASONS = [
  'user_cancelled',
  'grant_revoked',
  'already_exists',
  'not_found',
  'revision_conflict',
  'device_error',
  // Device flow: why the issuing device could not take the submitted value.
  'device_lost',
  'decrypt_failed',
  'bad_request',
  'denied',
  'internal',
  'timeout',
] as const;
export type WriteRequestReason = (typeof WRITE_REQUEST_REASONS)[number];

export const WRITE_REQUEST_FLOWS = ['dashboard', 'device'] as const;
export type WriteRequestFlow = (typeof WRITE_REQUEST_FLOWS)[number];

/** States in which a request still counts against the caps and can complete. */
const OPEN_STATES = "('pending_user', 'submitted')";

/** Outcomes a browser may report with `…/close`. */
const DEVICE_CLOSE: Record<string, readonly WriteRequestReason[]> = {
  cancelled: ['user_cancelled'],
  failed: ['already_exists', 'not_found', 'device_error'],
};

/** Outcome of `createWriteRequest` / `createInputRequest`. `refused` covers every input the store does not accept. */
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

/** A device-flow request as the MCP handler built it after the device issued its input key. */
export interface InputRequestInput extends WriteRequestOrigin {
  request_id: string;
  /** `iat` of the MCP token that asked. */
  token_iat: number;
  operation: 'create' | 'replace';
  /** The device that issued `input_pub` and alone can open the submission. */
  device_id: string;
  /** b64 of the 32-byte X25519 public input key. */
  input_pub: string;
  /** Unix ms, as the MCP handler stamped the request (the relay call's `expires_at` minus the lifetime). */
  created_at: number;
  expires_at: number;
}

/** What the input routes hand the relay after a claim: the device to deliver to and the requesting caller. */
export interface InputClaim {
  deviceId: string;
  clientId: string;
  grantId: string;
}

export type ClaimInputResult = { claim: InputClaim } | { error: ApiResult };

interface Row {
  request_id: string;
  account: string;
  client_id: string;
  grant_id: string;
  token_iat: number;
  operation: 'create' | 'replace';
  state: WriteRequestState;
  intent: string | null;
  reason: WriteRequestReason | null;
  receipt: string | null;
  created_at: number;
  expires_at: number;
  flow: WriteRequestFlow;
  device_id: string | null;
  input_pub: string | null;
}

const COLUMNS = 'request_id, account, client_id, grant_id, token_iat, operation, state, intent, reason, receipt, created_at, expires_at, flow, device_id, input_pub';
const RETENTION_MS = L.write_request_retention_s * 1000;
const MAX_ACCOUNT = 256;
const MAX_CLIENT_ID = 256;
const MAX_GRANT_ID = 64;

/** Lapse overdue open requests (clearing their ciphertext) and purge rows past retention. */
function prune(sql: SqlStorage, nowMs: number): void {
  sql.exec(`UPDATE write_requests SET state = 'expired', intent = NULL, closed_at = ? WHERE state IN ${OPEN_STATES} AND expires_at <= ?`, nowMs, nowMs);
  sql.exec('DELETE FROM write_requests WHERE closed_at IS NOT NULL AND closed_at + ? <= ?', RETENTION_MS, nowMs);
}

function load(sql: SqlStorage, requestId: string): Row | undefined {
  return sql.exec<Row & Record<string, string | number | null>>(`SELECT ${COLUMNS} FROM write_requests WHERE request_id = ?`, requestId).toArray()[0];
}

/** Whether one more open request of `account` from `clientId` fits the per-account, per-client and retained caps. Prune first. */
function hasRoom(sql: SqlStorage, account: string, clientId: string): boolean {
  const pending = sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM write_requests WHERE account = ? AND state IN ${OPEN_STATES}`, account).one().n;
  const held = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM write_requests WHERE account = ?', account).one().n;
  const clientPending = sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM write_requests WHERE account = ? AND client_id = ? AND state IN ${OPEN_STATES}`, account, clientId).one().n;
  return pending < L.write_requests_pending_per_account && clientPending < L.write_requests_pending_per_client && held < L.write_requests_retained_per_account;
}

/** A request lifetime the store accepts: stamped near the object's clock, within the allowed range, not yet over. */
function lifetimeAllowed(createdAt: number, expiresAt: number, nowMs: number): boolean {
  const lifetime = expiresAt - createdAt;
  return Math.abs(createdAt - nowMs) <= SEALED_MAX_FUTURE_MS && lifetime >= L.write_request_min_ttl_s * 1000 && lifetime <= L.write_request_ttl_s * 1000 && expiresAt > nowMs;
}

/**
 * Store a request built by the MCP handler (spec §3.10 "Who requests"): only for this
 * vault, only to the current key epoch, never while a rekey is pending, only when the
 * origin account is an `owner` member (only an owner can enroll the browser device that completes it), with a lifetime inside the allowed
 * range, never a `request_id` already held, and within the per-account, per-client and
 * retained caps. Caller holds the transaction.
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
  if (role !== 'owner') return 'refused';
  if (!Number.isSafeInteger(tokenIat) || tokenIat < 0) return 'refused';
  if (!lifetimeAllowed(intent.ts, intent.expires_at, nowMs)) return 'refused';
  prune(sql, nowMs);
  if (load(sql, intent.request_id)) return 'refused';
  if (!hasRoom(sql, intent.origin.account, intent.origin.client_id)) return 'too_many';
  sql.exec(
    `INSERT INTO write_requests (request_id, account, client_id, grant_id, token_iat, operation, state, intent, reason, receipt, created_at, expires_at, closed_at, flow)
     VALUES (?, ?, ?, ?, ?, ?, 'pending_user', ?, NULL, NULL, ?, ?, NULL, 'dashboard')`,
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

/** Whether `value` is canonical b64 of exactly `bytes` bytes. */
function isB64(value: unknown, bytes: number): value is string {
  if (typeof value !== 'string') return false;
  try {
    b64decodeLength(value, bytes);
    return true;
  } catch {
    return false;
  }
}

function boundedText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && /^[\x20-\x7e]+$/.test(value);
}

/**
 * Store a device-flow request (spec §3.11) after the device issued its input key: the
 * same vault, rekey, lifetime, uniqueness and cap rules as a dashboard request, for an
 * `owner` or `editor` account (the device, not a browser, writes the record), and only
 * when `device_id` is a current `human` writer device of that account. Caller holds the
 * transaction.
 */
export function createInputRequest(sql: SqlStorage, state: MembershipState, input: InputRequestInput, nowMs: number): CreateWriteRequestResult {
  if (
    !isB64(input.request_id, 16) ||
    !isB64(input.device_id, 16) ||
    !isB64(input.input_pub, 32) ||
    typeof input.account !== 'string' ||
    input.account.length === 0 ||
    input.account.length > MAX_ACCOUNT ||
    !boundedText(input.client_id, MAX_CLIENT_ID) ||
    !boundedText(input.grant_id, MAX_GRANT_ID) ||
    (input.operation !== 'create' && input.operation !== 'replace') ||
    !Number.isSafeInteger(input.token_iat) ||
    input.token_iat < 0 ||
    !Number.isSafeInteger(input.created_at) ||
    !Number.isSafeInteger(input.expires_at)
  ) {
    return 'refused';
  }
  if (state.rekey_required) return 'refused';
  const role = state.members.find((m) => m.account === input.account)?.role;
  if (role !== 'owner' && role !== 'editor') return 'refused';
  const device = state.devices.find((d) => d.device_id === input.device_id);
  if (!device || device.account !== input.account || device.kind !== 'human' || (device.role !== 'owner' && device.role !== 'editor')) return 'refused';
  if (!lifetimeAllowed(input.created_at, input.expires_at, nowMs)) return 'refused';
  prune(sql, nowMs);
  if (load(sql, input.request_id)) return 'refused';
  if (!hasRoom(sql, input.account, input.client_id)) return 'too_many';
  sql.exec(
    `INSERT INTO write_requests (request_id, account, client_id, grant_id, token_iat, operation, state, intent, reason, receipt, created_at, expires_at, closed_at, flow, device_id, input_pub)
     VALUES (?, ?, ?, ?, ?, ?, 'pending_user', NULL, NULL, NULL, ?, ?, NULL, 'device', ?, ?)`,
    input.request_id,
    input.account,
    input.client_id,
    input.grant_id,
    input.token_iat,
    input.operation,
    nowMs,
    input.expires_at,
    input.device_id,
    input.input_pub,
  );
  return 'created';
}

/**
 * Whether account `account` may open one more request from client `clientId` (checked
 * before the device is asked for a key, so a client at its cap cannot spend the
 * device's own key budget). The insert re-checks. Caller holds the transaction.
 */
export function writeRequestRoom(sql: SqlStorage, account: string, clientId: string, nowMs: number): boolean {
  prune(sql, nowMs);
  return hasRoom(sql, account, clientId);
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

/**
 * The grant behind an open request of account `account`, so the Worker can re-check its
 * revocation; null when none is open or the request belongs to another account.
 */
export function openWriteRequestGrant(sql: SqlStorage, requestId: string, account: string, nowMs: number): { sub: string; sid: string; iat: number } | null {
  const row = load(sql, requestId);
  if (!row || row.account !== account || (row.state !== 'pending_user' && row.state !== 'submitted') || row.expires_at <= nowMs) return null;
  return { sub: row.account, sid: row.grant_id, iat: row.token_iat };
}

/** Close an open request (either flow) whose grant was revoked. A request that is no longer open is left alone. */
export function cancelRevokedWriteRequest(sql: SqlStorage, requestId: string, nowMs: number): void {
  sql.exec(`UPDATE write_requests SET state = 'cancelled', reason = 'grant_revoked', intent = NULL, closed_at = ? WHERE request_id = ? AND state IN ${OPEN_STATES}`, nowMs, requestId);
}

/** The caller's own open dashboard request, else `not_found` (unknown, another account's, a device-flow one) or `bad_request` (closed, expired). */
function openRow(sql: SqlStorage, req: VaultRequest): Row {
  prune(sql, req.nowMs);
  const row = load(sql, req.writeRequestId!);
  if (!row || row.flow !== 'dashboard' || row.account !== req.claims.sub) throw new ApiError('not_found');
  if (row.state !== 'pending_user') throw new ApiError('bad_request', { message: 'write request is not open' });
  return row;
}

/**
 * The device-flow request an item PUT with `?input_request=` completes: the caller's own
 * (`sub`), issued by the calling device (`did`), from a device session (never `browser`
 * or `machine`), submitted and not expired. Anything else refuses before a write.
 */
function submittedInputRow(sql: SqlStorage, req: VaultRequest): Row {
  if (req.claims.kind === 'browser' || req.claims.kind === 'machine') throw new ApiError('forbidden');
  prune(sql, req.nowMs);
  const row = load(sql, req.inputRequestId!);
  if (!row || row.flow !== 'device' || row.account !== req.claims.sub) throw new ApiError('not_found');
  if (row.device_id !== req.claims.did) throw new ApiError('forbidden');
  if (row.state === 'expired') throw new ApiError('expired');
  if (row.state !== 'submitted') throw new ApiError('bad_request', { message: 'input request is not awaiting its value' });
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
 * Run an item PUT that completes a request, in the caller's transaction: a dashboard
 * request (`?write_request=`, `browser` session, open) or a device-flow request
 * (`?input_request=`, see `submittedInputRow`). The target item must match the
 * operation (`create`: no live item; `replace`: a live item), and the record must carry
 * a value: a request never completes with a deletion. A compare-and-swap conflict keeps
 * the preserved branch (spec §5) and closes the request as `conflict`; any other failure
 * rolls everything back and leaves the request as it was.
 */
export function completeWithItemPut(sql: SqlStorage, req: VaultRequest, itemId: string, body: JsonObject, put: () => ApiResult): ApiResult {
  const input = req.inputRequestId !== undefined;
  let row: Row;
  if (input) row = submittedInputRow(sql, req);
  else {
    if (req.claims.kind !== 'browser') throw new ApiError('forbidden');
    row = openRow(sql, req);
  }
  const record = parseItemPutBody(body, req.remoteAccess).record;
  if (typeof record !== 'object' || record === null || Array.isArray(record) || (record as JsonObject)['tombstone'] !== false) {
    throw new ApiError('bad_request', { message: 'a write request completes only with a value record' });
  }
  const live = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM items WHERE item_id = ? AND tombstone = 0', itemId).one().n > 0;
  if (row.operation === 'create' && live) throw new ApiError('bad_request', { message: 'write request targets a new secret' });
  if (row.operation === 'replace' && !live) throw new ApiError('bad_request', { message: 'write request targets an existing secret' });
  let result: ApiResult;
  try {
    result = put();
  } catch (err) {
    // A stale base below a later delete is refused before anything is written, so closing is safe.
    const refusal = toApiError(err);
    if (refusal.code !== 'tombstoned') throw err;
    closeRow(sql, row.request_id, 'conflict', 'revision_conflict', null, req.nowMs);
    return errorResult(refusal);
  }
  if (result.status === 200) {
    const receipt = randomId();
    closeRow(sql, row.request_id, 'completed', null, receipt, req.nowMs);
    return okResult({ ...(result.body as JsonObject), [input ? 'input_request' : 'write_request']: { state: 'completed', receipt } });
  }
  if (result.code === 'conflict') closeRow(sql, row.request_id, 'conflict', 'revision_conflict', null, req.nowMs);
  return result;
}

/** The caller's own device-flow request, or undefined (unknown, another account's, a dashboard one). Prune first. */
function ownInputRow(sql: SqlStorage, requestId: string, account: string): Row | undefined {
  const row = load(sql, requestId);
  return row && row.flow === 'device' && row.account === account ? row : undefined;
}

/**
 * `GET …/input-requests/{id}` by the requesting account's `input` session: what the
 * form shows beside the fragment (state, operation, requesting client, issuing device,
 * expiry). Another account's, a dashboard or an unknown request answer 404 alike.
 */
export function getInputRequest(sql: SqlStorage, requestId: string, account: string, nowMs: number): ApiResult {
  prune(sql, nowMs);
  const row = ownInputRow(sql, requestId, account);
  if (!row) return errorResult(new ApiError('not_found'));
  return okResult({ request_id: row.request_id, state: row.state, operation: row.operation, client_id: row.client_id, device_id: row.device_id, expires_at: row.expires_at });
}

/**
 * Take the single submission of a device-flow request (`pending_user` -> `submitted`):
 * 404 for another account's or an unknown one, 410 `expired` once past `expires_at`
 * (the row is marked expired), 409 `conflict` when it is not awaiting a submission
 * (a second POST included). Errors are returned, not thrown, so the expiry commits.
 * Caller holds the transaction.
 */
export function claimInputRequest(sql: SqlStorage, requestId: string, account: string, nowMs: number): ClaimInputResult {
  prune(sql, nowMs);
  const row = ownInputRow(sql, requestId, account);
  if (!row) return { error: errorResult(new ApiError('not_found')) };
  if (row.state === 'expired') return { error: errorResult(new ApiError('expired', { message: 'input request expired', extra: { state: 'expired' } })) };
  if (row.state !== 'pending_user') return { error: errorResult(new ApiError('conflict', { message: 'input request is not open', extra: { state: row.state } })) };
  sql.exec("UPDATE write_requests SET state = 'submitted' WHERE request_id = ?", requestId);
  return { claim: { deviceId: row.device_id!, clientId: row.client_id, grantId: row.grant_id } };
}

/** Undo a claim whose value never reached the device (it was offline or busy): `submitted` -> `pending_user`, only while still submitted. */
export function releaseInputRequest(sql: SqlStorage, requestId: string, nowMs: number): void {
  sql.exec("UPDATE write_requests SET state = 'pending_user' WHERE request_id = ? AND flow = 'device' AND state = 'submitted'", requestId);
  prune(sql, nowMs);
}

/**
 * Close a device-flow request the device could not complete, only while it is still
 * `submitted` (a request the device's item PUT already closed is left alone). Returns
 * the request's state and receipt afterwards, or null when it no longer exists.
 */
export function settleInputRequest(
  sql: SqlStorage,
  requestId: string,
  state: 'failed' | 'expired' | 'conflict',
  reason: WriteRequestReason | null,
  nowMs: number,
): { state: WriteRequestState; receipt: string | null } | null {
  sql.exec("UPDATE write_requests SET state = ?, reason = ?, intent = NULL, closed_at = ? WHERE request_id = ? AND flow = 'device' AND state = 'submitted'", state, reason, nowMs, requestId);
  const row = load(sql, requestId);
  return row ? { state: row.state, receipt: row.receipt } : null;
}
