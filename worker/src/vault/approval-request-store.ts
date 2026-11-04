/**
 * Access approvals (spec §3.13, ADR 0006). A device whose local resolve found no grant
 * publishes a signed approval request; a person answers it from another enrolled human
 * device of the same account (the CLI, or the dashboard's browser device), whose signed
 * decision the requesting device verifies before it writes any local grant. A remote MCP
 * client may only deny, which needs no signature because it can only refuse access.
 *
 * The server never sees a secret name or value: the subject (secret name, agent, reason)
 * is encrypted under `VK[e]`. It keeps, in the clear, the account, requesting device,
 * key epoch, state and times, and after a decision the approver, its source and the
 * decision. It enforces account binding, the request and decision signatures against
 * current membership, expiry, caps, and single use: a request is decided at most once, so
 * a replayed or second decision is refused. The requester re-verifies the decision, so
 * the server cannot forge or upgrade one; it can only withhold it.
 *
 * Rows outlive their decision by `approval_request_retention_s` and serve as the
 * account's approval history (who answered, when, how, from where).
 */
import {
  SEALED_MAX_FUTURE_MS,
  SIGN_CONTEXT,
  cjson,
  parseApprovalDecision,
  parseApprovalRequest,
  verifyApprovalDecision,
  verifyObject,
  type ApprovalRequestWire,
  type JsonObject,
  type MembershipState,
} from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { REMOTE_ACCESS_LIMITS as L } from '../limits.js';
import { queryInt, requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

export const APPROVAL_STATES = ['pending', 'allowed', 'denied', 'cancelled', 'expired'] as const;
export type ApprovalState = (typeof APPROVAL_STATES)[number];

/** Where a decision came from. `mcp` decisions are always unsigned denials. */
export type ApprovalSource = 'device' | 'browser' | 'mcp';

type Row = {
  request_id: string;
  account: string;
  requester: string;
  key_epoch: number;
  wire: string;
  state: ApprovalState;
  decision: string | null;
  decision_kind: string | null;
  approver: string | null;
  source: ApprovalSource | null;
  mcp_client: string | null;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
};

/** Mark lapsed open requests expired and purge closed rows past retention. */
function sweep(sql: SqlStorage, nowMs: number): void {
  sql.exec("UPDATE approval_requests SET state = 'expired', decided_at = ? WHERE state = 'pending' AND expires_at <= ?", nowMs, nowMs);
  sql.exec("DELETE FROM approval_requests WHERE state <> 'pending' AND COALESCE(decided_at, expires_at) <= ?", nowMs - L.approval_request_retention_s * 1000);
}

function humanWriter(state: MembershipState, did: string, account: string): boolean {
  const d = state.devices.find((x) => x.device_id === did);
  return !!d && d.account === account && d.kind === 'human' && (d.role === 'owner' || d.role === 'editor');
}

/** The metadata view every list and get returns: no subject, which is encrypted anyway. */
function view(r: Row, withWire: boolean): JsonObject {
  return {
    request_id: r.request_id,
    requester: r.requester,
    key_epoch: r.key_epoch,
    state: r.state,
    created_at: r.created_at,
    expires_at: r.expires_at,
    ...(r.decided_at === null ? {} : { decided_at: r.decided_at }),
    ...(r.decision_kind === null ? {} : { decision_kind: r.decision_kind }),
    ...(r.approver === null ? {} : { approver: r.approver }),
    ...(r.source === null ? {} : { source: r.source }),
    ...(r.mcp_client === null ? {} : { mcp_client: r.mcp_client }),
    ...(withWire ? { request: JSON.parse(r.wire) as JsonObject } : {}),
    ...(withWire && r.decision !== null ? { decision: JSON.parse(r.decision) as JsonObject } : {}),
  };
}

function rowOf(sql: SqlStorage, requestId: string, account: string): Row {
  const row = sql.exec<Row>('SELECT * FROM approval_requests WHERE request_id = ? AND account = ?', requestId, account).toArray()[0];
  if (!row) throw new ApiError('not_found');
  return row;
}

/**
 * `POST /approval-requests` with `{"request":<wire>}` from the requesting device itself:
 * `requester` is the token `did`, a current device of the token `sub` (any kind, so a
 * background job's machine device may ask), the vault and key epoch are current, the
 * signature verifies, `ts` is within the clock window and the lifetime within
 * `approval_request_min_ttl_s..approval_request_ttl_s`. Caller holds the transaction.
 */
export function createApprovalRequest(sql: SqlStorage, state: MembershipState, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, ['request']);
  let wire: ApprovalRequestWire;
  try {
    wire = parseApprovalRequest(body['request']);
  } catch {
    throw new ApiError('bad_request');
  }
  const device = state.devices.find((d) => d.device_id === wire.requester);
  if (wire.requester !== req.claims.did || !device || device.account !== req.claims.sub) throw new ApiError('forbidden');
  if (wire.vault_id !== state.vault_id || wire.key_epoch !== state.key_epoch) throw new ApiError('bad_request');
  try {
    verifyObject(SIGN_CONTEXT.approvalRequest, wire, device.sign_pub);
  } catch {
    throw new ApiError('bad_request', { message: 'approval request signature does not verify' });
  }
  const life = wire.expires_at - wire.ts;
  if (wire.ts > req.nowMs + SEALED_MAX_FUTURE_MS || req.nowMs - wire.ts > SEALED_MAX_FUTURE_MS) throw new ApiError('bad_request', { message: 'approval request ts outside the clock window' });
  if (life < L.approval_request_min_ttl_s * 1000 || life > L.approval_request_ttl_s * 1000) throw new ApiError('bad_request', { message: 'approval request lifetime out of range' });
  sweep(sql, req.nowMs);
  if (sql.exec('SELECT 1 FROM approval_requests WHERE request_id = ?', wire.request_id).toArray().length > 0) throw new ApiError('conflict');
  const count = (where: string, ...args: unknown[]) => sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM approval_requests WHERE ${where}`, ...args).one().n;
  if (
    count("account = ? AND requester = ? AND state = 'pending'", req.claims.sub, wire.requester) >= L.approval_requests_pending_per_device ||
    count("account = ? AND state = 'pending'", req.claims.sub) >= L.approval_requests_pending_per_account
  ) {
    throw new ApiError('rate_limited', { message: 'too many approval requests' });
  }
  // History never blocks a new request: past the retained cap the oldest closed rows go first.
  const excess = count('account = ?', req.claims.sub) - L.approval_requests_retained_per_account + 1;
  if (excess > 0) {
    sql.exec(
      "DELETE FROM approval_requests WHERE request_id IN (SELECT request_id FROM approval_requests WHERE account = ? AND state <> 'pending' ORDER BY COALESCE(decided_at, expires_at) LIMIT ?)",
      req.claims.sub,
      excess,
    );
  }
  sql.exec(
    "INSERT INTO approval_requests (request_id, account, requester, key_epoch, wire, state, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
    wire.request_id,
    req.claims.sub,
    wire.requester,
    wire.key_epoch,
    cjson(wire as unknown as JsonObject),
    req.nowMs,
    wire.expires_at,
  );
  return okResult({ request_id: wire.request_id, state: 'pending', expires_at: wire.expires_at });
}

/**
 * `GET /approval-requests?state=pending|all&limit=`: the caller's account's requests,
 * newest first, each with its signed wire so an approving device can open the subject.
 */
export function listApprovalRequests(sql: SqlStorage, req: VaultRequest): ApiResult {
  const names = req.queryList.map(([n]) => n);
  if (names.some((n) => n !== 'state' && n !== 'limit') || new Set(names).size !== names.length) throw new ApiError('bad_request');
  const which = req.query['state'] ?? 'pending';
  if (which !== 'pending' && which !== 'all') throw new ApiError('bad_request');
  const limit = queryInt(req.query, 'limit', L.approval_page_max, L.approval_page_max);
  if (limit < 1) throw new ApiError('bad_request');
  sweep(sql, req.nowMs);
  const rows = sql
    .exec<Row>(`SELECT * FROM approval_requests WHERE account = ? ${which === 'pending' ? "AND state = 'pending'" : ''} ORDER BY created_at DESC LIMIT ?`, req.claims.sub, limit)
    .toArray();
  return okResult({ approvals: rows.map((r) => view(r, true)) });
}

/** `GET /approval-requests/{id}`: one request of the caller's account, with its decision once decided. */
export function getApprovalRequest(sql: SqlStorage, req: VaultRequest): ApiResult {
  sweep(sql, req.nowMs);
  return okResult(view(rowOf(sql, req.approvalRequestId!, req.claims.sub), true));
}

/**
 * `POST /approval-requests/{id}/decision` with `{"decision":<signed decision>}` from a human
 * `owner`/`editor` device of the requesting account other than the requester (the CLI on
 * another machine, or a browser device). The decision must verify against the stored
 * request and the approver's current `sign_pub`; only a `pending` request takes one.
 */
export function decideApprovalRequest(sql: SqlStorage, state: MembershipState, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, ['decision']);
  sweep(sql, req.nowMs);
  const row = rowOf(sql, req.approvalRequestId!, req.claims.sub);
  if (row.state !== 'pending') throw new ApiError('conflict', { message: 'approval request is not pending' });
  let decision;
  try {
    decision = parseApprovalDecision(body['decision']);
  } catch {
    throw new ApiError('bad_request');
  }
  if (decision.approver !== req.claims.did || !humanWriter(state, decision.approver, req.claims.sub)) throw new ApiError('forbidden');
  if (decision.approver === row.requester) throw new ApiError('forbidden', { message: 'a device cannot approve its own request' });
  if (row.key_epoch !== state.key_epoch) throw new ApiError('conflict', { message: 'the vault key changed since the request' });
  if (!state.devices.some((d) => d.device_id === row.requester)) throw new ApiError('conflict', { message: 'the requesting device is no longer a member' });
  const signPub = state.devices.find((d) => d.device_id === decision.approver)!.sign_pub;
  try {
    verifyApprovalDecision(decision, JSON.parse(row.wire), { approverSignPub: signPub });
  } catch {
    throw new ApiError('bad_request', { message: 'approval decision does not verify against this request' });
  }
  if (decision.ts > req.nowMs + SEALED_MAX_FUTURE_MS) throw new ApiError('bad_request');
  const next: ApprovalState = decision.decision === 'deny' ? 'denied' : 'allowed';
  const source: ApprovalSource = req.claims.kind === 'browser' ? 'browser' : 'device';
  const updated = sql
    .exec(
      "UPDATE approval_requests SET state = ?, decision = ?, decision_kind = ?, approver = ?, source = ?, decided_at = ? WHERE request_id = ? AND state = 'pending' RETURNING request_id",
      next,
      cjson(decision as unknown as JsonObject),
      decision.decision,
      decision.approver,
      source,
      req.nowMs,
      row.request_id,
    )
    .toArray();
  if (updated.length === 0) throw new ApiError('conflict');
  return okResult({ request_id: row.request_id, state: next });
}

/** `POST /approval-requests/{id}/cancel` (empty body): the requesting device withdraws its own pending request. */
export function cancelApprovalRequest(sql: SqlStorage, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, []);
  sweep(sql, req.nowMs);
  const row = rowOf(sql, req.approvalRequestId!, req.claims.sub);
  if (row.requester !== req.claims.did) throw new ApiError('forbidden');
  if (row.state !== 'pending') throw new ApiError('conflict', { message: 'approval request is not pending' });
  sql.exec("UPDATE approval_requests SET state = 'cancelled', decided_at = ? WHERE request_id = ? AND state = 'pending'", req.nowMs, row.request_id);
  return okResult({ request_id: row.request_id, state: 'cancelled' });
}

/** MCP `approvals_list`: metadata of account `sub`'s pending requests (no wire, no subject). */
export function listApprovalsForMcp(sql: SqlStorage, sub: string, nowMs: number): JsonObject[] {
  sweep(sql, nowMs);
  return sql
    .exec<Row>("SELECT * FROM approval_requests WHERE account = ? AND state = 'pending' ORDER BY created_at DESC LIMIT ?", sub, L.approval_page_max)
    .toArray()
    .map((r) => view(r, false));
}

/** MCP `approvals_deny`: an unsigned denial recorded with the client that sent it. Null for an unknown or closed request. */
export function denyApprovalForMcp(sql: SqlStorage, requestId: string, sub: string, clientId: string, nowMs: number): ApprovalState | null {
  sweep(sql, nowMs);
  const updated = sql
    .exec(
      "UPDATE approval_requests SET state = 'denied', decision_kind = 'deny', source = 'mcp', mcp_client = ?, decided_at = ? WHERE request_id = ? AND account = ? AND state = 'pending' RETURNING request_id",
      clientId,
      nowMs,
      requestId,
      sub,
    )
    .toArray();
  return updated.length === 0 ? null : 'denied';
}

/** Whether account `sub` holds a pending request with this id (the MCP allow link is only offered for one). */
export function hasPendingApproval(sql: SqlStorage, requestId: string, sub: string, nowMs: number): boolean {
  sweep(sql, nowMs);
  return sql.exec("SELECT 1 FROM approval_requests WHERE request_id = ? AND account = ? AND state = 'pending'", requestId, sub).toArray().length > 0;
}
