/**
 * Sandbox secret leases (spec §3.14, §9.6, ADR 0007). A sandbox that is not a vault member
 * (the lease identity) publishes a self-signed request whose subject is sealed to the
 * vault's seal key; a human `owner`/`editor` device of the same account answers it with a
 * signed grant that seals the approved values to the sandbox's one-time lease key. The
 * sandbox fetches an allow exactly once.
 *
 * The server never sees a secret reference or value: both wires are opaque ciphertext to
 * it. It enforces account and requester binding, the current vault and key epoch, the
 * request and grant signatures (the grant against the approver's current `sign_pub`), the
 * clock window, lifetimes, caps, a single decision and single-use delivery. The grant
 * ciphertext is deleted when the lease is fetched, revoked or expires.
 *
 * States: `pending` -> `allowed` | `denied` | `revoked` | `expired`; `allowed` -> `fetched`
 * | `revoked` | `expired`. Closed rows stay `lease_retention_s` as history.
 */
import {
  SEALED_MAX_FUTURE_MS,
  cjson,
  parseLeaseGrant,
  parseLeaseRequest,
  verifyLeaseGrant,
  verifyLeaseRequestSignature,
  type JsonObject,
  type LeaseGrantWire,
  type LeaseRequestWire,
  type MembershipState,
} from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { REMOTE_ACCESS_LIMITS as L } from '../limits.js';
import { queryInt, requireKeys } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

export const LEASE_STATES = ['pending', 'allowed', 'denied', 'fetched', 'revoked', 'expired'] as const;
export type LeaseState = (typeof LEASE_STATES)[number];

type Row = {
  lease_id: string;
  account: string;
  requester: string;
  key_epoch: number;
  request: string;
  state: LeaseState;
  grant_wire: string | null;
  decision: string | null;
  approver: string | null;
  created_at: number;
  expires_at: number;
  grant_expires_at: number | null;
  decided_at: number | null;
  closed_at: number | null;
};

/**
 * Expire lapsed leases, revoke allowed leases that are no longer releasable, and purge
 * history past retention: a pending lease expires at its request's `expires_at`, an
 * allowed one at its grant's (its ciphertext deleted). Caller holds the transaction.
 */
function sweep(sql: SqlStorage, state: MembershipState, nowMs: number): void {
  sql.exec("UPDATE leases SET state = 'expired', closed_at = ? WHERE state = 'pending' AND expires_at <= ?", nowMs, nowMs);
  sql.exec("UPDATE leases SET state = 'expired', grant_wire = NULL, closed_at = ? WHERE state = 'allowed' AND grant_expires_at <= ?", nowMs, nowMs);
  revokeUnreleasable(sql, state, nowMs);
  sql.exec("DELETE FROM leases WHERE state NOT IN ('pending', 'allowed') AND closed_at <= ?", nowMs - L.lease_retention_s * 1000);
}

/**
 * Fail closed on release: an allowed lease is released only while its approver is still a
 * current human owner/editor device of the lease's account with the `sign_pub` the grant
 * carries, and the vault key epoch is still the lease's. Otherwise (approver removed,
 * demoted or re-keyed device; vault rekeyed) the lease becomes `revoked` and its grant is
 * deleted, so the sandbox's fetch answers 409.
 */
function revokeUnreleasable(sql: SqlStorage, state: MembershipState, nowMs: number): void {
  const rows = sql.exec<{ lease_id: string; account: string; key_epoch: number; grant_wire: string | null }>("SELECT lease_id, account, key_epoch, grant_wire FROM leases WHERE state = 'allowed'").toArray();
  for (const r of rows) {
    if (releasable(state, r.account, r.key_epoch, r.grant_wire)) continue;
    sql.exec("UPDATE leases SET state = 'revoked', grant_wire = NULL, closed_at = ? WHERE lease_id = ? AND state = 'allowed'", nowMs, r.lease_id);
  }
}

function releasable(state: MembershipState, account: string, keyEpoch: number, grantWire: string | null): boolean {
  if (grantWire === null || keyEpoch !== state.key_epoch) return false;
  let grant: LeaseGrantWire;
  try {
    grant = parseLeaseGrant(JSON.parse(grantWire));
  } catch {
    return false;
  }
  const device = state.devices.find((d) => d.device_id === grant.approver);
  return !!device && device.account === account && device.kind === 'human' && (device.role === 'owner' || device.role === 'editor') && device.sign_pub === grant.approver_key;
}

/** The expiry a client acts on: the grant's once allowed, else the request's approval window. */
function effectiveExpiry(r: Row): number {
  return r.grant_expires_at ?? r.expires_at;
}

/** The metadata view of list and get: the opaque request, never the grant ciphertext. */
function view(r: Row): JsonObject {
  return {
    lease_id: r.lease_id,
    requester: r.requester,
    key_epoch: r.key_epoch,
    state: r.state,
    created_at: r.created_at,
    expires_at: effectiveExpiry(r),
    ...(r.decided_at === null ? {} : { decided_at: r.decided_at }),
    ...(r.decision === null ? {} : { decision: r.decision }),
    ...(r.approver === null ? {} : { approver: r.approver }),
    request: JSON.parse(r.request) as JsonObject,
  };
}

/** One lease of `account`; another account's or an unknown one is `not_found`. */
function rowOf(sql: SqlStorage, leaseId: string, account: string): Row {
  const row = sql.exec<Row>('SELECT * FROM leases WHERE lease_id = ? AND account = ?', leaseId, account).toArray()[0];
  if (!row) throw new ApiError('not_found');
  return row;
}

/** A lease of the calling sandbox: also `not_found` to any `did` but the request's requester. */
function requesterRowOf(sql: SqlStorage, req: VaultRequest): Row {
  const row = rowOf(sql, req.leaseId!, req.claims.sub);
  if (row.requester !== req.claims.did) throw new ApiError('not_found');
  return row;
}

/**
 * `POST /leases` with `{"request":<wire>}` from the lease identity: `account` is the token
 * `sub`, `requester` the token `did`, the vault and key epoch are current, the signature
 * verifies, `ts` is within the clock window and the approval window within
 * `lease_request_min_ttl_s..lease_request_ttl_s`. Caller holds the transaction.
 */
export function createLease(sql: SqlStorage, state: MembershipState, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, ['request']);
  let wire: LeaseRequestWire;
  try {
    wire = parseLeaseRequest(body['request']);
  } catch {
    throw new ApiError('bad_request');
  }
  if (wire.account !== req.claims.sub || wire.requester !== req.claims.did) throw new ApiError('bad_request');
  if (wire.vault_id !== state.vault_id || wire.key_epoch !== state.key_epoch) throw new ApiError('bad_request');
  try {
    verifyLeaseRequestSignature(wire);
  } catch {
    throw new ApiError('bad_request', { message: 'lease request signature does not verify' });
  }
  if (wire.ts > req.nowMs + SEALED_MAX_FUTURE_MS || req.nowMs - wire.ts > SEALED_MAX_FUTURE_MS) throw new ApiError('bad_request', { message: 'lease request ts outside the clock window' });
  const life = wire.expires_at - wire.ts;
  if (life < L.lease_request_min_ttl_s * 1000 || life > L.lease_request_ttl_s * 1000) throw new ApiError('bad_request', { message: 'lease request lifetime out of range' });
  sweep(sql, state, req.nowMs);
  if (sql.exec('SELECT 1 FROM leases WHERE lease_id = ?', wire.lease_id).toArray().length > 0) throw new ApiError('conflict');
  const count = (where: string, ...args: unknown[]) => sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM leases WHERE ${where}`, ...args).one().n;
  if (count("account = ? AND state = 'pending'", req.claims.sub) >= L.leases_pending_per_account) throw new ApiError('rate_limited', { message: 'too many pending leases' });
  // History never blocks a new lease: past the retained cap the oldest closed rows go first.
  const excess = count('account = ?', req.claims.sub) - L.leases_retained_per_account + 1;
  if (excess > 0) {
    sql.exec(
      "DELETE FROM leases WHERE lease_id IN (SELECT lease_id FROM leases WHERE account = ? AND state NOT IN ('pending', 'allowed') ORDER BY closed_at LIMIT ?)",
      req.claims.sub,
      excess,
    );
  }
  sql.exec(
    "INSERT INTO leases (lease_id, account, requester, key_epoch, request, state, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
    wire.lease_id,
    req.claims.sub,
    wire.requester,
    wire.key_epoch,
    cjson(wire as unknown as JsonObject),
    req.nowMs,
    wire.expires_at,
  );
  return okResult({ lease_id: wire.lease_id, state: 'pending', expires_at: wire.expires_at });
}

/** `GET /leases/{id}/status` for the requesting sandbox. */
export function leaseStatus(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  sweep(sql, state, req.nowMs);
  const row = requesterRowOf(sql, req);
  return okResult({ lease_id: row.lease_id, state: row.state, expires_at: effectiveExpiry(row) });
}

/**
 * `POST /leases/{id}/fetch` (`{}`) by the requesting sandbox. An allowed lease returns its
 * grant and, in the same transaction, becomes `fetched` without its ciphertext; a denied
 * lease returns its (value-free) grant and stays `denied`; anything else is `409`.
 * Caller holds the transaction; the result is never stored for idempotent replay.
 */
export function fetchLease(sql: SqlStorage, state: MembershipState, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, []);
  sweep(sql, state, req.nowMs);
  const row = requesterRowOf(sql, req);
  if (row.state === 'denied' && row.grant_wire !== null) {
    return okResult({ lease_id: row.lease_id, state: 'denied', grant: JSON.parse(row.grant_wire) as JsonObject });
  }
  if (row.state !== 'allowed' || row.grant_wire === null) throw new ApiError('conflict', { message: 'lease is not ready to fetch' });
  const taken = sql
    .exec("UPDATE leases SET state = 'fetched', grant_wire = NULL, closed_at = ? WHERE lease_id = ? AND state = 'allowed' RETURNING lease_id", req.nowMs, row.lease_id)
    .toArray();
  if (taken.length === 0) throw new ApiError('conflict', { message: 'lease is not ready to fetch' });
  return okResult({ lease_id: row.lease_id, state: 'fetched', grant: JSON.parse(row.grant_wire) as JsonObject });
}

/** `GET /leases?state=pending|all&limit=`: the caller's account's leases, newest first. */
export function listLeases(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  const names = req.queryList.map(([n]) => n);
  if (names.some((n) => n !== 'state' && n !== 'limit') || new Set(names).size !== names.length) throw new ApiError('bad_request');
  const which = req.query['state'] ?? 'pending';
  if (which !== 'pending' && which !== 'all') throw new ApiError('bad_request');
  const limit = queryInt(req.query, 'limit', L.lease_page_max, L.lease_page_max);
  if (limit < 1) throw new ApiError('bad_request');
  sweep(sql, state, req.nowMs);
  const rows = sql
    .exec<Row>(`SELECT * FROM leases WHERE account = ? ${which === 'pending' ? "AND state = 'pending'" : ''} ORDER BY created_at DESC, lease_id LIMIT ?`, req.claims.sub, limit)
    .toArray();
  return okResult({ leases: rows.map(view) });
}

/** `GET /leases/{id}`: one lease of the caller's account. */
export function getLease(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  sweep(sql, state, req.nowMs);
  return okResult(view(rowOf(sql, req.leaseId!, req.claims.sub)));
}

/**
 * `POST /leases/{id}/grant` with `{"grant":<wire>}` from the approving device itself: a
 * current human `owner`/`editor` device of the lease's account whose `sign_pub` is the
 * grant's `approver_key`. The lease must be pending and its key epoch current; the grant
 * must verify against the stored request. Caller holds the transaction.
 */
export function grantLease(sql: SqlStorage, state: MembershipState, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, ['grant']);
  sweep(sql, state, req.nowMs);
  const row = rowOf(sql, req.leaseId!, req.claims.sub);
  let grant: LeaseGrantWire;
  try {
    grant = parseLeaseGrant(body['grant']);
  } catch {
    throw new ApiError('bad_request');
  }
  const device = state.devices.find((d) => d.device_id === grant.approver);
  if (
    grant.approver !== req.claims.did ||
    !device ||
    device.account !== req.claims.sub ||
    device.kind !== 'human' ||
    (device.role !== 'owner' && device.role !== 'editor') ||
    device.sign_pub !== grant.approver_key
  ) {
    throw new ApiError('forbidden');
  }
  if (row.state !== 'pending') throw new ApiError('conflict', { message: 'lease is not pending' });
  if (row.key_epoch !== state.key_epoch) throw new ApiError('conflict', { message: 'the vault key changed since the request' });
  try {
    verifyLeaseGrant(grant, JSON.parse(row.request));
  } catch {
    throw new ApiError('bad_request', { message: 'lease grant does not verify against this request' });
  }
  if (grant.ts > req.nowMs + SEALED_MAX_FUTURE_MS || req.nowMs - grant.ts > SEALED_MAX_FUTURE_MS) throw new ApiError('bad_request', { message: 'lease grant ts outside the clock window' });
  const allow = grant.decision === 'allow';
  // An allow always carries `expires_at` (parseLeaseGrant); one already past is useless to the sandbox.
  const grantExpiresAt = allow ? (grant.expires_at ?? 0) : null;
  if (grantExpiresAt !== null && grantExpiresAt <= req.nowMs) throw new ApiError('bad_request', { message: 'lease grant already expired' });
  const next: LeaseState = allow ? 'allowed' : 'denied';
  const updated = sql
    .exec(
      "UPDATE leases SET state = ?, grant_wire = ?, decision = ?, approver = ?, decided_at = ?, grant_expires_at = ?, closed_at = ? WHERE lease_id = ? AND state = 'pending' RETURNING lease_id",
      next,
      cjson(grant as unknown as JsonObject),
      grant.decision,
      grant.approver,
      req.nowMs,
      grantExpiresAt,
      allow ? null : req.nowMs,
      row.lease_id,
    )
    .toArray();
  if (updated.length === 0) throw new ApiError('conflict');
  return okResult({ lease_id: row.lease_id, state: next });
}

/** `POST /leases/{id}/revoke` (`{}`): close a pending or allowed lease and delete its grant. */
export function revokeLease(sql: SqlStorage, state: MembershipState, req: VaultRequest, body: JsonObject): ApiResult {
  requireKeys(body, []);
  sweep(sql, state, req.nowMs);
  const row = rowOf(sql, req.leaseId!, req.claims.sub);
  const updated = sql
    .exec("UPDATE leases SET state = 'revoked', grant_wire = NULL, closed_at = ? WHERE lease_id = ? AND state IN ('pending', 'allowed') RETURNING lease_id", req.nowMs, row.lease_id)
    .toArray();
  if (updated.length === 0) throw new ApiError('conflict', { message: 'lease is not open' });
  return okResult({ lease_id: row.lease_id, state: 'revoked' });
}
