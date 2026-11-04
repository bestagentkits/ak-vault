/**
 * Per-vault request checks that need vault state: rate limit, proof of
 * possession with single-use `jti`, membership of `sub`/`did`, token scope and
 * role. Order for an existing vault: read-only check of the device's `authorized`
 * budget -> Idempotency-Key format (mutations) -> membership -> proof -> scope ->
 * role -> charge the `authorized` budget, all before any item, wrap, audit or
 * recovery data is read or written. A refusal by the Idempotency-Key check or
 * authorization (for example a stolen token without the device key) is charged
 * to the separate `refused` budget, so it cannot exhaust the budget of the
 * device it names.
 */
import { isAkvError, verifyProof, type DeviceRecord, type MembershipState, type TransportProof } from '@ak-vault/protocol';
import type { Scope } from '../auth/jwt-verify.js';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { replayStateFor } from './request-replay-state.js';
import type { VaultRequest } from './vault-request.js';

/** Who may call an op once authenticated. */
export type RoleRule = 'any_device' | 'writer' | 'human_owner';

/**
 * Fixed-window budgets of `rate_window_seconds`. Per device (`rate_requests_per_window`
 * each): `authorized` for requests that passed authorization (only the holder of the
 * device key can spend it), `refused` for requests refused before or during it. Per
 * account (`recovery_identity_requests_per_window`): `recovery_identity` for every
 * request on the recovery-identity path whose proof verifies, so device IDs the
 * caller chooses cannot multiply that path's budget.
 */
export type RateBucket = 'authorized' | 'refused' | 'recovery_identity';

const RATE_BUCKETS: Record<RateBucket, number> = {
  authorized: LIMITS.rate_requests_per_window,
  refused: LIMITS.rate_requests_per_window,
  recovery_identity: LIMITS.recovery_identity_requests_per_window,
};

interface RateWindow {
  key: string;
  limit: number;
  windowStart: number;
  /** Requests already counted in the current window. */
  used: number;
  /** Seconds until the current window ends (at least 1). */
  retryAfter: number;
}

// Windows and burned `jti`s live in the vault object's memory (request-replay-state.ts), so a
// steady-state request writes no rows.
function rateWindow(sql: SqlStorage, bucket: RateBucket, subject: string, nowMs: number): RateWindow {
  const windowMs = LIMITS.rate_window_seconds * 1000;
  const windowStart = Math.floor(nowMs / windowMs) * windowMs;
  const key = `${bucket}\n${subject}`;
  const row = replayStateFor(sql, nowMs).rate(key);
  const used = row && row.windowStart === windowStart ? row.count : 0;
  return { key, limit: RATE_BUCKETS[bucket], windowStart, used, retryAfter: Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000)) };
}

function rateLimited(retryAfter: number): ApiError {
  return new ApiError('rate_limited', { headers: { 'Retry-After': String(retryAfter) } });
}

/**
 * Count one request against `bucket` for `subject` (a device ID, or an account for
 * `recovery_identity`); `rate_limited` once the window's budget is spent.
 */
export function enforceRateLimit(sql: SqlStorage, bucket: RateBucket, subject: string, nowMs: number): void {
  const w = rateWindow(sql, bucket, subject, nowMs);
  const count = w.used + 1;
  const state = replayStateFor(sql, nowMs);
  // A subject's first request of a window drops the bucket's counters of earlier windows, so memory
  // holds at most the subjects seen in the current window, however many fresh device IDs are named.
  if (w.used === 0) state.dropRatesBefore(`${bucket}\n`, w.windowStart);
  state.setRate(w.key, { windowStart: w.windowStart, count });
  if (count > w.limit) throw rateLimited(w.retryAfter);
}

/**
 * Read-only: `rate_limited` if `bucket` is already spent this window. Used on the
 * `authorized` budget before authorization, and on the `recovery_identity` budget
 * before that path's key and proof checks, so a spent budget is refused without
 * verification work; only requests with a verified proof can have spent either.
 */
export function requireRateBudget(sql: SqlStorage, bucket: RateBucket, subject: string, nowMs: number): void {
  const w = rateWindow(sql, bucket, subject, nowMs);
  if (w.used >= w.limit) throw rateLimited(w.retryAfter);
}

/**
 * Verify `AKV-Proof` against `signPub` and burn its `jti` for this device. With
 * `sql === null` only the signature and bindings are checked and nothing is
 * kept (genesis preflight before the vault has storage).
 */
export function verifyRequestProof(sql: SqlStorage | null, req: VaultRequest, signPub: string): void {
  if (!req.proof) throw new ApiError('unauthorized');
  const did = req.claims.did;
  const state = sql ? replayStateFor(sql, req.nowMs) : null;
  let proof: TransportProof;
  try {
    proof = verifyProof(req.proof, {
      htm: req.method,
      htu: req.htu,
      token: req.token,
      body: req.body,
      now: req.nowMs,
      signPub,
      maxSkewMs: LIMITS.clock_skew_seconds * 1000,
    });
  } catch (err) {
    if (isAkvError(err) && err.code === 'invalid_signature') throw new ApiError('invalid_signature', { status: 401 });
    throw new ApiError('unauthorized');
  }
  if (state?.isReplay(did, proof.jti, proof.ts, req.nowMs)) throw new ApiError('unauthorized');
  // A storage error writing the session marker propagates, so the request fails closed.
  state?.burn(did, proof.jti, req.nowMs);
}

export function requireScope(scopes: readonly Scope[], needed: readonly Scope[]): void {
  if (!needed.some((s) => scopes.includes(s))) throw new ApiError('forbidden');
}

/** The current device for the token, which must belong to the token's account. */
export function memberDevice(state: MembershipState, sub: string, did: string): DeviceRecord {
  const device = state.devices.find((d) => d.device_id === did);
  if (!device || device.account !== sub) throw new ApiError('forbidden');
  if (!state.members.some((m) => m.account === sub)) throw new ApiError('forbidden');
  return device;
}

export function enforceRole(device: DeviceRecord, rule: RoleRule): void {
  if (rule === 'any_device') return;
  if (device.kind !== 'human') throw new ApiError('forbidden');
  if (rule === 'writer' && (device.role === 'owner' || device.role === 'editor')) return;
  if (rule === 'human_owner' && device.role === 'owner') return;
  throw new ApiError('forbidden');
}
