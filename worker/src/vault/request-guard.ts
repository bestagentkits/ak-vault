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
import { isAkvError, verifyProof, type DeviceRecord, type MembershipState } from '@ak-vault/protocol';
import type { Scope } from '../auth/jwt-verify.js';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';
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

const RATE_BUCKETS: Record<RateBucket, { table: string; key: string; limit: number }> = {
  authorized: { table: 'rate_counters', key: 'did', limit: LIMITS.rate_requests_per_window },
  refused: { table: 'refused_rate_counters', key: 'did', limit: LIMITS.rate_requests_per_window },
  recovery_identity: { table: 'recovery_identity_rate_counters', key: 'account', limit: LIMITS.recovery_identity_requests_per_window },
};

interface RateWindow {
  table: string;
  key: string;
  limit: number;
  windowStart: number;
  /** Requests already counted in the current window. */
  used: number;
  /** Seconds until the current window ends (at least 1). */
  retryAfter: number;
}

function rateWindow(sql: SqlStorage, bucket: RateBucket, subject: string, nowMs: number): RateWindow {
  const { table, key, limit } = RATE_BUCKETS[bucket];
  const windowMs = LIMITS.rate_window_seconds * 1000;
  const windowStart = Math.floor(nowMs / windowMs) * windowMs;
  const row = sql.exec<{ window_start: number; count: number }>(`SELECT window_start, count FROM ${table} WHERE ${key} = ?`, subject).toArray()[0];
  const used = row && row.window_start === windowStart ? row.count : 0;
  return { table, key, limit, windowStart, used, retryAfter: Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000)) };
}

function rateLimited(retryAfter: number): ApiError {
  return new ApiError('rate_limited', { headers: { 'Retry-After': String(retryAfter) } });
}

/**
 * Count one request against `bucket` for `subject` (a device ID, or an account for
 * `recovery_identity`); `rate_limited` once the window's budget is spent. A storage
 * error propagates, so the request fails closed.
 */
export function enforceRateLimit(sql: SqlStorage, bucket: RateBucket, subject: string, nowMs: number): void {
  const w = rateWindow(sql, bucket, subject, nowMs);
  const count = w.used + 1;
  sql.exec(
    `INSERT INTO ${w.table} (${w.key}, window_start, count) VALUES (?, ?, ?) ON CONFLICT (${w.key}) DO UPDATE SET window_start = excluded.window_start, count = excluded.count`,
    subject,
    w.windowStart,
    count,
  );
  // A subject's first request of a window drops every row of earlier windows (each counts as zero), so the
  // table holds at most the subjects seen in the current window, however many fresh device IDs are named.
  // Request times are stamped in the Worker, so a request delayed across a boundary can see its own
  // window's rows already gone; that grants it at most a fresh budget for that window, never a larger one.
  if (w.used === 0) sql.exec(`DELETE FROM ${w.table} WHERE window_start < ?`, w.windowStart);
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
 * written (genesis preflight before the vault has storage).
 */
export function verifyRequestProof(sql: SqlStorage | null, req: VaultRequest, signPub: string): void {
  if (!req.proof) throw new ApiError('unauthorized');
  const did = req.claims.did;
  sql?.exec('DELETE FROM proof_jti WHERE expires_at < ?', req.nowMs);
  try {
    const proof = verifyProof(req.proof, {
      htm: req.method,
      htu: req.htu,
      token: req.token,
      body: req.body,
      now: req.nowMs,
      signPub,
      maxSkewMs: LIMITS.clock_skew_seconds * 1000,
      isReplay: (jti) => (sql ? sql.exec('SELECT 1 FROM proof_jti WHERE did = ? AND jti = ?', did, jti).toArray().length > 0 : false),
    });
    sql?.exec('INSERT INTO proof_jti (did, jti, expires_at) VALUES (?, ?, ?)', did, proof.jti, req.nowMs + LIMITS.proof_jti_ttl_seconds * 1000);
  } catch (err) {
    if (isAkvError(err) && err.code === 'invalid_signature') throw new ApiError('invalid_signature', { status: 401 });
    throw new ApiError('unauthorized');
  }
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
