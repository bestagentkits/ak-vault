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
 * Per-device budgets, each a fixed window of `rate_requests_per_window`:
 * `authorized` for requests that passed authorization (only the holder of the
 * device key can spend it), `refused` for requests refused before or during it.
 */
export type RateBucket = 'authorized' | 'refused';

const RATE_TABLES: Record<RateBucket, string> = {
  authorized: 'rate_counters',
  refused: 'refused_rate_counters',
};

interface RateWindow {
  table: string;
  windowStart: number;
  /** Requests already counted in the current window. */
  used: number;
  /** Seconds until the current window ends (at least 1). */
  retryAfter: number;
}

function rateWindow(sql: SqlStorage, bucket: RateBucket, did: string, nowMs: number): RateWindow {
  const table = RATE_TABLES[bucket];
  const windowMs = LIMITS.rate_window_seconds * 1000;
  const windowStart = Math.floor(nowMs / windowMs) * windowMs;
  const row = sql.exec<{ window_start: number; count: number }>(`SELECT window_start, count FROM ${table} WHERE did = ?`, did).toArray()[0];
  const used = row && row.window_start === windowStart ? row.count : 0;
  return { table, windowStart, used, retryAfter: Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000)) };
}

function rateLimited(retryAfter: number): ApiError {
  return new ApiError('rate_limited', { headers: { 'Retry-After': String(retryAfter) } });
}

/** Count one request against `bucket`; `rate_limited` once the window's budget is spent. */
export function enforceRateLimit(sql: SqlStorage, bucket: RateBucket, did: string, nowMs: number): void {
  const w = rateWindow(sql, bucket, did, nowMs);
  const count = w.used + 1;
  sql.exec(`INSERT INTO ${w.table} (did, window_start, count) VALUES (?, ?, ?) ON CONFLICT (did) DO UPDATE SET window_start = excluded.window_start, count = excluded.count`, did, w.windowStart, count);
  if (count > LIMITS.rate_requests_per_window) throw rateLimited(w.retryAfter);
}

/**
 * Read-only: `rate_limited` if `bucket` is already spent this window. Used on the
 * `authorized` budget before authorization, so a device over its own budget is
 * refused without verification work; only the key holder can have spent it.
 */
export function requireRateBudget(sql: SqlStorage, bucket: RateBucket, did: string, nowMs: number): void {
  const w = rateWindow(sql, bucket, did, nowMs);
  if (w.used >= LIMITS.rate_requests_per_window) throw rateLimited(w.retryAfter);
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
