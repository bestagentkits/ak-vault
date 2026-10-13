/**
 * Per-vault request checks that need vault state: rate limit, proof of
 * possession with single-use `jti`, membership of `sub`/`did`, token scope and
 * role. Order: rate limit -> membership -> proof -> scope -> role, all before
 * any item, wrap, audit or recovery data is read or written.
 */
import { isAkvError, verifyProof, type DeviceRecord, type MembershipState } from '@ak-vault/protocol';
import type { Scope } from '../auth/jwt-verify.js';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import type { VaultRequest } from './vault-request.js';

/** Who may call an op once authenticated. */
export type RoleRule = 'any_device' | 'writer' | 'human_owner';

export function enforceRateLimit(sql: SqlStorage, did: string, nowMs: number): void {
  const windowMs = LIMITS.rate_window_seconds * 1000;
  const windowStart = Math.floor(nowMs / windowMs) * windowMs;
  const row = sql.exec<{ window_start: number; count: number }>('SELECT window_start, count FROM rate_counters WHERE did = ?', did).toArray()[0];
  const count = row && row.window_start === windowStart ? row.count + 1 : 1;
  sql.exec('INSERT INTO rate_counters (did, window_start, count) VALUES (?, ?, ?) ON CONFLICT (did) DO UPDATE SET window_start = excluded.window_start, count = excluded.count', did, windowStart, count);
  if (count > LIMITS.rate_requests_per_window) {
    const retryAfter = Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000));
    throw new ApiError('rate_limited', { headers: { 'Retry-After': String(retryAfter) } });
  }
}

/** Verify `AKV-Proof` against `signPub` and burn its `jti` for this device. */
export function verifyRequestProof(sql: SqlStorage, req: VaultRequest, signPub: string): void {
  if (!req.proof) throw new ApiError('unauthorized');
  const did = req.claims.did;
  sql.exec('DELETE FROM proof_jti WHERE expires_at < ?', req.nowMs);
  try {
    const proof = verifyProof(req.proof, {
      htm: req.method,
      htu: req.htu,
      token: req.token,
      body: req.body,
      now: req.nowMs,
      signPub,
      maxSkewMs: LIMITS.clock_skew_seconds * 1000,
      isReplay: (jti) => sql.exec('SELECT 1 FROM proof_jti WHERE did = ? AND jti = ?', did, jti).toArray().length > 0,
    });
    sql.exec('INSERT INTO proof_jti (did, jti, expires_at) VALUES (?, ?, ?)', did, proof.jti, req.nowMs + LIMITS.proof_jti_ttl_seconds * 1000);
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
