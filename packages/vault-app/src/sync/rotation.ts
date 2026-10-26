/**
 * Credential rotation tracking for the dashboard.
 *
 * Two different things are called "rotation" and they are never merged:
 *
 * - a vault rekey advances `key_epoch` and re-encrypts items for the devices that
 *   remain. It changes no provider credential;
 * - an external provider credential rotation replaces the secret an item holds
 *   and revokes the old one at the provider. Only a person can finish it.
 *
 * Progress lives in the item's own signed, encrypted metadata (`meta.rotation`,
 * `meta.rotate_ttl_days`), so it follows the vault's CAS, trust and permission
 * rules and the server never sees it. Everything here is display and workflow
 * state: nothing in it grants access or reaches a policy decision. Whether the
 * Vault holds the new value is derived from the verified `rotated_ms`; whether
 * the old provider key is revoked is only what an operator attested.
 */
import { AppError } from '../app-error.js';

export const MS_PER_DAY = 86_400_000;
/** A due date this close counts as "due soon". */
export const DUE_SOON_DAYS = 14;
export const MAX_ROTATE_TTL_DAYS = 3650;

export const ROTATION_STATES = ['in_progress', 'paused', 'failed', 'revoked'] as const;
export type RotationState = (typeof ROTATION_STATES)[number];

/** The guided rotation an operator recorded on an item. */
export interface RotationMeta {
  state: RotationState;
  startedMs: number;
  updatedMs: number;
  /** When the operator confirmed the old provider key was revoked (`revoked` only). */
  revokedMs: number | null;
}

export type RotationChange =
  | { kind: 'start' }
  | { kind: 'pause' }
  | { kind: 'resume' }
  | { kind: 'fail' }
  | { kind: 'cancel' }
  | { kind: 'confirm_revoked' }
  | { kind: 'set_ttl'; days: number | null };

export type RotationHealth =
  | 'needs_rotate'
  | 'rotating'
  | 'paused'
  | 'failed'
  | 'awaiting_revocation'
  | 'overdue'
  | 'expired'
  | 'due_soon'
  | 'expiring_soon'
  | 'ok'
  | 'untracked';

/** What the health of one item depends on. */
export interface RotationInput {
  createdMs: number | null;
  rotatedMs: number | null;
  rotateTtlDays: number | null;
  rotation: RotationMeta | null;
  /** `ts` of the newest rekey that listed this item in `needs_rotate`; null when it was never listed. */
  exposedSinceMs: number | null;
  /** The item profile's `expires_at` (RFC 3339 UTC), as the profile carries it. */
  expiresAt: string | null;
}

function isTs(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}

/** Read `meta.rotation`; anything malformed is treated as no rotation (it is only a display hint). */
export function parseRotation(raw: unknown): RotationMeta | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const state = o['state'];
  if (!ROTATION_STATES.includes(state as RotationState)) return null;
  if (!isTs(o['started_ms']) || !isTs(o['updated_ms'])) return null;
  const revoked = o['revoked_ms'];
  if (state === 'revoked' ? !isTs(revoked) : revoked !== undefined) return null;
  return { state: state as RotationState, startedMs: o['started_ms'], updatedMs: o['updated_ms'], revokedMs: state === 'revoked' ? (revoked as number) : null };
}

/** The strict `YYYY-MM-DDTHH:MM:SSZ` form the profile allows, as unix ms; null for anything else. */
export function parseExpiresAt(text: string | null): number | null {
  if (text === null || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(text)) return null;
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * True once the Vault itself holds a replacement value: the verified head's
 * `rotated_ms` is not older than the moment the rotation started, or than the
 * rekey that exposed the item. This says nothing about the provider.
 */
export function vaultStepDone(item: RotationInput): boolean {
  if (item.rotatedMs === null) return false;
  if (item.exposedSinceMs !== null && item.rotatedMs >= item.exposedSinceMs) return true;
  const r = item.rotation;
  return r !== null && r.state !== 'revoked' && item.rotatedMs >= r.startedMs;
}

export function revocationConfirmed(item: RotationInput): boolean {
  const r = item.rotation;
  return r !== null && r.state === 'revoked' && r.revokedMs !== null && item.rotatedMs !== null && r.revokedMs >= item.rotatedMs;
}

/** Health for the list and the summary. The order is the priority order. */
export function rotationHealth(item: RotationInput, nowMs: number): RotationHealth {
  const exposed = item.exposedSinceMs !== null;
  const replaced = vaultStepDone(item);
  if (exposed && !(item.rotatedMs !== null && item.rotatedMs >= item.exposedSinceMs!)) return 'needs_rotate';
  const r = item.rotation;
  if (r && r.state !== 'revoked') {
    if (replaced) return 'awaiting_revocation';
    return r.state === 'in_progress' ? 'rotating' : r.state;
  }
  if (replaced && !revocationConfirmed(item)) return 'awaiting_revocation';

  const expiry = parseExpiresAt(item.expiresAt);
  const base = item.rotatedMs ?? item.createdMs;
  const due = item.rotateTtlDays !== null && base !== null ? base + item.rotateTtlDays * MS_PER_DAY : null;
  if (expiry !== null && expiry <= nowMs) return 'expired';
  if (due !== null && due <= nowMs) return 'overdue';
  const soon = nowMs + DUE_SOON_DAYS * MS_PER_DAY;
  if (due !== null && due <= soon) return 'due_soon';
  if (expiry !== null && expiry <= soon) return 'expiring_soon';
  return due !== null || expiry !== null ? 'ok' : 'untracked';
}

/** The next rotation due date in unix ms, or null when the metadata does not give one. */
export function nextDueMs(item: RotationInput): number | null {
  const base = item.rotatedMs ?? item.createdMs;
  return item.rotateTtlDays !== null && base !== null ? base + item.rotateTtlDays * MS_PER_DAY : null;
}

export interface RotationUpdate {
  /** The new `meta.rotation`; undefined removes it. */
  rotation: RotationMeta | null;
  /** The new `meta.rotate_ttl_days`; null removes it. */
  rotateTtlDays: number | null;
}

/** Wire form of `meta.rotation`. */
export function rotationToMeta(r: RotationMeta): Record<string, number | string> {
  const out: Record<string, number | string> = { state: r.state, started_ms: r.startedMs, updated_ms: r.updatedMs };
  if (r.state === 'revoked' && r.revokedMs !== null) out['revoked_ms'] = r.revokedMs;
  return out;
}

/**
 * Apply one operator step to the item's tracked rotation. A step that does not
 * fit the current state is refused (`rotation_invalid`) so two devices acting on
 * stale views cannot skip a state: confirming a revocation needs a Vault commit
 * the verified head already shows, and a rotation whose Vault step is done can
 * no longer be cancelled.
 */
export function applyRotationChange(item: RotationInput, change: RotationChange, nowMs: number): RotationUpdate {
  const cur = item.rotation;
  const open = cur !== null && cur.state !== 'revoked';
  const keep = (rotation: RotationMeta | null): RotationUpdate => ({ rotation, rotateTtlDays: item.rotateTtlDays });
  const to = (state: RotationState): RotationUpdate => keep({ state, startedMs: cur!.startedMs, updatedMs: nowMs, revokedMs: null });
  switch (change.kind) {
    case 'set_ttl': {
      const d = change.days;
      if (d !== null && !(Number.isSafeInteger(d) && d >= 1 && d <= MAX_ROTATE_TTL_DAYS)) throw new AppError('rotation_invalid');
      return { rotation: cur, rotateTtlDays: d };
    }
    case 'start':
      if (open) throw new AppError('rotation_invalid');
      return keep({ state: 'in_progress', startedMs: nowMs, updatedMs: nowMs, revokedMs: null });
    case 'pause':
      if (!open || cur.state !== 'in_progress') throw new AppError('rotation_invalid');
      return to('paused');
    case 'resume':
      if (!open || cur.state === 'in_progress') throw new AppError('rotation_invalid');
      return to('in_progress');
    case 'fail':
      if (!open || cur.state === 'failed') throw new AppError('rotation_invalid');
      return to('failed');
    case 'cancel':
      if (!open || vaultStepDone(item)) throw new AppError('rotation_invalid');
      return keep(null);
    case 'confirm_revoked': {
      if (!vaultStepDone(item) || revocationConfirmed(item)) throw new AppError('rotation_invalid');
      const revokedMs = Math.max(nowMs, item.rotatedMs ?? 0);
      return keep({ state: 'revoked', startedMs: cur?.startedMs ?? revokedMs, updatedMs: revokedMs, revokedMs });
    }
  }
}
