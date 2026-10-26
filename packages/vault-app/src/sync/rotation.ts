/**
 * Credential rotation state for one item, derived from signed encrypted
 * metadata only. Rotating a provider credential (replacing the secret at the
 * provider) is a different act from a vault rekey (`key_epoch`): a rekey
 * re-wraps vault keys for the remaining devices and replaces no credential.
 *
 * Nothing here decides access. Dates and workflow fields are written by vault
 * members and displayed as such; an absent or malformed field is "unknown" or
 * "no workflow", never a guess.
 */
import type { JsonObject, JsonValue } from '@ak-vault/protocol';

export const DAY_MS = 86_400_000;
/** Show "due soon" this many days before the due date. */
export const DUE_SOON_DAYS = 7;
/** Longest rotation interval the dashboard writes (ten years). */
export const MAX_ROTATE_TTL_DAYS = 3650;

/** Key in `meta` that holds the workflow. Unknown to older writers, which carry it forward unchanged. */
export const ROTATION_META_KEY = 'rotation';
export const ROTATE_TTL_META_KEY = 'rotate_ttl_days';

export type RotationState = 'active' | 'paused' | 'failed' | 'cancelled';
const STATES: readonly RotationState[] = ['active', 'paused', 'failed', 'cancelled'];

/** A rotation an operator started. The vault step and the provider step are tracked separately. */
export interface RotationWorkflow {
  state: RotationState;
  startedMs: number;
  /** When the operator confirmed the old provider credential is revoked; null until they do. */
  revokedMs: number | null;
}

export type RotationHealth = 'needs_rotate' | 'overdue' | 'due_soon' | 'ok' | 'unknown';

export interface RotationInfo {
  health: RotationHealth;
  /** Base date plus the configured interval; null when either is missing. */
  dueMs: number | null;
  /** Whole days until due (negative when overdue); null when no due date. */
  daysUntilDue: number | null;
  /** The vault holds a new value written after the workflow started. */
  vaultUpdated: boolean;
  /** The operator confirmed the old provider credential is revoked after that vault write. */
  providerRevoked: boolean;
}

export interface RotationInput {
  createdMs: number | null;
  rotatedMs: number | null;
  rotateTtlDays: number | null;
  /** Time of the latest rekey that listed this item in `needs_rotate`; null when never listed. */
  flaggedMs: number | null;
  /** Key epoch that rekey installed. */
  flaggedEpoch: number | null;
  keyEpoch: number;
  workflow: RotationWorkflow | null;
}

function isMs(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}

/** Parse the workflow from `meta`; anything not exactly the expected shape is no workflow. */
export function parseRotationWorkflow(meta: JsonObject): RotationWorkflow | null {
  const raw: JsonValue | undefined = meta[ROTATION_META_KEY];
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const keys = Object.keys(raw);
  if (keys.some((k) => k !== 'state' && k !== 'started_ms' && k !== 'revoked_ms')) return null;
  const state = raw['state'];
  const startedMs = raw['started_ms'];
  const revokedMs = raw['revoked_ms'];
  if (typeof state !== 'string' || !STATES.includes(state as RotationState) || !isMs(startedMs)) return null;
  if (revokedMs !== undefined && !isMs(revokedMs)) return null;
  return { state: state as RotationState, startedMs, revokedMs: revokedMs ?? null };
}

export function workflowToMeta(w: RotationWorkflow): JsonObject {
  const out: JsonObject = { state: w.state, started_ms: w.startedMs };
  if (w.revokedMs !== null) out['revoked_ms'] = w.revokedMs;
  return out;
}

/**
 * The flag from a member or device removal clears only when the item was
 * rewritten with a new value under the key epoch that rekey installed. The
 * check errs toward keeping the warning: a missing date keeps it.
 */
export function stillNeedsRotate(i: RotationInput): boolean {
  if (i.flaggedMs === null) return false;
  if (i.rotatedMs === null || i.rotatedMs < i.flaggedMs) return true;
  return i.flaggedEpoch !== null && i.keyEpoch < i.flaggedEpoch;
}

export function rotationInfo(i: RotationInput, nowMs: number): RotationInfo {
  const base = i.rotatedMs ?? i.createdMs;
  const dueMs = base !== null && i.rotateTtlDays !== null ? base + i.rotateTtlDays * DAY_MS : null;
  const daysUntilDue = dueMs === null ? null : Math.floor((dueMs - nowMs) / DAY_MS);
  const vaultUpdated = i.workflow !== null && i.rotatedMs !== null && i.rotatedMs >= i.workflow.startedMs;
  const providerRevoked = vaultUpdated && i.workflow!.revokedMs !== null && i.workflow!.revokedMs >= i.rotatedMs!;
  let health: RotationHealth;
  if (stillNeedsRotate(i)) health = 'needs_rotate';
  else if (dueMs === null) health = 'unknown';
  else if (dueMs <= nowMs) health = 'overdue';
  else if (dueMs - nowMs <= DUE_SOON_DAYS * DAY_MS) health = 'due_soon';
  else health = 'ok';
  return { health, dueMs, daysUntilDue, vaultUpdated, providerRevoked };
}
