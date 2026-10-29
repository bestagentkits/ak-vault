/**
 * Credential rotation state for one item, derived from signed encrypted
 * metadata only. Rotating a provider credential (replacing the secret at the
 * provider) is a different act from a vault rekey (`key_epoch`): a rekey
 * re-wraps vault keys for the remaining devices and replaces no credential.
 *
 * Nothing here decides access. Dates and workflow fields are written by vault
 * members and displayed as such; an absent or malformed field is "unknown" or
 * "no workflow", never a guess. Expiry comes only from the profile this device
 * verified (`VaultSnapshot.profiles`), never from a field the provenance check dropped.
 */
import { parseProfileValue, type JsonObject, type JsonValue } from '@ak-vault/protocol';

export const DAY_MS = 86_400_000;
/** Show "due soon" this many days before the due date. */
export const DUE_SOON_DAYS = 7;
/** Show "expires soon" this many days before a verified profile's `expires_at`. */
export const EXPIRING_SOON_DAYS = 14;
/** Longest rotation interval the dashboard writes (one hundred years). */
export const MAX_ROTATE_TTL_DAYS = 36500;

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

export type RotationHealth = 'needs_rotate' | 'awaiting_revoke' | 'overdue' | 'due_soon' | 'ok' | 'unknown';

/** Where a credential stands against its profile's `expires_at`. Separate from {@link RotationHealth} so neither hides the other. */
export type ExpiryHealth = 'expired' | 'expiring_soon' | 'ok';

export interface RotationInfo {
  health: RotationHealth;
  /** Base date plus the configured interval; null when either is missing. */
  dueMs: number | null;
  /** The vault holds a new value written after the workflow started. */
  vaultUpdated: boolean;
  /** The operator confirmed the old provider credential is revoked after that vault write. */
  providerRevoked: boolean;
  /** Null when the verified profile carries no valid `expires_at`. */
  expiry: ExpiryHealth | null;
  expiresMs: number | null;
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
  /** The verified profile's `expires_at` as unix ms ({@link parseExpiresMs}); null when absent or not verified. */
  expiresMs: number | null;
}

export function isMs(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}

/**
 * A profile `expires_at` (strict `YYYY-MM-DDTHH:MM:SSZ`, checked by the protocol's
 * profile rule) as unix ms. Anything else is null: no expiry is shown rather than a guess.
 */
export function parseExpiresMs(value: unknown): number | null {
  let text: string | string[];
  try {
    text = parseProfileValue('expires_at', value, 'expires_at');
  } catch {
    return null;
  }
  if (typeof text !== 'string') return null;
  // The protocol rule already fixed the form and calendar; a date before 1970 is still a real (past) expiry.
  const ms = Date.parse(text);
  return Number.isSafeInteger(ms) ? ms : null;
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
 * Removal exposure is cleared only by the operator's confirmation that the old
 * provider credential is revoked, recorded after a new value was written under
 * the key epoch that rekey installed. A rewrite alone (the dashboard's, or a
 * CLI `set`, which also bumps `rotated_ms` for an unchanged value) never clears
 * it, because nothing here can see whether the old credential still works.
 */
export function stillNeedsRotate(i: RotationInput): boolean {
  if (i.flaggedMs === null) return false;
  const revokedMs = i.workflow?.revokedMs ?? null;
  if (i.rotatedMs === null || revokedMs === null) return true;
  if (i.rotatedMs < i.flaggedMs || revokedMs < i.rotatedMs) return true;
  return i.flaggedEpoch !== null && i.keyEpoch < i.flaggedEpoch;
}

export function rotationInfo(i: RotationInput, nowMs: number): RotationInfo {
  const base = i.rotatedMs ?? i.createdMs;
  const dueMs = base !== null && i.rotateTtlDays !== null ? base + i.rotateTtlDays * DAY_MS : null;
  const vaultUpdated = i.workflow !== null && i.rotatedMs !== null && i.rotatedMs >= i.workflow.startedMs;
  const providerRevoked = vaultUpdated && i.workflow!.revokedMs !== null && i.workflow!.revokedMs >= i.rotatedMs!;
  let health: RotationHealth;
  if (stillNeedsRotate(i)) health = 'needs_rotate';
  else if (vaultUpdated && !providerRevoked && (i.workflow!.state === 'active' || i.workflow!.state === 'paused')) health = 'awaiting_revoke';
  else if (dueMs === null) health = 'unknown';
  else if (dueMs <= nowMs) health = 'overdue';
  else if (dueMs - nowMs <= DUE_SOON_DAYS * DAY_MS) health = 'due_soon';
  else health = 'ok';
  const expiresMs = i.expiresMs;
  const expiry: ExpiryHealth | null = expiresMs === null
    ? null
    : expiresMs <= nowMs ? 'expired' : expiresMs - nowMs <= EXPIRING_SOON_DAYS * DAY_MS ? 'expiring_soon' : 'ok';
  return { health, dueMs, vaultUpdated, providerRevoked, expiry, expiresMs };
}
