/**
 * Human-only write requests (`secrets_prepare_write`, spec §9.9) kept in the
 * account's relay object. A row holds routing and binding facts only: the vault,
 * the MCP grant and client that asked, the operation, the target name sealed to the
 * vault's seal key (ciphertext; the Worker cannot read it back) and, once claimed,
 * the browser device, item and base revision. It never holds a value: the value is
 * typed in the browser and travels only as a signed, sealed item record.
 *
 * Every transition is a compare-and-set on `status`, run inside `transactionSync`,
 * so two concurrent callers cannot both win one.
 */
import { REMOTE_ACCESS_LIMITS } from '../limits.js';

const L = REMOTE_ACCESS_LIMITS;

export const INTENT_STATUSES = ['pending_user', 'processing', 'queued', 'completed', 'conflict', 'expired', 'cancelled', 'failed'] as const;
export type IntentStatus = (typeof INTENT_STATUSES)[number];
export type IntentOp = 'create' | 'replace';

/** Statuses a request leaves only by time (purge). `queued` is reserved for a write that waits for a device. */
const OPEN: readonly IntentStatus[] = ['pending_user', 'processing'];

export type IntentRow = {
  rid: string;
  vault_id: string;
  grant_id: string;
  grant_iat: number;
  client_id: string;
  op: IntentOp;
  sensitivity: 'normal' | 'high' | null;
  /** Sealed-op wire JSON of the target name (ciphertext only). */
  target: string;
  status: IntentStatus;
  created_at: number;
  expires_at: number;
  did: string | null;
  item_id: string | null;
  base_revision: number | null;
  claimed_at: number | null;
  ended_at: number | null;
};

export const INTENT_SCHEMA = `
  CREATE TABLE IF NOT EXISTS write_intent (
    rid TEXT PRIMARY KEY, vault_id TEXT NOT NULL, grant_id TEXT NOT NULL, grant_iat INTEGER NOT NULL, client_id TEXT NOT NULL,
    op TEXT NOT NULL, sensitivity TEXT, target TEXT NOT NULL, status TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    did TEXT, item_id TEXT, base_revision INTEGER, claimed_at INTEGER, ended_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS write_intent_expiry ON write_intent (expires_at);
`;

export function getIntent(sql: SqlStorage, rid: string): IntentRow | null {
  return sql.exec<IntentRow>('SELECT * FROM write_intent WHERE rid = ?', rid).toArray()[0] ?? null;
}

export function openIntentCount(sql: SqlStorage, nowMs: number): number {
  return sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM write_intent WHERE status IN ('pending_user','processing') AND expires_at > ?", nowMs).one().n;
}

export function insertIntent(sql: SqlStorage, row: Omit<IntentRow, 'did' | 'item_id' | 'base_revision' | 'claimed_at' | 'ended_at' | 'status'>): void {
  sql.exec(
    `INSERT INTO write_intent (rid, vault_id, grant_id, grant_iat, client_id, op, sensitivity, target, status, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_user', ?, ?)`,
    row.rid,
    row.vault_id,
    row.grant_id,
    row.grant_iat,
    row.client_id,
    row.op,
    row.sensitivity,
    row.target,
    row.created_at,
    row.expires_at,
  );
}

/**
 * Move `rid` from `from` to `to` if it is still in `from`; true when this call won.
 * Ending states stamp `ended_at`, which starts the retention clock.
 */
export function transition(sql: SqlStorage, rid: string, from: IntentStatus, to: IntentStatus, nowMs: number): boolean {
  const ends = !OPEN.includes(to);
  return sql.exec('UPDATE write_intent SET status = ?, ended_at = CASE WHEN ? THEN ? ELSE ended_at END WHERE rid = ? AND status = ?', to, ends ? 1 : 0, nowMs, rid, from).rowsWritten === 1;
}

/** Claim a pending request for one browser device and the item revision it will write. */
export function claim(sql: SqlStorage, rid: string, did: string, itemId: string, baseRevision: number, nowMs: number): boolean {
  return (
    sql.exec(
      "UPDATE write_intent SET status = 'processing', did = ?, item_id = ?, base_revision = ?, claimed_at = ? WHERE rid = ? AND status = 'pending_user' AND expires_at > ?",
      did,
      itemId,
      baseRevision,
      nowMs,
      rid,
      nowMs,
    ).rowsWritten === 1
  );
}

/** Whether a claimed request has outlived the window to finish its browser write. */
export function processingOverdue(row: IntentRow, nowMs: number): boolean {
  return row.status === 'processing' && row.claimed_at !== null && nowMs >= row.claimed_at + L.write_intent_processing_s * 1000;
}

/** Earliest time a row becomes purgeable, or null when the table is empty. */
export function nextPurgeAt(sql: SqlStorage): number | null {
  const row = sql.exec<{ at: number | null }>('SELECT MIN(COALESCE(ended_at, expires_at)) AS at FROM write_intent').one();
  return row.at === null ? null : row.at + L.write_intent_retention_s * 1000;
}

/** Drop rows past retention: terminal ones after `ended_at`, never-finished ones after `expires_at`. */
export function purgeIntents(sql: SqlStorage, nowMs: number): void {
  sql.exec('DELETE FROM write_intent WHERE COALESCE(ended_at, expires_at) + ? <= ?', L.write_intent_retention_s * 1000, nowMs);
}
