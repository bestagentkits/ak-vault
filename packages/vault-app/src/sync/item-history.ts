/**
 * Per-item revision history, rebuilt from the signed change log.
 *
 * The whole log is fetched again and verified from position 1 against the
 * verified membership, the removal fences and the head this browser already
 * witnessed, exactly as the vault pull does. Only then are the records of one
 * item replayed with the protocol's own CAS rules, and the server's conflict
 * labels must equal what the replay derives. Nothing here trusts the order the
 * server served beyond that: a gap, a reorder, a substituted record or a
 * relabelled branch fails closed.
 *
 * An entry carries metadata only. Each ciphertext is opened once to learn
 * whether this browser can authenticate it, and the plaintext is dropped on
 * the spot; no value is returned, rendered or kept. The records stay (they are
 * ciphertext) so a restore can re-seal an old value without another request.
 */
import { applyRecord, isAkvError, verifyChangeLog, type ItemState, type SignedRecord, type VerifiedChangeLog } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { AkvClient } from './akv-client.js';
import { fetchChanges, openRecord, type ChangeEntry, type VaultSnapshot } from './vault-sync.js';

/** Newest entries kept per item; older ones are counted, not listed. */
export const MAX_HISTORY_ENTRIES = 500;

/**
 * - `readable`: this browser holds the key for the record's epoch and the
 *   ciphertext authenticated against its signed context.
 * - `no_key`: the browser was never given that epoch's key.
 * - `unverified`: the key is held but the ciphertext did not authenticate.
 */
export type EntryReadability = 'readable' | 'no_key' | 'unverified';

/** Why an applied revision cannot be restored from this browser. */
export type RestoreBlock = 'current' | 'deletion' | 'before_deletion' | 'no_key' | 'unverified';

export interface HistoryEntry {
  /** Verified change-log position. */
  logSeq: number;
  kind: 'applied' | 'conflict';
  /** The revision an applied record created; null for a conflict branch. */
  revision: number | null;
  baseRevision: number;
  conflictId: string | null;
  /** Conflict branches only: open now, or resolved by the revision that listed it. */
  conflictOpen: boolean;
  resolvedAtRevision: number | null;
  /** Branch IDs this record resolves. */
  resolves: string[];
  author: string;
  /** Whether the author is a current device (otherwise it was removed). */
  authorCurrent: boolean;
  /** Signed by the author, not attested by the server. */
  ts: number;
  tombstone: boolean;
  keyEpoch: number;
  readability: EntryReadability;
  /** Applied, live revisions only: null when it can be restored. */
  restoreBlock: RestoreBlock | null;
  /** Ciphertext and signature; used only to re-seal a value in memory. */
  record: SignedRecord;
}

export interface ItemHistory {
  itemId: string;
  /** Newest first, at most {@link MAX_HISTORY_ENTRIES}. */
  entries: HistoryEntry[];
  omitted: number;
  /** Verified log position this history is complete to (the server may still withhold newer entries). */
  logSeq: number;
  /** The item or its open branches moved on since the dashboard's list was verified. */
  stale: boolean;
  /** The item is deleted at its head. */
  deleted: boolean;
  openConflicts: number;
}

function readabilityOf(snapshot: VaultSnapshot, record: SignedRecord): EntryReadability {
  const vk = snapshot.vaultKeys.get(record.key_epoch);
  if (!vk) return 'no_key';
  const opened = openRecord(record, vk);
  // The plaintext is not kept; only whether it authenticated is.
  return opened === null ? 'unverified' : 'readable';
}

/** The log must continue the position this browser witnessed and respect every removal fence. */
function verifyLog(entries: readonly ChangeEntry[], snapshot: VaultSnapshot): VerifiedChangeLog {
  const kept = new Map<number, string>();
  if (snapshot.witnessed.log_seq > 0) kept.set(snapshot.witnessed.log_seq, snapshot.witnessed.log_head);
  try {
    return verifyChangeLog(entries, snapshot.state, { complete: true, keptHeads: kept });
  } catch (err) {
    throw new AppError(isAkvError(err) && err.code === 'rollback' ? 'rollback' : 'vault_verification_failed');
  }
}

function sameConflicts(a: ItemState, b: ItemState): boolean {
  const ids = (s: ItemState) => s.conflicts.map((c) => c.conflict_id).sort().join(',');
  return ids(a) === ids(b);
}

/** Verify the log and replay one item. Throws the same AppError codes as a vault pull. */
export async function loadItemHistory(client: AkvClient, snapshot: VaultSnapshot, itemId: string): Promise<ItemHistory> {
  const shown = snapshot.itemStates.get(itemId);
  if (!shown) throw new AppError('not_found');
  const entries = await fetchChanges(client, snapshot.vaultId);
  const verified = verifyLog(entries, snapshot);

  let state: ItemState | undefined;
  const rows: HistoryEntry[] = [];
  verified.records.forEach((record: SignedRecord, i: number) => {
    if (record.item_id !== itemId) return;
    const entry = entries[i]!;
    const conflictId = entry.conflict_id === null ? undefined : (entry.conflict_id as string);
    let applied;
    try {
      applied = applyRecord(state, record, conflictId === undefined ? {} : { conflictId });
    } catch {
      throw new AppError('vault_verification_failed');
    }
    if ((conflictId === undefined) !== (applied.outcome.status === 'applied')) throw new AppError('vault_verification_failed');
    state = applied.state;
    const isApplied = applied.outcome.status === 'applied';
    rows.push({
      logSeq: entry.log_seq as number,
      kind: isApplied ? 'applied' : 'conflict',
      revision: isApplied ? record.base_revision + 1 : null,
      baseRevision: record.base_revision,
      conflictId: conflictId ?? null,
      conflictOpen: false,
      resolvedAtRevision: null,
      resolves: [...record.resolves],
      author: record.author,
      authorCurrent: snapshot.state.devices.some((d) => d.device_id === record.author),
      ts: record.ts,
      tombstone: record.tombstone,
      keyEpoch: record.key_epoch,
      readability: readabilityOf(snapshot, record),
      restoreBlock: null,
      record,
    });
  });
  if (!state) throw new AppError('vault_verification_failed');
  const final: ItemState = state;

  const openIds = new Set(final.conflicts.map((c) => c.conflict_id));
  for (const row of rows) {
    if (row.kind !== 'conflict') continue;
    row.conflictOpen = openIds.has(row.conflictId!);
    if (!row.conflictOpen) row.resolvedAtRevision = rows.find((r) => r.kind === 'applied' && r.resolves.includes(row.conflictId!))?.revision ?? null;
  }
  for (const row of rows) {
    if (row.kind !== 'applied' || row.tombstone) continue;
    row.restoreBlock = restoreBlockOf(row, final);
  }
  for (const row of rows) {
    if (row.kind === 'applied' && row.tombstone) row.restoreBlock = 'deletion';
  }

  const stale = final.revision !== shown.revision || final.head !== shown.head || !sameConflicts(final, shown);
  const newestFirst = rows.sort((a, b) => b.logSeq - a.logSeq);
  return {
    itemId,
    entries: newestFirst.slice(0, MAX_HISTORY_ENTRIES),
    omitted: Math.max(0, newestFirst.length - MAX_HISTORY_ENTRIES),
    logSeq: verified.head.log_seq,
    stale,
    deleted: final.tombstone,
    openConflicts: final.conflicts.length,
  };
}

/**
 * A live revision is restorable only from the item's current life (after its
 * last deletion), when it is not already the head, and when this browser can
 * authenticate it. A deleted item is never revived from here.
 */
function restoreBlockOf(row: HistoryEntry, final: ItemState): RestoreBlock | null {
  if (final.tombstone) return 'deletion';
  if (row.revision! <= final.tombstone_revision) return 'before_deletion';
  if (row.revision === final.revision) return 'current';
  if (row.readability === 'no_key') return 'no_key';
  if (row.readability === 'unverified') return 'unverified';
  return null;
}
