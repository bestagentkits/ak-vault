/**
 * Per-item revision history, projected from the change log this device already
 * verified (signatures, contiguity, removal fences, kept heads). An entry is
 * metadata only: revision, author, time, key epoch, tombstone, conflict status
 * and whether this browser can open the ciphertext. The decrypted payload of an
 * entry is dropped inside `canOpen`; it is never returned, so no screen can show
 * or copy a value from the history.
 *
 * Nothing here trusts the server's ordering: positions come from the verified
 * replay, a revision is `base_revision + 1` of an applied record, and the current
 * head is the one whose digest the replay computed.
 */
import { recordDigest, type ItemPayload, type ItemState, type MembershipState, type SignedRecord, type TombstonePayload } from '@ak-vault/protocol';

/** One verified change-log entry of an item: its position, branch label and record. */
export interface LoggedRecord {
  logSeq: number;
  /** The preserved branch's ID; null for an applied record. */
  conflictId: string | null;
  record: SignedRecord;
}

/** Entries shown per item; older ones stay in the signed log but are not listed here. */
export const HISTORY_LIMIT = 200;

export type AuthorStanding = 'this_browser' | 'current_device' | 'removed_device' | 'unknown_device';

export interface HistoryEntry {
  logSeq: number;
  kind: 'revision' | 'conflict';
  /** The revision an applied record produced; null for a preserved branch. */
  revision: number | null;
  baseRevision: number;
  conflictId: string | null;
  /** A short, non-secret prefix of the author's device ID. */
  author: string;
  authorStanding: AuthorStanding;
  ts: number;
  keyEpoch: number;
  tombstone: boolean;
  /** How many branches this record resolved. */
  resolves: number;
  /** `current`/`superseded` for a revision, `open`/`resolved` for a branch. */
  status: 'current' | 'superseded' | 'open' | 'resolved';
  /** The revision whose record resolved this branch, when it is resolved. */
  resolvedAtRevision: number | null;
  /** `unavailable`: the key epoch was never given to this browser, or the ciphertext does not open. */
  content: 'readable' | 'unavailable' | 'none';
  /** A live, readable, non-current revision of a live item. */
  restorable: boolean;
  /** An open, readable, non-tombstone branch. */
  adoptable: boolean;
}

export interface ItemHistory {
  itemId: string;
  name: string;
  revision: number;
  entries: HistoryEntry[];
  /** Entries older than {@link HISTORY_LIMIT} that are not listed. */
  omitted: number;
  openConflicts: number;
}

export type OpenFn = (record: SignedRecord, vk: Uint8Array | undefined) => ItemPayload | TombstonePayload | null;

/** True when this browser can open the record's ciphertext as an item value; the payload is dropped here. */
function canOpen(record: SignedRecord, vaultKeys: ReadonlyMap<number, Uint8Array>, open: OpenFn): boolean {
  const payload = open(record, vaultKeys.get(record.key_epoch));
  return payload !== null && !('deleted' in payload);
}

function standing(author: string, state: MembershipState, selfDeviceId: string): AuthorStanding {
  if (author === selfDeviceId && state.devices.some((d) => d.device_id === author)) return 'this_browser';
  if (state.devices.some((d) => d.device_id === author)) return 'current_device';
  if (state.removals.some((r) => r.device_id === author)) return 'removed_device';
  return 'unknown_device';
}

export interface HistoryInput {
  itemId: string;
  name: string;
  itemState: ItemState;
  log: readonly LoggedRecord[];
  state: MembershipState;
  vaultKeys: ReadonlyMap<number, Uint8Array>;
  selfDeviceId: string;
  open: OpenFn;
  limit?: number;
}

export function buildItemHistory(input: HistoryInput): ItemHistory {
  const { itemState, state, vaultKeys, log } = input;
  const live = itemState.revision > 0 && !itemState.tombstone;
  const openIds = new Set(itemState.conflicts.map((c) => c.conflict_id));
  // Where each branch was resolved: the first applied record after it that lists it.
  const resolvedAt = new Map<string, number>();
  for (const e of log) {
    if (e.conflictId !== null) continue;
    for (const id of e.record.resolves) if (!resolvedAt.has(id)) resolvedAt.set(id, e.record.base_revision + 1);
  }
  const limit = input.limit ?? HISTORY_LIMIT;
  const recent = log.length > limit ? log.slice(log.length - limit) : log;
  const entries: HistoryEntry[] = [];
  for (let i = recent.length - 1; i >= 0; i--) {
    const { logSeq, conflictId, record } = recent[i]!;
    const applied = conflictId === null;
    const isCurrent = applied && recordDigest(record) === itemState.head && record.base_revision + 1 === itemState.revision;
    const content = record.tombstone ? 'none' : canOpen(record, vaultKeys, input.open) ? 'readable' : 'unavailable';
    const open = !applied && openIds.has(conflictId);
    entries.push({
      logSeq,
      kind: applied ? 'revision' : 'conflict',
      revision: applied ? record.base_revision + 1 : null,
      baseRevision: record.base_revision,
      conflictId,
      author: record.author.slice(0, 8),
      authorStanding: standing(record.author, state, input.selfDeviceId),
      ts: record.ts,
      keyEpoch: record.key_epoch,
      tombstone: record.tombstone,
      resolves: record.resolves.length,
      status: applied ? (isCurrent ? 'current' : 'superseded') : open ? 'open' : 'resolved',
      resolvedAtRevision: !applied && !open ? (resolvedAt.get(conflictId) ?? null) : null,
      content,
      restorable: live && applied && !isCurrent && !record.tombstone && content === 'readable',
      adoptable: live && open && !record.tombstone && content === 'readable',
    });
  }
  return { itemId: input.itemId, name: input.name, revision: itemState.revision, entries, omitted: log.length - recent.length, openConflicts: openIds.size };
}
