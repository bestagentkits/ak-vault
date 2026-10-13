/**
 * Pure per-item CAS / conflict / tombstone semantic model (spec §5), shared by
 * the Worker and clients. No I/O; callers persist the returned state.
 *
 * Rules, in order, for an already-verified and authorized record:
 * 1. Record already seen for this item (applied or preserved) -> throw `conflict` (replay; not preserved).
 * 2. `base_revision` < highest tombstone revision -> throw `tombstoned` (not preserved).
 * 3. `base_revision` != current revision -> outcome `conflict`: preserved as a branch with `conflict_id`.
 * 4. Tombstone of a missing or already deleted item, or `resolves` naming an unknown branch -> throw `bad_request`.
 * 5. Otherwise applied: revision = base_revision + 1, resolved branches removed.
 */
import { b64encode, sha256b64 } from './base64url.js';
import { randomBytes } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import { recordDigest, type SignedRecord } from './records.js';
import { asId } from './validate.js';

export interface ConflictBranch {
  conflict_id: string;
  record_digest: string;
  record: SignedRecord;
}

export interface ItemState {
  vault_id: string;
  item_id: string;
  /** Current revision; 0 for an item that was never written. */
  revision: number;
  tombstone: boolean;
  /** Highest revision at which the item was tombstoned (0 if never). */
  tombstone_revision: number;
  /** recordDigest of the record at `revision` ('' if none). */
  head: string;
  conflicts: ConflictBranch[];
  /** Digests of every record applied or preserved for this item (replay detection). */
  seen: string[];
}

export type ApplyOutcome = { status: 'applied'; revision: number } | { status: 'conflict'; conflict_id: string };

export function emptyItemState(vaultId: string, itemId: string): ItemState {
  return { vault_id: vaultId, item_id: itemId, revision: 0, tombstone: false, tombstone_revision: 0, head: '', conflicts: [], seen: [] };
}

export interface ApplyRecordOptions {
  /** Conflict branch ID to assign on CAS mismatch (b64 16 bytes). Random when omitted. */
  conflictId?: string;
  /**
   * Extra replay check for stores that do not load `seen` into memory (e.g. an
   * indexed lookup). Consulted in addition to `state.seen`; return true if the
   * record digest was already applied or preserved for this item.
   */
  isReplay?: (digest: string) => boolean;
}

export function applyRecord(
  state: ItemState | undefined,
  record: SignedRecord,
  opts: ApplyRecordOptions = {},
): { state: ItemState; outcome: ApplyOutcome } {
  const current = state ?? emptyItemState(record.vault_id, record.item_id);
  if (current.vault_id !== record.vault_id || current.item_id !== record.item_id) fail('bad_request', 'record does not belong to this item');
  const digest = recordDigest(record);
  if (current.seen.includes(digest) || opts.isReplay?.(digest)) fail('conflict', 'replayed record');
  if (record.base_revision < current.tombstone_revision) fail('tombstoned', 'item was deleted at a later revision');

  if (record.base_revision !== current.revision) {
    const conflictId = asId(opts.conflictId ?? b64encode(randomBytes(16)), 'conflict_id');
    if (current.conflicts.some((c) => c.conflict_id === conflictId)) fail('bad_request', 'duplicate conflict_id');
    return {
      state: {
        ...current,
        conflicts: [...current.conflicts, { conflict_id: conflictId, record_digest: digest, record }],
        seen: [...current.seen, digest],
      },
      outcome: { status: 'conflict', conflict_id: conflictId },
    };
  }

  if (record.tombstone && (current.revision === 0 || current.tombstone)) fail('bad_request', 'cannot delete a missing or deleted item');
  const known = new Set(current.conflicts.map((c) => c.conflict_id));
  for (const id of record.resolves) if (!known.has(id)) fail('bad_request', 'resolves names an unknown conflict branch');
  const revision = record.base_revision + 1;
  return {
    state: {
      ...current,
      revision,
      tombstone: record.tombstone,
      tombstone_revision: record.tombstone ? revision : current.tombstone_revision,
      head: digest,
      conflicts: current.conflicts.filter((c) => !record.resolves.includes(c.conflict_id)),
      seen: [...current.seen, digest],
    },
    outcome: { status: 'applied', revision },
  };
}

/**
 * `state_digest` = b64 sha256(cjson(sorted [[item_id, revision, head]...])),
 * sorted by item_id byte order. Items with revision 0 are excluded.
 */
export function computeStateDigest(items: Iterable<Pick<ItemState, 'item_id' | 'revision' | 'head'>>): string {
  const rows = [...items]
    .filter((i) => i.revision > 0)
    .map((i) => [i.item_id, i.revision, i.head] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (let i = 1; i < rows.length; i++) if (rows[i]![0] === rows[i - 1]![0]) fail('bad_request', 'duplicate item in state');
  return sha256b64(cjsonBytes(rows));
}
