/**
 * Item records (spec §5). The CAS / conflict / tombstone decision is the pure
 * `applyRecord` model from the protocol library; this module only loads the item
 * state it needs and persists the outcome. There is no last-writer-wins path:
 * a base-revision mismatch is preserved as a conflict branch and answered 409.
 * The append-only change log is bounded by `records_per_vault` and
 * `record_bytes_per_vault` (403 `quota_exceeded`); replay detection is an
 * indexed digest lookup, so per-write cost does not grow with item history.
 */
import {
  applyRecord,
  authorizeRecordWrite,
  cjson,
  parseJson,
  parseRecord,
  recordDigest,
  utf8Encode,
  verifyRecord,
  type ConflictBranch,
  type ItemState,
  type MembershipState,
  type SignedRecord,
} from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import type { JsonObject } from '@ak-vault/protocol';
import { appendLogHead } from './change-log-heads.js';

/** `meta` key holding `{records, bytes}` totals for the per-vault record caps. */
export const RECORD_USAGE_KEY = 'record_usage';

interface ItemRow {
  revision: number;
  tombstone: number;
  tombstone_revision: number;
  head: string;
  head_log_seq: number;
}

function loadItemState(sql: SqlStorage, vaultId: string, itemId: string): { state: ItemState; row: ItemRow | undefined } {
  const row = sql.exec<ItemRow & Record<string, number | string>>('SELECT revision, tombstone, tombstone_revision, head, head_log_seq FROM items WHERE item_id = ?', itemId).toArray()[0];
  const conflicts: ConflictBranch[] = sql
    .exec<{ conflict_id: string; digest: string; record_json: string }>(
      `SELECT c.conflict_id, r.digest, r.record_json FROM conflicts c JOIN records r ON r.log_seq = c.log_seq
       WHERE c.item_id = ? AND c.resolved_revision IS NULL ORDER BY c.log_seq`,
      itemId,
    )
    .toArray()
    .map((c) => ({ conflict_id: c.conflict_id, record_digest: c.digest, record: parseRecord(parseJson(c.record_json)) }));
  return {
    row,
    state: {
      vault_id: vaultId,
      item_id: itemId,
      revision: row?.revision ?? 0,
      tombstone: row ? row.tombstone === 1 : false,
      tombstone_revision: row?.tombstone_revision ?? 0,
      head: row?.head ?? '',
      conflicts,
      // Replays are detected by the indexed `isReplay` lookup instead of loading every digest.
      seen: [],
    },
  };
}

/** Indexed replay check on `UNIQUE (item_id, digest)`. */
function digestStored(sql: SqlStorage, itemId: string, digest: string): boolean {
  return sql.exec('SELECT 1 FROM records WHERE item_id = ? AND digest = ?', itemId, digest).toArray().length > 0;
}

interface RecordUsage {
  records: number;
  bytes: number;
}

/** Running totals in `meta`, seeded once from the records table if absent. */
function recordUsage(sql: SqlStorage): RecordUsage {
  const row = sql.exec<{ v: string }>('SELECT v FROM meta WHERE k = ?', RECORD_USAGE_KEY).toArray()[0];
  if (row) return JSON.parse(row.v) as RecordUsage;
  const seed = sql.exec<{ n: number; b: number }>('SELECT COUNT(*) AS n, COALESCE(SUM(length(CAST(record_json AS BLOB))), 0) AS b FROM records').one();
  return { records: seed.n, bytes: seed.b };
}

function insertRecord(sql: SqlStorage, record: SignedRecord, kind: 'applied' | 'conflict', revision: number | null, conflictId: string | null, digest: string): number {
  const json = cjson(record as unknown as JsonObject);
  const size = utf8Encode(json).length;
  const usage = recordUsage(sql);
  if (usage.records + 1 > LIMITS.records_per_vault || usage.bytes + size > LIMITS.record_bytes_per_vault) throw new ApiError('quota_exceeded', { status: 403 });
  const row = sql
    .exec<{ log_seq: number }>(
      // Explicit MAX + 1 keeps log_seq contiguous; clients treat a gap as rollback and removal fences rely on it.
      'INSERT INTO records (log_seq, item_id, kind, revision, conflict_id, digest, record_json) VALUES ((SELECT COALESCE(MAX(log_seq), 0) + 1 FROM records), ?, ?, ?, ?, ?, ?) RETURNING log_seq',
      record.item_id,
      kind,
      revision,
      conflictId,
      digest,
      json,
    )
    .one();
  appendLogHead(sql, row.log_seq, conflictId, digest);
  const next: RecordUsage = { records: usage.records + 1, bytes: usage.bytes + size };
  sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v', RECORD_USAGE_KEY, JSON.stringify(next));
  return row.log_seq;
}

/** `PUT /items/:iid` with a signed record. Caller holds the transaction. */
export function putRecord(sql: SqlStorage, state: MembershipState, did: string, itemId: string, body: unknown): ApiResult {
  const record = verifyRecord(body, state);
  if (record.item_id !== itemId) throw new ApiError('bad_request', { message: 'record item_id does not match the path' });
  if (record.author !== did) throw new ApiError('forbidden', { message: 'record author is not the authenticated device' });
  authorizeRecordWrite(state, record);
  if (cjson(record.env as unknown as JsonObject).length > LIMITS.envelope_max_bytes) throw new ApiError('quota_exceeded');

  const { state: itemState, row } = loadItemState(sql, state.vault_id, itemId);
  const { state: next, outcome } = applyRecord(itemState, record, { isReplay: (d) => digestStored(sql, itemId, d) });
  const digest = recordDigest(record);

  if (outcome.status === 'conflict') {
    const open = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM conflicts WHERE resolved_revision IS NULL').one().n;
    if (open >= LIMITS.open_conflicts_per_vault) throw new ApiError('quota_exceeded', { status: 403 });
    const logSeq = insertRecord(sql, record, 'conflict', null, outcome.conflict_id, digest);
    sql.exec('INSERT INTO conflicts (conflict_id, item_id, log_seq, resolved_revision) VALUES (?, ?, ?, NULL)', outcome.conflict_id, itemId, logSeq);
    return {
      status: 409,
      code: 'conflict',
      body: { error: { code: 'conflict', message: 'base revision mismatch; record preserved as a conflict branch', conflict_id: outcome.conflict_id, current_revision: next.revision, log_seq: logSeq } },
    };
  }

  if (!row) {
    const count = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM items').one().n;
    if (count >= LIMITS.items_per_vault) throw new ApiError('quota_exceeded', { status: 403 });
  }
  const logSeq = insertRecord(sql, record, 'applied', outcome.revision, null, digest);
  sql.exec(
    `INSERT INTO items (item_id, revision, tombstone, tombstone_revision, head, head_log_seq) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (item_id) DO UPDATE SET revision = excluded.revision, tombstone = excluded.tombstone,
       tombstone_revision = excluded.tombstone_revision, head = excluded.head, head_log_seq = excluded.head_log_seq`,
    itemId,
    next.revision,
    next.tombstone ? 1 : 0,
    next.tombstone_revision,
    next.head,
    logSeq,
  );
  for (const conflictId of record.resolves) sql.exec('UPDATE conflicts SET resolved_revision = ? WHERE conflict_id = ?', outcome.revision, conflictId);
  return okResult({ revision: outcome.revision, tombstone: next.tombstone, log_seq: logSeq }, 200);
}

/** `GET /items/:iid`: current record plus open conflict branches. */
export function getItem(sql: SqlStorage, itemId: string): ApiResult {
  const row = sql.exec<{ revision: number; tombstone: number; head_log_seq: number }>('SELECT revision, tombstone, head_log_seq FROM items WHERE item_id = ?', itemId).toArray()[0];
  if (!row) throw new ApiError('not_found');
  const record = sql.exec<{ record_json: string }>('SELECT record_json FROM records WHERE log_seq = ?', row.head_log_seq).one().record_json;
  const conflicts = sql
    .exec<{ conflict_id: string; record_json: string }>(
      'SELECT c.conflict_id, r.record_json FROM conflicts c JOIN records r ON r.log_seq = c.log_seq WHERE c.item_id = ? AND c.resolved_revision IS NULL ORDER BY c.log_seq',
      itemId,
    )
    .toArray()
    .map((c) => ({ conflict_id: c.conflict_id, record: JSON.parse(c.record_json) as unknown }));
  return okResult({ revision: row.revision, tombstone: row.tombstone === 1, record: JSON.parse(record) as unknown, conflicts });
}
