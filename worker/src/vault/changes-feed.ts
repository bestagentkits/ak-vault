/**
 * `GET /changes?cursor=&limit=`: the append-only change log, ordered by `log_seq`.
 * Each entry is an applied record or a preserved conflict branch (with the
 * revision that resolved it, if any) and the change-log head at its position.
 * The response also carries the current heads a client needs for its checkpoint
 * and for a removal fence (`log_seq`, `log_head`).
 */
import type { MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { logHeadAt } from './change-log-heads.js';
import { queryInt } from './request-body.js';
import type { VaultRequest } from './vault-request.js';

interface ChangeRow {
  log_seq: number;
  kind: string;
  item_id: string;
  revision: number | null;
  conflict_id: string | null;
  resolved_revision: number | null;
  record_json: string;
  log_head: string | null;
}

export function currentLogSeq(sql: SqlStorage): number {
  return sql.exec<{ n: number | null }>('SELECT MAX(log_seq) AS n FROM records').one().n ?? 0;
}

export function getChanges(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  const cursor = queryInt(req.query, 'cursor', 0);
  const limit = Math.max(1, queryInt(req.query, 'limit', LIMITS.changes_page_default, LIMITS.changes_page_max));
  const rows = sql
    .exec<ChangeRow & Record<string, string | number | null>>(
      `SELECT r.log_seq, r.kind, r.item_id, r.revision, r.conflict_id, c.resolved_revision, r.record_json, h.head AS log_head
       FROM records r LEFT JOIN conflicts c ON r.kind = 'conflict' AND c.log_seq = r.log_seq
       LEFT JOIN log_heads h ON h.log_seq = r.log_seq
       WHERE r.log_seq > ? ORDER BY r.log_seq LIMIT ?`,
      cursor,
      limit + 1,
    )
    .toArray();
  const page = rows.slice(0, limit);
  // Every stored record has a head (written with it, or backfilled on start); a missing one fails closed.
  if (page.some((r) => r.log_head === null)) throw new ApiError('internal');
  const changes = page.map((r) => ({
    log_seq: r.log_seq,
    kind: r.kind,
    item_id: r.item_id,
    revision: r.revision,
    conflict_id: r.conflict_id,
    resolved_revision: r.resolved_revision,
    record: JSON.parse(r.record_json) as unknown,
    log_head: r.log_head,
  }));
  const head = currentLogSeq(sql);
  return okResult({
    changes,
    next_cursor: page.length > 0 ? page[page.length - 1]!.log_seq : cursor,
    has_more: rows.length > limit,
    head: {
      log_seq: head,
      log_head: logHeadAt(sql, head),
      membership_seq: state.seq,
      membership_head: state.head,
      key_epoch: state.key_epoch,
      rekey_required: state.rekey_required,
    },
  });
}
