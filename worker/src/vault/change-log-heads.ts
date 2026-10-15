/**
 * Change-log heads (spec §5): `log_heads.head` at position n is `nextLogHead` of
 * the head at n - 1 and the record at n. A removal's signed `log_head` must equal
 * the stored head at its fence. Clients never trust these values: they recompute
 * the chain and compare it with the signed fences; the server publishes heads
 * only so a client can spot a divergence early.
 */
import { nextLogHead } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';

/** The head at `logSeq` (`""` at 0). A missing head is an inconsistent store: fail closed. */
export function logHeadAt(sql: SqlStorage, logSeq: number): string {
  if (logSeq === 0) return '';
  const row = sql.exec<{ head: string }>('SELECT head FROM log_heads WHERE log_seq = ?', logSeq).toArray()[0];
  if (!row) throw new ApiError('internal');
  return row.head;
}

/** Store the head of a record just inserted at `logSeq`. Caller holds the write transaction. */
export function appendLogHead(sql: SqlStorage, logSeq: number, conflictId: string | null, digest: string): string {
  const head = nextLogHead(logHeadAt(sql, logSeq - 1), logSeq, conflictId, digest);
  sql.exec('INSERT INTO log_heads (log_seq, head) VALUES (?, ?)', logSeq, head);
  return head;
}

/**
 * Compute heads missing for records stored before heads existed, so a staging
 * vault without removals keeps working instead of failing every feed read.
 * Positions are contiguous, so the missing heads are a suffix; this runs once
 * per vault, in log order, carrying the previous head in memory, and is a
 * single indexed lookup when the heads are complete.
 */
export function backfillLogHeads(sql: SqlStorage): void {
  const last = sql.exec<{ n: number | null }>('SELECT MAX(log_seq) AS n FROM log_heads').one().n ?? 0;
  let prev = logHeadAt(sql, last);
  // Read the pending rows first: inserts must not interleave with an open cursor.
  const pending = sql
    .exec<{ log_seq: number; conflict_id: string | null; digest: string }>('SELECT log_seq, conflict_id, digest FROM records WHERE log_seq > ? ORDER BY log_seq', last)
    .toArray();
  for (const r of pending) {
    prev = nextLogHead(prev, r.log_seq, r.conflict_id, r.digest);
    sql.exec('INSERT INTO log_heads (log_seq, head) VALUES (?, ?)', r.log_seq, prev);
  }
}
