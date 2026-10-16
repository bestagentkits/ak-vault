/**
 * Change-log head chain and log replay against signed removal fences (spec §5).
 *
 * Every change-log position `n` has a head that commits to the whole prefix
 * `1..n`:
 *
 *   log_head[0] = ""
 *   log_head[n] = b64 sha256(utf8("akv1/log-head") || 0x0A ||
 *                 cjson({"conflict_id", "log_seq": n, "prev": log_head[n-1], "record": recordDigest}))
 *
 * where `conflict_id` is the preserved branch's ID, or `null` for an applied
 * record. A removal signs `{log_fence, log_head}`, the head its author computed
 * itself at the fence, so a device that first reads the log after the removal
 * detects any position at or below the fence that differs from what the remover
 * verified: a substituted, dropped, reordered or relabelled record changes the
 * head. SHA-256 only, composed like the membership and audit chains.
 */
import { sha256b64 } from './base64url.js';
import { concatBytes, utf8Encode } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import type { MembershipState } from './membership-types.js';
import { recordDigest, type SignedRecord } from './records.js';
import { verifyLoggedRecord } from './removal-fence.js';
import { asArray, asB64, asId, asInt, asObject, exactKeys } from './validate.js';

/** A verified position in the change log: `log_seq` and the head at it. */
export interface ChangeLogCursor {
  log_seq: number;
  log_head: string;
}

/** The empty log: position 0, head `""`. */
export const LOG_START: Readonly<ChangeLogCursor> = Object.freeze({ log_seq: 0, log_head: '' });

/** Upper bound on entries per {@link verifyChangeLog} call (callers verify page by page). */
export const MAX_CHANGE_LOG_ENTRIES = 100_000;

/**
 * The head at `logSeq` given the head at `logSeq - 1` (`prev`), the entry's
 * `conflict_id` (`null` for an applied record) and its `recordDigest`.
 */
export function nextLogHead(prev: string, logSeq: number, conflictId: string | null, digest: string): string {
  return sha256b64(concatBytes(utf8Encode('akv1/log-head\n'), cjsonBytes({ conflict_id: conflictId, log_seq: logSeq, prev, record: digest })));
}

/**
 * Validate a `{log_fence, log_head}` pair: `log_head` is `""` exactly when the
 * fence is 0, else b64 of 32 bytes (bad_request).
 */
export function parseLogPosition(logSeq: unknown, logHead: unknown, seqName: string, headName: string): ChangeLogCursor {
  const seq = asInt(logSeq, seqName);
  if (seq === 0) {
    if (logHead !== '') fail('bad_request', `${headName} must be "" at position 0`);
    return { log_seq: 0, log_head: '' };
  }
  return { log_seq: seq, log_head: asB64(logHead, headName, 32) };
}

export interface VerifyChangeLogOptions {
  /**
   * Cursor the entries continue from (default {@link LOG_START}). It MUST be a
   * cursor this client computed itself, from position 1, never a value the
   * server supplied.
   */
  from?: ChangeLogCursor;
  /**
   * The entries reach the server's current head (the last page). Then a removal
   * whose fence lies beyond the last entry means the log is behind the signed
   * fence (rollback).
   */
  complete?: boolean;
  /**
   * Heads this client computed earlier, by position. Every removal whose fence lies
   * below `from` (other than at 0) MUST be covered: a missing head is bad_request,
   * a different one rollback. Keep the head of every verified position, or verify
   * again from {@link LOG_START}. A kept head at a position this call covers (`from`
   * or an entry) MUST equal the head computed there, and with `complete` no kept
   * head may lie beyond the last position (rollback): a log restored below a
   * position the client holds, then regrown past it, is refused here, which
   * `checkRollback` on checkpoints alone does not do. Pass at least the head at
   * the highest witnessed checkpoint's `log_seq`.
   */
  keptHeads?: ReadonlyMap<number, string>;
}

export interface VerifiedChangeLog {
  /** Cursor after the last entry (the `from` cursor when there are none). */
  head: ChangeLogCursor;
  /** The verified records, in log order. */
  records: SignedRecord[];
}

/**
 * Verify change-log entries `{log_seq, conflict_id, record}` that continue from
 * `opts.from`, against verified membership. Order: `from` is a valid position
 * (bad_request); `entries` is an array; every removal whose fence is at `from`
 * matches `from.log_head` (rollback); a kept head at `from` equals
 * `from.log_head` (rollback); every removal whose fence lies in
 * `1..from.log_seq - 1` has a kept head (bad_request) equal to its signed head
 * (rollback); then for each entry: exact keys,
 * `log_seq` integer, `conflict_id` null or an ID (bad_request); `log_seq` is the
 * previous position + 1 (rollback: gap, repeat or reorder);
 * `verifyLoggedRecord(record, state, log_seq)`; the head advances. Every removal
 * whose `log_fence` is a position covered (the `from` position or an entry's)
 * MUST have signed exactly the head computed there (rollback), and every kept
 * head at a covered position MUST equal it (rollback). With `opts.complete`, a
 * removal fence or a kept head beyond the last position is rollback.
 */
export function verifyChangeLog(entries: readonly unknown[], state: MembershipState, opts: VerifyChangeLogOptions = {}): VerifiedChangeLog {
  const from = opts.from ?? LOG_START;
  let head = parseLogPosition(from.log_seq, from.log_head, 'from.log_seq', 'from.log_head');
  const list = asArray(entries, 'entries', MAX_CHANGE_LOG_ENTRIES);
  const checkFences = (at: ChangeLogCursor) => {
    for (const removal of state.removals) {
      if (removal.log_fence === at.log_seq && removal.log_head !== at.log_head) {
        fail('rollback', 'change log differs from the log a removal fence signed');
      }
    }
    const kept = opts.keptHeads?.get(at.log_seq);
    if (kept !== undefined && kept !== at.log_head) fail('rollback', 'change log differs from a head this client kept');
  };
  checkFences(head);
  for (const removal of state.removals) {
    if (removal.log_fence === 0 || removal.log_fence >= head.log_seq) continue;
    const kept = opts.keptHeads?.get(removal.log_fence);
    if (kept === undefined) fail('bad_request', 'a removal fence lies below from; pass the head kept at that position');
    if (kept !== removal.log_head) fail('rollback', 'change log differs from the log a removal fence signed');
  }
  const records: SignedRecord[] = [];
  list.forEach((value, i) => {
    const what = `entries[${i}]`;
    const entry = asObject(value, what);
    exactKeys(entry, ['log_seq', 'conflict_id', 'record'], what);
    const logSeq = asInt(entry['log_seq'], `${what}.log_seq`, 1);
    const conflictId = entry['conflict_id'] === null ? null : asId(entry['conflict_id'], `${what}.conflict_id`);
    if (logSeq !== head.log_seq + 1) fail('rollback', 'change log is not contiguous');
    const record = verifyLoggedRecord(entry['record'], state, logSeq);
    head = { log_seq: logSeq, log_head: nextLogHead(head.log_head, logSeq, conflictId, recordDigest(record)) };
    checkFences(head);
    records.push(record);
  });
  if (opts.complete && state.removals.some((r) => r.log_fence > head.log_seq)) {
    fail('rollback', 'change log is behind a signed removal fence');
  }
  if (opts.complete && opts.keptHeads) {
    for (const logSeq of opts.keptHeads.keys()) if (logSeq > head.log_seq) fail('rollback', 'change log is behind a head this client kept');
  }
  return { head, records };
}
