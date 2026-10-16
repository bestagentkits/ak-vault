/**
 * removal-fence.json: change-log records by removed authors against each removal's signed
 * log_fence, and change-log replay against each removal's signed log_head.
 */
import { b64encode, verifyChangeLog, verifyLoggedRecord, verifyMembershipChain, type ChangeLogCursor, type MembershipEvent, type SignedRecord } from '../../src/index.js';
import { CHANGE_LOGS, cursorAt, LOG_HEADS, vectorRecord, type ChainName, type LogEntry } from './change-log.js';
import { aliceLaptop, aliceNewPhone, alicePhone, bobLaptop, carolPhone, flipByte, id, negative, seed, stranger } from './fixtures.js';
import { personalChain, sharedChain } from './membership.js';

const CHAINS: Record<ChainName, MembershipEvent[]> = { shared: sharedChain, personal: personalChain };

export function removalFenceVectors(): Record<string, unknown> {
  const states = { shared: verifyMembershipChain(sharedChain), personal: verifyMembershipChain(personalChain) };
  const ok = (name: string, chain: ChainName, rec: SignedRecord, logSeq: number) => {
    verifyLoggedRecord(rec, states[chain], logSeq);
    return { name, chain, record: rec, log_seq: logSeq };
  };
  const bad = (name: string, code: string, chain: ChainName, rec: unknown, logSeq: number) =>
    negative(name, code, { chain, record: rec, log_seq: logSeq }, () => verifyLoggedRecord(rec, states[chain], logSeq));

  // Shared chain: aliceLaptop removed at seq 5 (key epoch 1, log_fence 4); carolPhone removed
  // with acct_carol at seq 7 (key epoch 2, log_fence 7). Personal chain: alicePhone removed at
  // seq 2 (key epoch 1, log_fence 5) and re-added at seq 4 (key epoch 2).
  const record = (label: string, chain: ChainName, author: typeof alicePhone, keyEpoch: number) => vectorRecord(chain, { label, author, keyEpoch });
  const laptopE1 = record('laptop-e1', 'shared', aliceLaptop, 1);
  const carolE2 = record('carol-e2', 'shared', carolPhone, 2);
  const phoneE1 = record('phone-e1', 'personal', alicePhone, 1);

  // Change-log replay. `slice(chain, a, b)` = entries at positions a..b of the honest log.
  const slice = (chain: ChainName, a: number, b: number): LogEntry[] => CHANGE_LOGS[chain].slice(a - 1, b);
  const replace = (entries: LogEntry[], logSeq: number, change: Partial<LogEntry>): LogEntry[] => entries.map((e) => (e.log_seq === logSeq ? { ...e, ...change } : e));
  // kept_heads: heads the client computed earlier, keyed by decimal position.
  type Kept = Record<string, string>;
  const keptMap = (kept: Kept) => new Map(Object.entries(kept).map(([k, h]) => [Number(k), h]));
  const logOk = (name: string, chain: ChainName, from: ChangeLogCursor, entries: LogEntry[], complete: boolean, kept: Kept = {}) => {
    const { head } = verifyChangeLog(entries, states[chain], { from, complete, keptHeads: keptMap(kept) });
    return { name, chain, from, kept_heads: kept, entries, complete, head };
  };
  const logBad = (name: string, code: string, chain: ChainName, from: unknown, entries: unknown[], complete: boolean, kept: Kept = {}) =>
    negative(name, code, { chain, from, kept_heads: kept, entries, complete }, () =>
      verifyChangeLog(entries, states[chain], { from: from as ChangeLogCursor, complete, keptHeads: keptMap(kept) }),
    );
  const keptAt = (chain: ChainName, ...positions: number[]): Kept => Object.fromEntries(positions.map((p) => [String(p), LOG_HEADS[chain][p]!]));
  const start = cursorAt('shared', 0);
  const full = slice('shared', 1, 8);
  // Records the removed devices sign after their removal, which a colluding server places at or below the fence.
  const laptopLate = { log_seq: 0, conflict_id: null, record: vectorRecord('shared', { label: 'log/shared/laptop-late', author: aliceLaptop, keyEpoch: 1, item: 'log/b' }) };
  const phoneLate = { log_seq: 0, conflict_id: null, record: vectorRecord('personal', { label: 'log/personal/phone-late', author: alicePhone, keyEpoch: 1, item: 'log/p1' }) };
  // The conflict branch at position 3 dropped and the later entries renumbered so the log stays gap-free.
  const dropped = [...slice('shared', 1, 2), ...slice('shared', 4, 8).map((e) => ({ ...e, log_seq: e.log_seq - 1 }))];
  // A server restore to position 7, above every fence, then regrown past the client's witnessed
  // position 8 by validly signed records of current members: item log/d at revision 1 differs and a
  // new item follows. The regrown log verifies on its own; only the head the client kept at 8 refuses it.
  const regrown = [
    ...slice('shared', 1, 7),
    { log_seq: 8, conflict_id: null, record: vectorRecord('shared', { label: 'log/shared/regrown-8', author: bobLaptop, keyEpoch: 3, item: 'log/d' }) },
    { log_seq: 9, conflict_id: null, record: vectorRecord('shared', { label: 'log/shared/regrown-9', author: bobLaptop, keyEpoch: 3, item: 'log/e' }) },
  ];

  return {
    version: 1,
    description:
      'Removal fence (spec §5, §6). chains: membership.json chains (shared = chains[0], personal = chains[1]); state = verifyMembershipChain(chain); state.removals lists each removal with the removed sign_pub, the key_epoch current at removal and the signed log_fence and log_head of the removing event. ' +
      'verifyLoggedRecord(record, state, log_seq): record parses; same vault; log_seq >= 1 (bad_request); the author is a current device, or a removed device whose record key_epoch is not newer than the key_epoch of its last removal (forbidden); the signature verifies under that device key (invalid_signature); for every removal of the author with removal.key_epoch >= record.key_epoch, log_seq > removal.log_fence is forbidden. cases MUST pass; invalid MUST fail with expect_error. ' +
      'change_logs: the honest change log of each chain, entries {log_seq, conflict_id (null = applied record), record}; heads[n] is the log head at position n: heads[0] = "", heads[n] = b64 sha256(utf8("akv1/log-head\\n") || cjson({"conflict_id", "log_seq": n, "prev": heads[n-1], "record": b64 sha256(record signing input)})). ' +
      'verifyChangeLog(entries, state, {from, complete}): from is a valid position (log_head "" exactly at 0, else 32 bytes; bad_request); per entry: exact keys {log_seq, conflict_id, record}, conflict_id null or an ID (bad_request); log_seq = previous + 1 (rollback); verifyLoggedRecord; the head advances; every removal whose log_fence equals the from position or an entry position MUST carry the head computed there (rollback); every removal whose log_fence lies in 1..from.log_seq-1 needs a head in kept_heads (keyed by decimal position; missing: bad_request) equal to its log_head (rollback); a kept head at the from position MUST equal from.log_head (rollback), checked right after the fence at from and before the kept heads of fences below from; a kept head at an entry position MUST equal the head computed there (rollback), checked after the fence at that position; with complete, a removal log_fence beyond the last position is rollback, then a kept head beyond the last position is rollback. A client passes at least the head it kept at its highest witnessed checkpoint, so a log restored below that position and regrown past it is refused (restored_regrown_*): checkRollback on checkpoints alone accepts it. log_cases MUST pass and yield head; log_invalid MUST fail with expect_error.',
    chains: CHAINS,
    removals: { shared: states.shared.removals, personal: states.personal.removals },
    cases: [
      ok('removed_author_before_fence', 'shared', laptopE1, 3),
      ok('removed_author_at_fence', 'shared', laptopE1, 4),
      ok('removed_member_at_fence', 'shared', carolE2, 7),
      ok('current_author_unaffected', 'shared', record('bob-e3', 'shared', bobLaptop, 3), 100),
      ok('current_author_old_epoch_record', 'shared', record('bob-e1', 'shared', bobLaptop, 1), 100),
      ok('readded_device_writes_at_newer_epoch', 'personal', record('phone-e2', 'personal', alicePhone, 2), 20),
      ok('readded_device_old_record_before_fence', 'personal', phoneE1, 5),
      ok('recovered_device_unaffected', 'personal', record('newphone-e1', 'personal', aliceNewPhone, 1), 9),
    ],
    invalid: [
      bad('removed_author_after_fence', 'forbidden', 'shared', laptopE1, 5),
      bad('removed_member_after_fence', 'forbidden', 'shared', carolE2, 8),
      bad('removed_member_older_epoch_after_fence', 'forbidden', 'shared', record('carol-e1', 'shared', carolPhone, 1), 8),
      bad('removed_author_newer_key_epoch', 'forbidden', 'shared', record('laptop-e2', 'shared', aliceLaptop, 2), 1),
      bad('readded_device_old_epoch_after_fence', 'forbidden', 'personal', phoneE1, 6),
      bad('never_a_member', 'forbidden', 'shared', record('stranger', 'shared', stranger, 1), 1),
      bad('bad_record_signature', 'invalid_signature', 'shared', { ...laptopE1, sig: flipByte(laptopE1.sig, 6) }, 3),
      bad('record_from_other_vault', 'bad_request', 'shared', phoneE1, 3),
      bad('log_seq_zero', 'bad_request', 'shared', laptopE1, 0),
    ],
    change_logs: {
      shared: { entries: CHANGE_LOGS.shared, heads: LOG_HEADS.shared },
      personal: { entries: CHANGE_LOGS.personal, heads: LOG_HEADS.personal },
    },
    log_cases: [
      logOk('shared_full_log', 'shared', start, full, true),
      logOk('shared_resume_below_fence', 'shared', cursorAt('shared', 2), slice('shared', 3, 8), true),
      logOk('shared_resume_at_fence', 'shared', cursorAt('shared', 4), slice('shared', 5, 8), true),
      logOk('shared_first_page', 'shared', start, slice('shared', 1, 2), false),
      logOk('shared_resume_past_fence_with_kept_head', 'shared', cursorAt('shared', 6), slice('shared', 7, 8), true, keptAt('shared', 4)),
      logOk('shared_no_entries_at_cursor', 'shared', cursorAt('shared', 8), [], true, keptAt('shared', 4, 7)),
      logOk('personal_full_log', 'personal', cursorAt('personal', 0), slice('personal', 1, 7), true),
      logOk('shared_reread_with_every_kept_head', 'shared', start, full, true, keptAt('shared', 0, 1, 2, 3, 4, 5, 6, 7, 8)),
      logOk('restored_regrown_log_without_kept_head', 'shared', start, regrown, true, keptAt('shared', 4, 7)),
      logOk('page_below_kept_head', 'shared', start, slice('shared', 1, 7), false, keptAt('shared', 8)),
    ],
    log_invalid: [
      logBad('removed_device_record_substituted_below_fence', 'rollback', 'shared', start, replace(full, 2, { record: laptopLate.record }), true),
      logBad('removed_device_record_substituted_at_fence', 'rollback', 'shared', start, replace(full, 4, { record: laptopLate.record, conflict_id: null }), true),
      logBad('removed_member_record_substituted_at_second_fence', 'rollback', 'shared', cursorAt('shared', 4), replace(slice('shared', 5, 8), 7, { record: vectorRecord('shared', { label: 'log/shared/carol-late', author: carolPhone, keyEpoch: 2, item: 'log/c', base: 1 }) }), true),
      logBad('conflict_branch_dropped_and_renumbered', 'rollback', 'shared', start, dropped, false),
      logBad('conflict_branch_relabelled', 'rollback', 'shared', start, replace(full, 3, { conflict_id: id('fence/conflict/other') }), true),
      logBad('applied_record_marked_as_conflict', 'rollback', 'shared', start, replace(full, 1, { conflict_id: id('fence/conflict/other') }), true),
      logBad('records_reordered', 'rollback', 'shared', start, [...slice('shared', 1, 1), { ...full[2]!, log_seq: 2 }, { ...full[1]!, log_seq: 3 }, ...slice('shared', 4, 8)], true),
      logBad('personal_record_substituted_below_fence', 'rollback', 'personal', cursorAt('personal', 0), replace(slice('personal', 1, 7), 1, { record: phoneLate.record }), true),
      logBad('resume_cursor_head_differs_at_fence', 'rollback', 'shared', { log_seq: 4, log_head: b64encode(seed('log/bogus-head')) }, slice('shared', 5, 8), true),
      logBad('resume_past_fence_without_kept_head', 'bad_request', 'shared', cursorAt('shared', 6), slice('shared', 7, 8), true),
      logBad('resume_past_fence_with_forked_kept_head', 'rollback', 'shared', cursorAt('shared', 6), slice('shared', 7, 8), true, { '4': b64encode(seed('log/forked-head')) }),
      logBad('log_truncated_before_fence', 'rollback', 'shared', start, slice('shared', 1, 3), true),
      logBad('log_truncated_between_fences', 'rollback', 'shared', start, slice('shared', 1, 6), true),
      logBad('gap', 'rollback', 'shared', start, [...slice('shared', 1, 2), ...slice('shared', 4, 8)], true),
      logBad('first_entry_does_not_follow_cursor', 'rollback', 'shared', cursorAt('shared', 2), slice('shared', 4, 8), true),
      logBad('repeated_position', 'rollback', 'shared', start, [...slice('shared', 1, 2), ...slice('shared', 2, 8)], true),
      logBad('removed_author_above_fence_in_log', 'forbidden', 'shared', start, [...slice('shared', 1, 4), { ...laptopLate, log_seq: 5 }], false),
      logBad('entry_extra_key', 'bad_request', 'shared', start, [{ ...full[0]!, kind: 'applied' }], false),
      logBad('entry_malformed_conflict_id', 'bad_request', 'shared', start, replace(slice('shared', 1, 3), 3, { conflict_id: 'not-an-id' }), false),
      logBad('from_log_head_at_zero', 'bad_request', 'shared', { log_seq: 0, log_head: LOG_HEADS.shared[1]! }, full, true),
      logBad('from_empty_log_head_above_zero', 'bad_request', 'shared', { log_seq: 2, log_head: '' }, slice('shared', 3, 8), true),
      logBad('restored_regrown_past_kept_head', 'rollback', 'shared', start, regrown, true, keptAt('shared', 8)),
      logBad('restored_regrown_resumed_below_kept_head', 'rollback', 'shared', cursorAt('shared', 7), regrown.slice(7), true, keptAt('shared', 4, 7, 8)),
      logBad('restored_regrown_first_page_past_kept_head', 'rollback', 'shared', start, regrown.slice(0, 8), false, keptAt('shared', 8)),
      logBad('restored_log_behind_kept_head', 'rollback', 'shared', start, slice('shared', 1, 7), true, keptAt('shared', 8)),
      logBad('kept_head_at_from_checked_before_missing_fence_heads', 'rollback', 'shared', cursorAt('shared', 8), [], true, { '8': b64encode(seed('log/forked-head')) }),
      logBad('resume_cursor_differs_from_kept_head', 'rollback', 'shared', cursorAt('shared', 8), [], true, { '4': LOG_HEADS.shared[4]!, '7': LOG_HEADS.shared[7]!, '8': b64encode(seed('log/forked-head')) }),
    ],
  };
}
