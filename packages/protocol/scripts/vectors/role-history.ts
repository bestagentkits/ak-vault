/**
 * role-history.json: change-log records checked against the role and device kind
 * their author had at that log position (each `role_set` signs log_fence and
 * log_head), and the record key epoch bounded by the verified state.
 *
 * Shared vault `vault/roles`. Chain: genesis (alicePhone, owner); member_add acct_bob
 * editor [bobLaptop human, bobCi machine]; member_add acct_carol reader [carolPhone];
 * role_set acct_bob reader (log_fence 3); role_set acct_carol editor (log_fence 4);
 * role_set acct_bob editor (log_fence 6); role_set acct_carol reader (log_fence 7);
 * member_remove acct_carol (log_fence 8, key epoch 1); rekey to key epoch 2.
 * So bobLaptop may write at positions 1..3 and from 7 on, carolPhone at 5..7 only,
 * bobCi never.
 *
 * Chain `legacy` (same vault ID) holds `role_set` events signed without a fence,
 * as an earlier revision allowed (only before the first fenced one): genesis; the
 * same two member_adds; legacy role_set acct_bob reader; legacy role_set
 * acct_carol editor; role_set acct_bob reader (log_fence 4, a same-role
 * re-affirm); role_set acct_carol editor (log_fence 6, a re-affirm). Between two fenced changes a
 * legacy change has no position, so any role the author held there counts:
 * bobLaptop may write at 1..4 (a writer before its legacy demotion), carolPhone at
 * every position (a writer after its legacy promotion), bobCi never.
 */
import {
  LOG_START, nextLogHead, recordDigest, sealItem, signRecord, verifyChangeLog, verifyLoggedRecord, verifyMembershipChain, wrapsDigest,
  type ChangeLogCursor, type JsonObject, type SignedRecord,
} from '../../src/index.js';
import { alicePhone, b64, BASE_TS, bobCi, bobLaptop, buildChain, by, carolPhone, flipByte, id, key32, negative, nonce, recoverySignPub, seed, stranger, type ChainStep, type VectorDevice } from './fixtures.js';
import { addSet, wrapsFor } from './membership.js';

const VAULT_ROLES = id('vault/roles');
const rec = (d: VectorDevice) => ({ ...d.record }) as unknown as JsonObject;

interface RecordSpec {
  label: string;
  author: VectorDevice;
  keyEpoch: number;
  item?: string;
  base?: number;
}

/** A signed record of the roles vault, encrypted under its deterministic VK[keyEpoch]. */
function roleRecord(spec: RecordSpec): SignedRecord {
  const ctx = {
    vault_id: VAULT_ROLES,
    item_id: id(`roles/item/${spec.item ?? spec.label}`),
    base_revision: spec.base ?? 0,
    key_epoch: spec.keyEpoch,
    author: spec.author.record.device_id,
    tombstone: false,
  };
  const env = sealItem({ ...ctx, vk: key32(`vk/${VAULT_ROLES}/epoch${spec.keyEpoch}`), payload: { name: 'API_KEY', value: `roles-${spec.label}`, meta: {}, sensitivity: 'normal' }, nonce: nonce(`roles/record/${spec.label}`) });
  return signRecord({ ...ctx, ts: BASE_TS, resolves: [], env }, spec.author.signSecret);
}

interface LogEntry {
  log_seq: number;
  conflict_id: string | null;
  record: SignedRecord;
}

const entry = (logSeq: number, spec: RecordSpec): LogEntry => ({ log_seq: logSeq, conflict_id: null, record: roleRecord(spec) });

/** The honest change log: every record by a device that could write at its position. */
const LOG: LogEntry[] = [
  entry(1, { label: 'log/1', author: alicePhone, keyEpoch: 1, item: 'log/a' }),
  entry(2, { label: 'log/2', author: bobLaptop, keyEpoch: 1, item: 'log/b' }),
  entry(3, { label: 'log/3', author: bobLaptop, keyEpoch: 1, item: 'log/b', base: 1 }),
  entry(4, { label: 'log/4', author: alicePhone, keyEpoch: 1, item: 'log/c' }),
  entry(5, { label: 'log/5', author: carolPhone, keyEpoch: 1, item: 'log/d' }),
  entry(6, { label: 'log/6', author: alicePhone, keyEpoch: 1, item: 'log/e' }),
  entry(7, { label: 'log/7', author: bobLaptop, keyEpoch: 1, item: 'log/b', base: 2 }),
  entry(8, { label: 'log/8', author: alicePhone, keyEpoch: 1, item: 'log/f' }),
  entry(9, { label: 'log/9', author: bobLaptop, keyEpoch: 2, item: 'log/g' }),
];

/** The head chain of `log`: "" then the head after each entry. */
function headsOf(log: LogEntry[]): string[] {
  const heads: string[] = [LOG_START.log_head];
  for (const e of log) heads.push(nextLogHead(heads[heads.length - 1]!, e.log_seq, e.conflict_id, recordDigest(e.record)));
  return heads;
}

const HEADS = headsOf(LOG);

const fenceAt = (logSeq: number) => ({ log_fence: logSeq, log_head: HEADS[logSeq]! });
const cursorAt = (logSeq: number): ChangeLogCursor => ({ log_seq: logSeq, log_head: HEADS[logSeq]! });

/** Genesis and the two member_adds both chains start with. */
const PREFIX: ChainStep[] = [
  {
    type: 'genesis', ...by(alicePhone),
    body: { vault_kind: 'shared', owner_account: 'acct_alice', recovery_sign_pub: recoverySignPub, devices: [rec(alicePhone)], wraps_digest: wrapsDigest(addSet([alicePhone], [1], 'roles/0', VAULT_ROLES)) },
  },
  { type: 'member_add', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop), rec(bobCi)], wraps_digest: wrapsDigest(addSet([bobLaptop, bobCi], [1], 'roles/1', VAULT_ROLES)) } },
  { type: 'member_add', ...by(alicePhone), body: { account: 'acct_carol', role: 'reader', devices: [rec(carolPhone)], wraps_digest: wrapsDigest(addSet([carolPhone], [1], 'roles/2', VAULT_ROLES)) } },
];

const CHAIN = buildChain(VAULT_ROLES, [
  ...PREFIX,
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_bob', role: 'reader', ...fenceAt(3) } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_carol', role: 'editor', ...fenceAt(4) } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', ...fenceAt(6) } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_carol', role: 'reader', ...fenceAt(7) } },
  { type: 'member_remove', ...by(alicePhone), body: { account: 'acct_carol', ...fenceAt(8) } },
  { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 2, wraps_digest: wrapsDigest(wrapsFor([alicePhone, bobLaptop, bobCi], 2, 'roles/e2', VAULT_ROLES)), needs_rotate: [] } },
]);

/** The honest change log of the legacy chain. */
const LEGACY_LOG: LogEntry[] = [
  entry(1, { label: 'legacy/1', author: alicePhone, keyEpoch: 1, item: 'legacy/a' }),
  entry(2, { label: 'legacy/2', author: bobLaptop, keyEpoch: 1, item: 'legacy/b' }),
  entry(3, { label: 'legacy/3', author: bobLaptop, keyEpoch: 1, item: 'legacy/c' }),
  entry(4, { label: 'legacy/4', author: alicePhone, keyEpoch: 1, item: 'legacy/d' }),
  entry(5, { label: 'legacy/5', author: carolPhone, keyEpoch: 1, item: 'legacy/e' }),
  entry(6, { label: 'legacy/6', author: alicePhone, keyEpoch: 1, item: 'legacy/f' }),
  entry(7, { label: 'legacy/7', author: carolPhone, keyEpoch: 1, item: 'legacy/g' }),
];
const LEGACY_HEADS = headsOf(LEGACY_LOG);
const legacyFenceAt = (logSeq: number) => ({ log_fence: logSeq, log_head: LEGACY_HEADS[logSeq]! });

const LEGACY_CHAIN = buildChain(VAULT_ROLES, [
  ...PREFIX,
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_bob', role: 'reader' } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_carol', role: 'editor' } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_bob', role: 'reader', ...legacyFenceAt(4) } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_carol', role: 'editor', ...legacyFenceAt(6) } },
]);

/**
 * Chain `readded` (same vault ID): role history split at a removal. role_set
 * acct_bob reader (log_fence 3); device_remove bobLaptop (log_fence 4); rekey to
 * key epoch 2; device_add bobLaptop again as a reader; role_set acct_bob editor
 * (log_fence 6). The demotion belongs to the key-epoch-1 term only, so a
 * key-epoch-2 record of bobLaptop is a reader's until the promotion fence.
 */
const READDED_CHAIN = buildChain(VAULT_ROLES, [
  ...PREFIX,
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_bob', role: 'reader', ...fenceAt(3) } },
  { type: 'device_remove', ...by(alicePhone), body: { device_id: bobLaptop.record.device_id, reason: 'lost', ...fenceAt(4) } },
  { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 2, wraps_digest: wrapsDigest(wrapsFor([alicePhone, bobCi, carolPhone], 2, 'roles/readded/e2', VAULT_ROLES)), needs_rotate: [] } },
  {
    type: 'device_add', ...by(alicePhone),
    body: { device: { ...rec(bobLaptop), role: 'reader' }, sas: b64(seed('roles/readded/sas')), wraps_digest: wrapsDigest(addSet([bobLaptop], [2], 'roles/readded/add', VAULT_ROLES)) },
  },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', ...fenceAt(6) } },
]);

export function roleHistoryVectors(): Record<string, unknown> {
  const states = { roles: verifyMembershipChain(CHAIN), legacy: verifyMembershipChain(LEGACY_CHAIN), readded: verifyMembershipChain(READDED_CHAIN) };
  type Chain = keyof typeof states;
  const ok = (name: string, record: SignedRecord, logSeq: number, chain: Chain = 'roles') => {
    verifyLoggedRecord(record, states[chain], logSeq);
    return { name, chain, record, log_seq: logSeq };
  };
  const bad = (name: string, code: string, record: unknown, logSeq: number, chain: Chain = 'roles') =>
    negative(name, code, { chain, record, log_seq: logSeq }, () => verifyLoggedRecord(record, states[chain], logSeq));
  const record = (label: string, author: VectorDevice, keyEpoch: number) => roleRecord({ label, author, keyEpoch });
  const bobE1 = record('bob-e1', bobLaptop, 1);
  const carolE1 = record('carol-e1', carolPhone, 1);
  const ciE1 = record('ci-e1', bobCi, 1);

  type Kept = Record<string, string>;
  const keptMap = (kept: Kept) => new Map(Object.entries(kept).map(([k, h]) => [Number(k), h]));
  const keptAt = (...positions: number[]): Kept => Object.fromEntries(positions.map((p) => [String(p), HEADS[p]!]));
  const slice = (a: number, b: number) => LOG.slice(a - 1, b);
  const logOk = (name: string, from: ChangeLogCursor, entries: LogEntry[], complete: boolean, kept: Kept = {}, chain: Chain = 'roles') => {
    const { head } = verifyChangeLog(entries, states[chain], { from, complete, keptHeads: keptMap(kept) });
    return { name, chain, from, kept_heads: kept, entries, complete, head };
  };
  const logBad = (name: string, code: string, from: ChangeLogCursor, entries: unknown[], complete: boolean, kept: Kept = {}, chain: Chain = 'roles') =>
    negative(name, code, { chain, from, kept_heads: kept, entries, complete }, () => verifyChangeLog(entries, states[chain], { from, complete, keptHeads: keptMap(kept) }));
  // A record bob signs after the fenced re-affirm that bounds his legacy demotion.
  const bobAfterBound = { log_seq: 5, conflict_id: null, record: roleRecord({ label: 'legacy/bob-late', author: bobLaptop, keyEpoch: 1, item: 'legacy/c', base: 1 }) };
  const legacyCursor = (logSeq: number): ChangeLogCursor => ({ log_seq: logSeq, log_head: LEGACY_HEADS[logSeq]! });
  // Records a demoted editor signs after its demotion, which a colluding server places in the log.
  const bobLate = { log_seq: 4, conflict_id: null, record: roleRecord({ label: 'log/bob-late', author: bobLaptop, keyEpoch: 1, item: 'log/b', base: 2 }) };
  // A record bob could have written as an editor, substituted below the demotion fence.
  const bobSubstitute = { ...LOG[1]!, record: roleRecord({ label: 'log/bob-substitute', author: bobLaptop, keyEpoch: 1, item: 'log/b' }) };

  return {
    version: 1,
    description:
      'Role and device-kind history (spec §5). chains.roles, chains.legacy and chains.readded: one shared vault each (chains.readded removes, rekeys and re-adds a device); state = verifyMembershipChain(chains[case.chain]); every case names its chain. Each role_set signs log_fence and log_head like a removal; a legacy role_set signed under an earlier revision carries neither (chains.legacy) and still verifies. state.role_changes lists one row per device of the account at that role_set {device_id, changed_seq, prev_role, role, log_fence, log_head}, with log_fence and log_head null for a legacy role_set; each removal also records the device role and kind at removal. ' +
      'verifyLoggedRecord(record, state, log_seq): record parses; same vault; log_seq >= 1 (bad_request); record key_epoch above state.key_epoch is forbidden; the author term: the first removal of the author (chain order) whose key_epoch >= record.key_epoch, else the current device, else forbidden; signature (invalid_signature); removal fences as removal-fence.json (forbidden); then the term kind MUST be human and a candidate role at log_seq MUST be owner or editor (forbidden). The term changes are the role changes of that device after its previous removal (if any) and before the removal that ends the term (if any); the candidate roles at log_seq: let i be the first fenced term change (chain order) whose log_fence >= log_seq and j the last fenced term change before i; the candidates are the prev_role of every term change after j up to and including i, plus, when there is no i, the role at the term end (the removal role, or the current device role). Every candidate MUST be in the closed role set and at least one MUST be owner or editor. Without legacy changes there is exactly one candidate. cases MUST pass; invalid MUST fail with expect_error. ' +
      'change_logs.roles: entries {log_seq, conflict_id, record} and heads as removal-fence.json. verifyChangeLog treats every fenced role change like a removal fence (a legacy one binds nothing): the head computed at its log_fence MUST equal its log_head (rollback); a fence below from needs a kept head (bad_request when missing, rollback when different); with complete, a fence beyond the last position is rollback. log_cases MUST pass and yield head; log_invalid MUST fail with expect_error.',
    chains: { roles: CHAIN, legacy: LEGACY_CHAIN, readded: READDED_CHAIN },
    removals: { roles: states.roles.removals, legacy: states.legacy.removals, readded: states.readded.removals },
    role_changes: { roles: states.roles.role_changes, legacy: states.legacy.role_changes, readded: states.readded.role_changes },
    cases: [
      ok('editor_before_demotion', bobE1, 2),
      ok('editor_at_demotion_fence', bobE1, 3),
      ok('repromoted_editor_after_repromotion_fence', bobE1, 7),
      ok('editor_at_newer_key_epoch', record('bob-e2', bobLaptop, 2), 9),
      ok('promoted_reader_after_promotion_fence', carolE1, 5),
      ok('promoted_reader_at_demotion_fence', carolE1, 7),
      ok('owner_unaffected', record('alice-e2', alicePhone, 2), 100),
      ok('legacy_editor_before_legacy_demotion', bobE1, 2, 'legacy'),
      ok('legacy_editor_in_legacy_demotion_span', bobE1, 3, 'legacy'),
      ok('legacy_editor_at_bounding_fence', bobE1, 4, 'legacy'),
      ok('legacy_reader_in_legacy_promotion_span', carolE1, 5, 'legacy'),
      ok('legacy_reader_before_legacy_promotion', carolE1, 1, 'legacy'),
      ok('legacy_promoted_reader_after_bounding_fence', carolE1, 7, 'legacy'),
      ok('legacy_owner_unaffected', record('alice-e1', alicePhone, 1), 5, 'legacy'),
      ok('readded_old_term_before_demotion', bobE1, 2, 'readded'),
      ok('readded_new_term_after_promotion_fence', record('bob-e2', bobLaptop, 2), 7, 'readded'),
    ],
    invalid: [
      bad('demoted_editor_after_demotion_fence', 'forbidden', bobE1, 4),
      bad('demoted_editor_at_repromotion_fence', 'forbidden', bobE1, 6),
      bad('reader_before_promotion', 'forbidden', carolE1, 1),
      bad('reader_at_promotion_fence', 'forbidden', carolE1, 4),
      bad('demoted_reader_before_removal_fence', 'forbidden', carolE1, 8),
      bad('removed_reader_after_removal_fence', 'forbidden', carolE1, 9),
      bad('machine_device_of_editor_account', 'forbidden', ciE1, 2),
      bad('machine_device_at_current_key_epoch', 'forbidden', record('ci-e2', bobCi, 2), 9),
      bad('owner_key_epoch_above_state', 'forbidden', record('alice-e3', alicePhone, 3), 9),
      bad('editor_key_epoch_above_state', 'forbidden', record('bob-e3', bobLaptop, 3), 9),
      bad('never_a_member', 'forbidden', record('stranger', stranger, 1), 1),
      bad('demoted_editor_bad_signature', 'invalid_signature', { ...bobE1, sig: flipByte(bobE1.sig, 6) }, 4),
      bad('legacy_demoted_editor_after_bounding_fence', 'forbidden', bobE1, 5, 'legacy'),
      bad('legacy_machine_device_in_legacy_span', 'forbidden', ciE1, 3, 'legacy'),
      bad('readded_old_term_after_demotion_fence', 'forbidden', bobE1, 4, 'readded'),
      bad('readded_new_term_before_promotion_fence', 'forbidden', record('bob-e2', bobLaptop, 2), 5, 'readded'),
      bad('readded_new_term_ignores_old_term_role_changes', 'forbidden', record('bob-e2', bobLaptop, 2), 2, 'readded'),
    ],
    change_logs: { roles: { entries: LOG, heads: HEADS }, legacy: { entries: LEGACY_LOG, heads: LEGACY_HEADS } },
    log_cases: [
      logOk('full_log', cursorAt(0), LOG, true),
      logOk('resume_past_role_fences_with_kept_heads', cursorAt(5), slice(6, 9), true, keptAt(3, 4)),
      logOk('resume_at_role_fence', cursorAt(3), slice(4, 9), true),
      logOk('first_page_before_role_fences', cursorAt(0), slice(1, 2), false),
      logOk('legacy_full_log', legacyCursor(0), LEGACY_LOG, true, {}, 'legacy'),
    ],
    log_invalid: [
      logBad('demoted_editor_record_after_fence', 'forbidden', cursorAt(0), [...slice(1, 3), bobLate], false),
      logBad('record_substituted_below_role_fence', 'rollback', cursorAt(0), [LOG[0]!, bobSubstitute, ...slice(3, 9)], true),
      logBad('resume_past_role_fence_without_kept_head', 'bad_request', cursorAt(5), slice(6, 9), true, keptAt(4)),
      logBad('resume_past_role_fence_with_forked_kept_head', 'rollback', cursorAt(5), slice(6, 9), true, { '3': b64(seed('roles/forked-head')), '4': HEADS[4]! }),
      logBad('log_truncated_before_role_fence', 'rollback', cursorAt(0), slice(1, 5), true),
      logBad('legacy_demoted_editor_record_after_bounding_fence', 'forbidden', legacyCursor(0), [...LEGACY_LOG.slice(0, 4), bobAfterBound], false, {}, 'legacy'),
    ],
  };
}
