/** checkpoints.json and audit.json */
import {
  appendAuditEntry,
  checkRollback,
  computeStateDigest,
  membershipEventHash,
  signAuditCheckpoint,
  signCheckpoint,
  verifyAuditChain,
  verifyAuditCheckpoint,
  verifyCheckpoint,
  verifyMembershipChain,
  type AuditHead,
  type CheckpointView,
  type Envelope,
  type JsonObject,
} from '../../src/index.js';
import { MEMBERSHIPS } from './records.js';
import { alicePhone, b64, BASE_TS, bobLaptop, flipByte, id, key32, negative, nonce, seed, stranger, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';

export function checkpointVectors(): Record<string, unknown> {
  const events = MEMBERSHIPS['epoch3']!;
  const state = verifyMembershipChain(events);
  const rows = [
    { item_id: id('item/B'), revision: 3, head: b64(seed('head/B')) },
    { item_id: id('item/A'), revision: 4, head: b64(seed('head/A')) },
    { item_id: id('item/unwritten'), revision: 0, head: '' },
  ];
  const digest = computeStateDigest(rows);
  const fields = { vault_id: VAULT_SHARED, membership_seq: state.seq, membership_head: state.head, log_seq: 9, state_digest: digest, key_epoch: state.key_epoch, ts: BASE_TS + 3_600_000, author: alicePhone.record.device_id };
  const cp = signCheckpoint(fields, alicePhone.signSecret);
  const strangerCp = signCheckpoint({ ...fields, author: stranger.record.device_id }, stranger.signSecret);
  const otherVault = signCheckpoint({ ...fields, vault_id: VAULT_PERSONAL }, alicePhone.signSecret);
  const verifyBad = (name: string, code: string, checkpoint: unknown) => negative(name, code, { checkpoint }, () => verifyCheckpoint(checkpoint, state));
  const view: CheckpointView = { vault_id: cp.vault_id, membership_seq: cp.membership_seq, membership_head: cp.membership_head, log_seq: cp.log_seq, state_digest: cp.state_digest, key_epoch: cp.key_epoch };
  const ok = (name: string, incoming: CheckpointView) => {
    checkRollback(view, incoming);
    return { name, incoming };
  };
  const rb = (name: string, code: string, incoming: CheckpointView) => negative(name, code, { incoming }, () => checkRollback(view, incoming));
  const other = b64(seed('other-hash'));
  return {
    version: 1,
    description:
      'Checkpoints (spec §6). state_digest_cases: digest = b64 sha256(cjson([[item_id,revision,head]...] sorted by item_id)), rows with revision 0 excluded. checkpoint: signed with akv1/checkpoint by a current device of membership_events; verify MUST succeed; invalid_checkpoints MUST fail with expect_error. rollback: checkRollback(witnessed, incoming) MUST accept `accept` cases and reject `reject` cases with expect_error.',
    membership_events: events,
    state_digest_cases: [
      { rows: rows.map((r) => [r.item_id, r.revision, r.head]), digest },
      { rows: [], digest: computeStateDigest([]) },
    ],
    checkpoint: cp,
    invalid_checkpoints: [
      verifyBad('bad_signature', 'invalid_signature', { ...cp, sig: flipByte(cp.sig, 9) }),
      verifyBad('tampered_log_seq', 'invalid_signature', { ...cp, log_seq: 10 }),
      verifyBad('non_member_author', 'forbidden', strangerCp),
      verifyBad('other_vault', 'bad_request', otherVault),
      verifyBad('unsupported_version', 'unsupported_version', { ...cp, v: 2 }),
    ],
    rollback: {
      witnessed: view,
      accept: [
        ok('same_state', view),
        ok('newer_log', { ...view, log_seq: 12, state_digest: other }),
        ok('newer_membership', { ...view, membership_seq: 9, membership_head: other, log_seq: 12, state_digest: other, key_epoch: 4 }),
      ],
      reject: [
        rb('membership_seq_lower', 'rollback', { ...view, membership_seq: 2, membership_head: membershipEventHash(events[2]!) }),
        rb('membership_fork_same_seq', 'rollback', { ...view, membership_head: other }),
        rb('log_seq_lower', 'rollback', { ...view, log_seq: 8, state_digest: other }),
        rb('state_fork_same_log_seq', 'rollback', { ...view, state_digest: other }),
        rb('key_epoch_lower', 'rollback', { ...view, log_seq: 12, state_digest: other, key_epoch: 2 }),
      ],
    },
  };
}

export function auditVectors(): Record<string, unknown> {
  const key = key32('audit');
  const events: JsonObject[] = [
    { action: 'item_read', item_id: id('item/A'), device_id: alicePhone.record.device_id, ts: BASE_TS },
    { action: 'item_write', item_id: id('item/A'), device_id: bobLaptop.record.device_id, ts: BASE_TS + 1000 },
    { action: 'grant', item_id: id('item/B'), device_id: alicePhone.record.device_id, ts: BASE_TS + 2000, purpose: 'deploy' },
    { action: 'item_read', item_id: id('item/B'), device_id: bobLaptop.record.device_id, ts: BASE_TS + 3000 },
  ];
  const chain = (evs: JsonObject[], label: string, nonceFor = (i: number) => nonce(`audit/${label}/${i}`)) => {
    let head: AuditHead | null = null;
    const entries: Envelope[] = [];
    evs.forEach((event, i) => {
      const r = appendAuditEntry({ key, vaultId: VAULT_SHARED, kid: 'e1', head, event, nonce: nonceFor(i) });
      entries.push(r.entry);
      head = r.head;
    });
    return { entries, head: head! };
  };
  const main = chain(events, 'main');
  const membership = MEMBERSHIPS['base']!;
  const state = verifyMembershipChain(membership);
  const cp = signAuditCheckpoint({ vault_id: VAULT_SHARED, seq: main.head.seq, head: main.head.head, author: alicePhone.record.device_id, ts: BASE_TS + 10_000 }, alicePhone.signSecret);
  verifyAuditCheckpoint(cp, state);
  const witnessed = { seq: cp.seq, head: cp.head };
  const forged = chain([events[0]!, { ...events[1]!, action: 'nothing_happened' }, events[2]!, events[3]!], 'forged');
  const rewrittenTail = chain([...events.slice(0, 3), { ...events[3]!, action: 'item_list' }], 'tail');
  const extended = chain([...events, { action: 'item_read', item_id: id('item/C'), device_id: alicePhone.record.device_id, ts: BASE_TS + 4000 }], 'main');
  const dup = chain(events.slice(0, 2), 'dup', () => nonce('audit/dup'));
  const e = main.entries;
  const bad = (name: string, code: string, entries: Envelope[], useWitness = true) =>
    negative(name, code, { entries, witnessed: useWitness ? witnessed : null }, () => verifyAuditChain(entries, useWitness ? { key, vaultId: VAULT_SHARED, witnessed } : { key, vaultId: VAULT_SHARED }));
  const verifyOk = (entries: Envelope[]) => verifyAuditChain(entries, { key, vaultId: VAULT_SHARED, witnessed });
  return {
    version: 1,
    description:
      'Encrypted audit chain (spec §7). Entry i is an xc20p envelope (kid "e1") of cjson(event) with aad {ctx:"akv1/audit",vault_id,seq:i,prev}, prev = b64 sha256(cjson(entry i-1)) or "" for i=0. checkpoint {v,vault_id,seq,head,author,ts,sig} is signed with akv1/audit-checkpoint by a device of membership_events. cases: verifying entries against the witnessed checkpoint MUST return `events` and `head`. invalid: MUST fail with expect_error (reorder/drop/substitution -> decrypt_failed, truncation or rewritten tail vs witnessed checkpoint -> rollback, nonce reuse -> bad_request).',
    key: b64(key),
    vault_id: VAULT_SHARED,
    membership_events: membership,
    checkpoint: cp,
    cases: [
      { name: 'chain_matches_checkpoint', entries: e, witnessed, events, head: verifyOk(e).head },
      { name: 'chain_extended_after_checkpoint', entries: extended.entries, witnessed, events: verifyOk(extended.entries).events, head: verifyOk(extended.entries).head },
    ],
    invalid: [
      bad('reordered', 'decrypt_failed', [e[0]!, e[2]!, e[1]!, e[3]!]),
      bad('dropped_middle', 'decrypt_failed', [e[0]!, e[1]!, e[3]!]),
      bad('dropped_tail', 'rollback', e.slice(0, 3)),
      bad('overwritten_middle', 'decrypt_failed', [forged.entries[0]!, forged.entries[1]!, e[2]!, e[3]!]),
      bad('overwritten_tail', 'rollback', rewrittenTail.entries),
      bad('nonce_reuse', 'bad_request', dup.entries, false),
    ],
    invalid_checkpoints: [
      negative('bad_signature', 'invalid_signature', { checkpoint: { ...cp, sig: flipByte(cp.sig, 2) } }, () => verifyAuditCheckpoint({ ...cp, sig: flipByte(cp.sig, 2) }, state)),
      negative('tampered_seq', 'invalid_signature', { checkpoint: { ...cp, seq: 2 } }, () => verifyAuditCheckpoint({ ...cp, seq: 2 }, state)),
    ],
  };
}
