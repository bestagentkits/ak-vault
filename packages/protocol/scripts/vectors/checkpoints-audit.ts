/** checkpoints.json and audit.json */
import {
  appendAuditEntry,
  auditAad,
  checkRollback,
  cjsonBytes,
  computeStateDigest,
  deriveAuditKey,
  membershipEventHash,
  parseAuditEventEnvelope,
  sealEnvelope,
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
      'Checkpoints (spec §6). state_digest_cases: digest = b64 sha256(cjson([[item_id,revision,head]...] sorted by item_id)), rows with revision 0 excluded. checkpoint: signed with akv1/checkpoint by a current device of membership_events; verify MUST succeed; invalid_checkpoints MUST fail with expect_error. rollback: checkRollback(witnessed, incoming) MUST accept `accept` cases and reject `reject` cases with expect_error. It compares checkpoints only: a log restored below the witnessed log_seq and regrown past it is accepted here (regrown_past_witnessed_passes_checkpoint_comparison_alone) and refused by verifyChangeLog against the head the client kept at the witnessed position (removal-fence.json restored_regrown_*), plus the state digest at that position for a peer checkpoint.',
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
        // A log restored below the witnessed log_seq and regrown past it looks exactly like newer_log here.
        ok('regrown_past_witnessed_passes_checkpoint_comparison_alone', { ...view, log_seq: view.log_seq + 1, state_digest: other }),
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
  // Shared-vault keys of epochs 1 and 2; entries 0-1 are written at epoch 1, 2-3 after the rekey to 2.
  const vaultKeys: Record<number, Uint8Array> = { 1: key32('vk/epoch1'), 2: key32('vk/epoch2') };
  // Plaintext events use the shared envelope (spec §7.1). Entry 2 is a rotation event,
  // a type the CLI does not define: readers accept it on its envelope alone.
  const events: JsonObject[] = [
    { v: 1, type: 'item_put', item_id: id('item/A'), revision: 1, device_id: alicePhone.record.device_id, ts: BASE_TS },
    { v: 1, type: 'item_put', item_id: id('item/A'), revision: 2, device_id: bobLaptop.record.device_id, ts: BASE_TS + 1000 },
    { v: 1, type: 'rotation_started', item_id: id('item/B'), device_id: alicePhone.record.device_id, ts: BASE_TS + 2000 },
    { v: 1, type: 'item_delete', item_id: id('item/B'), revision: 2, device_id: bobLaptop.record.device_id, ts: BASE_TS + 3000 },
  ];
  const EPOCHS = [1, 1, 2, 2, 2];
  const chain = (evs: JsonObject[], label: string, epochs = EPOCHS, nonceFor = (i: number) => nonce(`audit/${label}/${i}`)) => {
    let head: AuditHead | null = null;
    const entries: Envelope[] = [];
    evs.forEach((event, i) => {
      const keyEpoch = epochs[i]!;
      const r = appendAuditEntry({ vk: vaultKeys[keyEpoch]!, vaultId: VAULT_SHARED, keyEpoch, head, event, nonce: nonceFor(i) });
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
  const forged = chain([events[0]!, { ...events[1]!, type: 'item_delete' }, events[2]!, events[3]!], 'forged');
  const rewrittenTail = chain([...events.slice(0, 3), { ...events[3]!, type: 'conflict_settled' }], 'tail');
  const extended = chain([...events, { v: 1, type: 'rotation_revoked', item_id: id('item/C'), device_id: alicePhone.record.device_id, ts: BASE_TS + 4000 }], 'main');
  const dup = chain(events.slice(0, 2), 'dup', EPOCHS, () => nonce('audit/dup'));
  const decreasing = chain(events.slice(0, 3), 'decreasing', [1, 2, 1]);
  // The vault key used directly as the audit key instead of the derived per-epoch key.
  const rawKeyEntry = sealEnvelope(vaultKeys[1]!, cjsonBytes(events[0]!), auditAad(VAULT_SHARED, 0, '', 1), { kid: 'e1', nonce: nonce('audit/raw-key/0') });
  const e = main.entries;
  type Opts = { epochs: number[]; keyEpoch: number; minKeyEpoch: number; witnessed: AuditHead | null };
  const FULL: Opts = { epochs: [1, 2], keyEpoch: 2, minKeyEpoch: 1, witnessed };
  const JOINED_AT_2: Opts = { ...FULL, epochs: [2], minKeyEpoch: 2 };
  const run = (entries: Envelope[], o: Opts) =>
    verifyAuditChain(entries, {
      vaultKeys: (k) => (o.epochs.includes(k) ? vaultKeys[k] : undefined),
      vaultId: VAULT_SHARED,
      keyEpoch: o.keyEpoch,
      minKeyEpoch: o.minKeyEpoch,
      ...(o.witnessed ? { witnessed: o.witnessed } : {}),
    });
  const fields = (entries: Envelope[], o: Opts) => ({ entries, vault_key_epochs: o.epochs, key_epoch: o.keyEpoch, min_key_epoch: o.minKeyEpoch, witnessed: o.witnessed });
  const caseOf = (name: string, entries: Envelope[], o: Opts) => {
    const out = run(entries, o);
    return { name, ...fields(entries, o), events: out.events, head: out.head };
  };
  const bad = (name: string, code: string, entries: Envelope[], o: Partial<Opts> = {}) => {
    const opts = { ...FULL, ...o };
    return negative(name, code, fields(entries, opts), () => run(entries, opts));
  };
  const envelope = (event: unknown) => parseAuditEventEnvelope(event);
  const okEnv = (name: string, event: JsonObject) => ({ name, event, envelope: envelope(event) });
  const badEnv = (name: string, code: string, event: unknown) => negative(name, code, { event }, () => envelope(event));
  const dev = alicePhone.record.device_id;
  const base = { v: 1, type: 'item_put', device_id: dev, ts: BASE_TS };
  return {
    version: 1,
    description:
      'Encrypted audit chain (spec §7). Entry i is an xc20p envelope with kid "e<k>" of cjson(event) under AuditKey[k] = HKDF-SHA256(ikm=VK[k], salt=b64decode(vault_id), info=utf8("akv1/audit-key\\n") || cjson({key_epoch:k}), L=32), aad {ctx:"akv1/audit",vault_id,seq:i,prev,key_epoch:k}, prev = b64 sha256(cjson(entry i-1)) or "" for i=0. vault_keys: VK by epoch; each case lists the epochs the verifier holds (vault_key_epochs), the current membership key_epoch and min_key_epoch. The verifier MUST hold the key of key_epoch, and of every entry epoch >= min_key_epoch (else bad_request); min_key_epoch must lie in 1..key_epoch. Key epochs never decrease along the chain nor exceed key_epoch; an entry at an older epoch the verifier holds no key for is opaque ({seq,key_epoch,opaque:true}) but still hash-chained; a decrypted entry is {seq,key_epoch,opaque:false,event}. checkpoint {v,vault_id,seq,head,author,ts,sig} is signed with akv1/audit-checkpoint by a device of membership_events. cases MUST return `events` and `head`. event_envelopes (spec §7.1): the plaintext of an audit entry is {"v":1,"type","device_id","ts",...}; parseAuditEventEnvelope MUST return {type,device_id,ts} for each valid case and read no other field (an event of a type the reader does not know, such as rotation_started, is accepted on its envelope alone) and MUST fail invalid cases with expect_error. invalid MUST fail with expect_error (reorder/drop/substitution or a non-derived key -> decrypt_failed, truncation or rewritten tail vs witnessed checkpoint -> rollback, nonce reuse, non-epoch kid, decreasing or future epoch -> bad_request).',
    vault_keys: { '1': b64(vaultKeys[1]!), '2': b64(vaultKeys[2]!) },
    audit_keys: { '1': b64(deriveAuditKey(vaultKeys[1]!, VAULT_SHARED, 1)), '2': b64(deriveAuditKey(vaultKeys[2]!, VAULT_SHARED, 2)) },
    vault_id: VAULT_SHARED,
    membership_events: membership,
    checkpoint: cp,
    cases: [
      caseOf('chain_matches_checkpoint', e, FULL),
      caseOf('chain_extended_after_checkpoint', extended.entries, FULL),
      caseOf('older_epoch_opaque_below_min_key_epoch', e, JOINED_AT_2),
      caseOf('empty_chain', [], { ...FULL, witnessed: null }),
    ],
    invalid: [
      bad('reordered', 'decrypt_failed', [e[0]!, e[2]!, e[1]!, e[3]!]),
      bad('dropped_middle', 'decrypt_failed', [e[0]!, e[1]!, e[3]!]),
      bad('dropped_tail', 'rollback', e.slice(0, 3)),
      bad('overwritten_middle', 'decrypt_failed', [forged.entries[0]!, forged.entries[1]!, e[2]!, e[3]!]),
      bad('overwritten_tail', 'rollback', rewrittenTail.entries),
      bad('nonce_reuse', 'bad_request', dup.entries, { witnessed: null }),
      bad('epoch_relabeled', 'decrypt_failed', [e[0]!, e[1]!, { ...e[2]!, kid: 'e1' }, e[3]!]),
      bad('kid_not_epoch_tag', 'bad_request', [{ ...e[0]!, kid: 'audit' }, ...e.slice(1)]),
      bad('epoch_decreases', 'bad_request', decreasing.entries, { witnessed: null }),
      bad('epoch_ahead_of_membership', 'bad_request', e, { keyEpoch: 1 }),
      bad('vault_key_used_directly', 'decrypt_failed', [rawKeyEntry], { witnessed: null }),
      bad('every_entry_opaque_without_keys', 'bad_request', e, { epochs: [], minKeyEpoch: 2 }),
      bad('tail_opaque_without_current_key', 'bad_request', e, { epochs: [1] }),
      bad('all_opaque_without_current_key', 'bad_request', e.slice(0, 2), { epochs: [1], witnessed: null }),
      bad('older_key_missing_at_or_above_min', 'bad_request', e, { epochs: [2], minKeyEpoch: 1 }),
      bad('min_key_epoch_above_key_epoch', 'bad_request', e, { minKeyEpoch: 3 }),
    ],
    event_envelopes: {
      valid: [
        okEnv('known_type', { ...base, item_id: id('item/A'), revision: 1 }),
        okEnv('unknown_type_rotation_started', { v: 1, type: 'rotation_started', item_id: id('item/B'), device_id: dev, ts: BASE_TS }),
        okEnv('unknown_type_other_fields_unread', { v: 1, type: 'future_event_9', device_id: dev, ts: BASE_TS, extra: { nested: [1, 2] } }),
        okEnv('ts_at_safe_maximum', { ...base, ts: Number.MAX_SAFE_INTEGER }),
        okEnv('type_at_64_bytes', { ...base, type: `a${'b'.repeat(63)}` }),
      ],
      invalid: [
        badEnv('unsupported_version', 'unsupported_version', { ...base, v: 2 }),
        badEnv('missing_version', 'unsupported_version', { type: 'item_put', device_id: dev, ts: BASE_TS }),
        badEnv('legacy_action_shape', 'unsupported_version', { action: 'item_read', item_id: id('item/A'), device_id: dev, ts: BASE_TS }),
        badEnv('missing_type', 'bad_request', { v: 1, device_id: dev, ts: BASE_TS }),
        badEnv('type_not_lowercase', 'bad_request', { ...base, type: 'Rotation_Started' }),
        badEnv('type_starts_with_digit', 'bad_request', { ...base, type: '1rotation' }),
        badEnv('type_has_dash', 'bad_request', { ...base, type: 'rotation-started' }),
        badEnv('type_empty', 'bad_request', { ...base, type: '' }),
        badEnv('type_over_64_bytes', 'bad_request', { ...base, type: `a${'b'.repeat(64)}` }),
        badEnv('missing_device_id', 'bad_request', { v: 1, type: 'item_put', ts: BASE_TS }),
        badEnv('malformed_device_id', 'bad_request', { ...base, device_id: 'not-an-id' }),
        badEnv('missing_ts', 'bad_request', { v: 1, type: 'item_put', device_id: dev }),
        badEnv('version_is_string', 'unsupported_version', { ...base, v: '1' }),
        badEnv('type_not_a_string', 'bad_request', { ...base, type: 7 }),
        badEnv('device_id_wrong_length', 'bad_request', { ...base, device_id: id('x').slice(0, 8) }),
        badEnv('ts_above_safe_maximum', 'bad_request', { ...base, ts: 2 ** 53 }),
        badEnv('negative_ts', 'bad_request', { ...base, ts: -1 }),
        badEnv('fractional_ts', 'bad_request', { ...base, ts: 1.5 }),
        badEnv('not_an_object', 'bad_request', ['item_put']),
      ],
    },
    invalid_checkpoints: [
      negative('bad_signature', 'invalid_signature', { checkpoint: { ...cp, sig: flipByte(cp.sig, 2) } }, () => verifyAuditCheckpoint({ ...cp, sig: flipByte(cp.sig, 2) }, state)),
      negative('tampered_seq', 'invalid_signature', { checkpoint: { ...cp, seq: 2 } }, () => verifyAuditCheckpoint({ ...cp, seq: 2 }, state)),
    ],
  };
}
