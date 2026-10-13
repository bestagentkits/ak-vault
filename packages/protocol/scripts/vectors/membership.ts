/** membership.json: chains, negative chains, wrap recipient checks, SAS. */
import {
  membershipEventHash,
  sasCode,
  sasDigest,
  sasTranscript,
  utf8Decode,
  validateWrapRecipients,
  verifyMembershipChain,
  wrapToDevice,
  wrapsDigest,
  type JsonObject,
  type MembershipEvent,
  type SasInput,
  type VerifyChainOptions,
  type X25519Wrap,
} from '../../src/index.js';
import {
  aliceLaptop, aliceNewPhone, alicePhone, b64, bobCi, bobLaptop, buildChain, by, byRecovery, carolPhone, deviceFixture,
  flipByte, id, key32, negative, nonce, recoverySign, recoveryAuthor, recoverySignPub, seed, stranger, VAULT_PERSONAL, VAULT_SHARED,
  type ChainStep, type VectorDevice,
} from './fixtures.js';

const rec = (d: VectorDevice) => ({ ...d.record }) as unknown as JsonObject;

export function wrapsFor(devices: VectorDevice[], epoch: number, label: string): X25519Wrap[] {
  return devices.map((d) =>
    wrapToDevice({ vk: key32(`vk/epoch${epoch}`), vaultId: VAULT_SHARED, keyEpoch: epoch, recipient: d.record, ephemeralSecret: seed(`esk/${label}/${d.name}`), nonce: nonce(`wrap/${label}/${d.name}`) }),
  );
}

export const sasInput: SasInput = { vault_id: VAULT_SHARED, initiator: aliceLaptop.record.device_id, joiner: bobCi.record, nonce_i: b64(seed('sas/i').slice(0, 16)), nonce_j: b64(seed('sas/j').slice(0, 16)) };
export const epoch2Wraps = wrapsFor([alicePhone, bobLaptop, bobCi, carolPhone], 2, 'e2');
export const epoch3Wraps = wrapsFor([alicePhone, bobLaptop, bobCi], 3, 'e3');

const genesisShared: ChainStep = {
  type: 'genesis', ...by(alicePhone),
  body: { vault_kind: 'shared', owner_account: 'acct_alice', recovery_sign_pub: recoverySignPub, devices: [rec(alicePhone), rec(aliceLaptop)] },
};
const SHARED: ChainStep[] = [
  genesisShared,
  { type: 'member_add', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop)] } },
  { type: 'member_add', ...by(alicePhone), body: { account: 'acct_carol', role: 'reader', devices: [rec(carolPhone)] } },
  { type: 'device_add', ...by(aliceLaptop), body: { device: rec(bobCi), sas: sasDigest(sasInput) } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_carol', role: 'editor' } },
  { type: 'device_remove', ...by(alicePhone), body: { device_id: aliceLaptop.record.device_id, reason: 'lost' } },
  { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 2, wraps_digest: wrapsDigest(epoch2Wraps), needs_rotate: [id('item/1'), id('item/2')] } },
  { type: 'member_remove', ...by(alicePhone), body: { account: 'acct_carol' } },
  { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 3, wraps_digest: wrapsDigest(epoch3Wraps), needs_rotate: [id('item/3')] } },
];

const genesisPersonal: ChainStep = {
  type: 'genesis', ...by(alicePhone),
  body: { vault_kind: 'personal', owner_account: 'acct_alice', recovery_sign_pub: recoverySignPub, devices: [rec(alicePhone)] },
};
const PERSONAL_RECOVERY: ChainStep[] = [
  genesisPersonal,
  { type: 'device_add', ...byRecovery, body: { device: rec(aliceNewPhone), sas: '' } },
  { type: 'device_remove', ...byRecovery, body: { device_id: alicePhone.record.device_id, reason: 'lost' } },
  { type: 'rekey', ...by(aliceNewPhone), body: { new_key_epoch: 2, wraps_digest: b64(seed('personal/wraps')), needs_rotate: [] } },
  { type: 'device_add', ...by(aliceNewPhone), body: { device: rec(alicePhone), sas: b64(seed('personal/sas')) } },
];

/** Exported for records/checkpoint/audit vectors. */
export const sharedChain = buildChain(VAULT_SHARED, SHARED);
export const personalChain = buildChain(VAULT_PERSONAL, PERSONAL_RECOVERY);

function optionsJson(o: VerifyChainOptions): JsonObject {
  const out: JsonObject = {};
  if (o.trustedAnchor) out['trusted_anchor'] = o.trustedAnchor;
  if (o.witnessedCheckpoint) out['witnessed_checkpoint'] = { membership_seq: o.witnessedCheckpoint.membership_seq, membership_head: o.witnessedCheckpoint.membership_head };
  return out;
}

function chainCase(name: string, events: MembershipEvent[], opts: VerifyChainOptions = {}) {
  return { name, events, options: optionsJson(opts), expected_state: verifyMembershipChain(events, opts) };
}

function bad(name: string, code: string, events: unknown[], opts: VerifyChainOptions = {}) {
  return negative(name, code, { events, options: optionsJson(opts) }, () => verifyMembershipChain(events, opts));
}

const withStep = (prefix: number, step: ChainStep, base = SHARED, vault = VAULT_SHARED) => buildChain(vault, [...base.slice(0, prefix), step]);

function invalidChains() {
  const ev = sharedChain;
  const daveLaptop = { ...rec(aliceLaptop), account: 'acct_dave', role: 'reader' };
  const strangerAdd: JsonObject = { device: { ...rec(stranger), account: 'acct_bob', role: 'editor' }, sas: b64(seed('sas/x')) };
  return [
    bad('bad_signature', 'invalid_signature', [ev[0], { ...ev[1]!, sig: flipByte(ev[1]!.sig, 5) }, ev[2]]),
    bad('tampered_body', 'invalid_signature', [ev[0], { ...ev[1]!, body: { ...ev[1]!.body, role: 'owner' } }]),
    bad('wrong_prev', 'bad_request', withStep(2, { ...SHARED[2]!, override: { prev: b64(seed('bogus-prev')) } })),
    bad('seq_gap', 'bad_request', [ev[0], ev[1], ev[3]]),
    bad('membership_epoch_mismatch', 'bad_request', withStep(1, { ...SHARED[1]!, override: { membership_epoch: 5 } })),
    bad('non_owner_author', 'forbidden', withStep(2, { type: 'device_add', ...by(bobLaptop), body: strangerAdd })),
    bad('non_member_non_recovery_author', 'forbidden', withStep(2, { type: 'device_add', ...by(stranger), body: strangerAdd })),
    bad('machine_device_author', 'forbidden', withStep(4, { type: 'role_set', ...by(bobCi), body: { account: 'acct_bob', role: 'owner' } })),
    bad('removed_device_authors', 'forbidden', withStep(6, { type: 'role_set', ...by(aliceLaptop), body: { account: 'acct_bob', role: 'reader' } })),
    bad('removed_device_reappears_in_member_add', 'forbidden', withStep(6, { type: 'member_add', ...by(alicePhone), body: { account: 'acct_dave', role: 'reader', devices: [daveLaptop] } })),
    bad('key_epoch_decrease', 'rollback', withStep(7, { ...SHARED[7]!, override: { key_epoch: 1 } })),
    bad('key_epoch_change_without_rekey', 'bad_request', withStep(1, { ...SHARED[1]!, override: { key_epoch: 2 } })),
    bad('rekey_skips_epoch', 'bad_request', withStep(6, { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 3, wraps_digest: b64(seed('w')), needs_rotate: [] } })),
    bad('invalid_remove_reason', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'other' } })),
    bad('demote_last_owner', 'forbidden', withStep(1, { type: 'role_set', ...by(alicePhone), body: { account: 'acct_alice', role: 'editor' } })),
    bad('remove_last_owner_device', 'forbidden', withStep(1, { type: 'device_remove', ...by(alicePhone), body: { device_id: alicePhone.record.device_id, reason: 'retired' } }, PERSONAL_RECOVERY, VAULT_PERSONAL)),
    bad('member_add_in_personal_vault', 'forbidden', withStep(1, { type: 'member_add', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop)] } }, PERSONAL_RECOVERY, VAULT_PERSONAL)),
    bad('recovery_key_authors_member_add', 'forbidden', withStep(1, { type: 'member_add', ...byRecovery, body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop)] } })),
    bad('recovery_key_adds_non_owner', 'forbidden', withStep(2, { type: 'device_add', ...byRecovery, body: { device: { ...rec(stranger), account: 'acct_bob', role: 'editor' }, sas: '' } })),
    bad('recovery_device_add_with_sas', 'bad_request', withStep(1, { ...PERSONAL_RECOVERY[1]!, body: { device: rec(aliceNewPhone), sas: b64(seed('sas/x')) } }, PERSONAL_RECOVERY, VAULT_PERSONAL)),
    bad('owner_device_add_without_sas', 'bad_request', withStep(3, { ...SHARED[3]!, body: { device: rec(bobCi), sas: '' } })),
    bad('genesis_author_not_in_devices', 'forbidden', buildChain(VAULT_SHARED, [{ ...genesisShared, ...by(stranger) }])),
    bad('genesis_not_first', 'bad_request', buildChain(VAULT_SHARED, [SHARED[1]!])),
    bad('unsupported_version', 'unsupported_version', [ev[0], { ...ev[1]!, v: 2 }]),
    bad('unknown_event_type', 'unsupported_version', [ev[0], { ...ev[1]!, type: 'grant_all' }]),
    bad('untrusted_anchor', 'forbidden', ev, { trustedAnchor: stranger.record.sign_pub }),
    bad('chain_behind_witnessed_checkpoint', 'rollback', ev.slice(0, 5), { witnessedCheckpoint: { membership_seq: 8, membership_head: membershipEventHash(ev[8]!) } }),
    bad('chain_forks_from_witnessed_checkpoint', 'rollback', ev, { witnessedCheckpoint: { membership_seq: 3, membership_head: b64(seed('fork')) } }),
  ];
}

function wrapChecks() {
  const state = verifyMembershipChain(sharedChain);
  const ok = (name: string, wraps: X25519Wrap[], o: { keyEpoch?: number; requireAll?: boolean } = {}) => {
    validateWrapRecipients(state, wraps, o);
    return { name, chain: 'shared_full', wraps, options: { key_epoch: o.keyEpoch ?? null, require_all: o.requireAll ?? false }, wraps_digest: wrapsDigest(wraps) };
  };
  const no = (name: string, code: string, wraps: X25519Wrap[], o: { keyEpoch?: number; requireAll?: boolean } = {}) =>
    negative(name, code, { chain: 'shared_full', wraps, options: { key_epoch: o.keyEpoch ?? null, require_all: o.requireAll ?? false } }, () => validateWrapRecipients(state, wraps, o));
  const older = wrapsFor([alicePhone], 1, 'e1');
  return [
    ok('rekey_wrap_set_current_epoch', epoch3Wraps, { keyEpoch: 3, requireAll: true }),
    ok('older_retained_epoch_to_current_member', older),
    no('injected_recipient', 'forbidden', [...epoch3Wraps, ...wrapsFor([stranger], 3, 'inj')]),
    no('removed_member_recipient', 'forbidden', wrapsFor([carolPhone], 3, 'removed')),
    no('removed_member_older_epoch', 'forbidden', wrapsFor([carolPhone], 2, 'removed-old')),
    no('future_epoch', 'bad_request', wrapsFor([alicePhone], 4, 'future')),
    no('missing_recipient', 'bad_request', epoch3Wraps.slice(0, 2), { keyEpoch: 3, requireAll: true }),
    no('duplicate_recipient', 'bad_request', [epoch3Wraps[0]!, ...wrapsFor([alicePhone], 3, 'dup')]),
  ];
}

export function membershipVectors(): Record<string, unknown> {
  const anchor = alicePhone.record.sign_pub;
  return {
    version: 1,
    description:
      'Membership log (spec §3.5, §4). devices: secrets and records used. chains: verifying `events` with `options` (trusted_anchor, witnessed_checkpoint) MUST yield `expected_state` exactly. invalid: verification MUST fail with expect_error. wrap_checks: validate `wraps` against the final state of chain `chain` (options.key_epoch null = any retained epoch 1..key_epoch); positives also give wraps_digest = b64 sha256(cjson(wraps sorted by rcpt)). sas: transcript, 6-digit code and digest for `input`.',
    devices: [alicePhone, aliceLaptop, bobLaptop, bobCi, carolPhone, aliceNewPhone, stranger].map(deviceFixture),
    recovery: { sign_seed: b64(recoverySign.secretKey), sign_pub: recoverySignPub, author: recoveryAuthor },
    chains: [
      chainCase('shared_full', sharedChain, { trustedAnchor: anchor, witnessedCheckpoint: { membership_seq: 4, membership_head: membershipEventHash(sharedChain[4]!) } }),
      chainCase('personal_recovery_key_reenrollment', personalChain, { trustedAnchor: anchor }),
    ],
    invalid: invalidChains(),
    wrap_checks: wrapChecks(),
    sas: [{ input: sasInput, transcript: utf8Decode(sasTranscript(sasInput)), code: sasCode(sasInput), digest: sasDigest(sasInput) }],
  };
}
