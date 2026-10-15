/** membership.json: chains, negative chains, wrap recipient checks, SAS. Also the signed wrap sets of device-adding events. */
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
  aliceLaptop, aliceNewPhone, alicePhone, aliceTablet, b64, bobCi, bobLaptop, buildChain, by, byRecovery, byRecovery2, carolPhone, deviceFixture,
  flipByte, id, key32, negative, nonce, recoverySign, recoverySign2, recoveryAuthor, recoverySignPub, recoverySignPub2, seed, stranger,
  VAULT_PERSONAL, VAULT_SHARED, type ChainStep, type VectorDevice,
} from './fixtures.js';
import { fenceAt } from './change-log.js';

const rec = (d: VectorDevice) => ({ ...d.record }) as unknown as JsonObject;

/** Wraps of VK[epoch] (deterministic per vault) to `devices`; the esk/nonce label keeps every wrap distinct. */
export function wrapsFor(devices: VectorDevice[], epoch: number, label: string, vaultId = VAULT_SHARED): X25519Wrap[] {
  const vk = vaultId === VAULT_SHARED ? key32(`vk/epoch${epoch}`) : key32(`vk/${vaultId}/epoch${epoch}`);
  return devices.map((d) =>
    wrapToDevice({ vk, vaultId, keyEpoch: epoch, recipient: d.record, ephemeralSecret: seed(`esk/${label}/${d.name}`), nonce: nonce(`wrap/${label}/${d.name}`) }),
  );
}

/** Wraps for `devices` at each of `epochs` (a device-adding event's set). */
export function addSet(devices: VectorDevice[], epochs: number[], label: string, vaultId = VAULT_SHARED): X25519Wrap[] {
  return epochs.flatMap((e) => wrapsFor(devices, e, `${label}/e${e}`, vaultId));
}

export const sasInput: SasInput = { vault_id: VAULT_SHARED, initiator: aliceLaptop.record.device_id, joiner: bobCi.record, nonce_i: b64(seed('sas/i').slice(0, 16)), nonce_j: b64(seed('sas/j').slice(0, 16)) };
export const epoch2Wraps = wrapsFor([alicePhone, bobLaptop, bobCi, carolPhone], 2, 'e2');
export const epoch3Wraps = wrapsFor([alicePhone, bobLaptop, bobCi], 3, 'e3');

/** Signed wrap sets of the device-adding events, keyed by `<chain>/<seq>`. */
export const ADD_SETS: Record<string, X25519Wrap[]> = {
  'shared/0': addSet([alicePhone, aliceLaptop], [1], 'add/shared/0'),
  'shared/1': addSet([bobLaptop], [1], 'add/shared/1'),
  'shared/2': addSet([carolPhone], [1], 'add/shared/2'),
  'shared/3': addSet([bobCi], [1], 'add/shared/3'),
  'personal/0': addSet([alicePhone], [1], 'add/personal/0', VAULT_PERSONAL),
  'personal/1': addSet([aliceNewPhone], [1], 'add/personal/1', VAULT_PERSONAL),
  // Older epochs are optional; this set also delivers epoch 1.
  'personal/4': addSet([alicePhone], [1, 2], 'add/personal/4', VAULT_PERSONAL),
  // Recovery-authored: carries only the epochs in the recovery bundle (here the current one).
  'personal/6': addSet([aliceTablet], [2], 'add/personal/6', VAULT_PERSONAL),
};
const digestOf = (key: string) => wrapsDigest(ADD_SETS[key]!);

const genesisShared: ChainStep = {
  type: 'genesis', ...by(alicePhone),
  body: { vault_kind: 'shared', owner_account: 'acct_alice', recovery_sign_pub: recoverySignPub, devices: [rec(alicePhone), rec(aliceLaptop)], wraps_digest: digestOf('shared/0') },
};
const SHARED: ChainStep[] = [
  genesisShared,
  { type: 'member_add', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop)], wraps_digest: digestOf('shared/1') } },
  { type: 'member_add', ...by(alicePhone), body: { account: 'acct_carol', role: 'reader', devices: [rec(carolPhone)], wraps_digest: digestOf('shared/2') } },
  { type: 'device_add', ...by(aliceLaptop), body: { device: rec(bobCi), sas: sasDigest(sasInput), wraps_digest: digestOf('shared/3') } },
  { type: 'role_set', ...by(alicePhone), body: { account: 'acct_carol', role: 'editor' } },
  { type: 'device_remove', ...by(alicePhone), body: { device_id: aliceLaptop.record.device_id, reason: 'lost', ...fenceAt('shared', 4) } },
  { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 2, wraps_digest: wrapsDigest(epoch2Wraps), needs_rotate: [id('item/1'), id('item/2')] } },
  { type: 'member_remove', ...by(alicePhone), body: { account: 'acct_carol', ...fenceAt('shared', 7) } },
  { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 3, wraps_digest: wrapsDigest(epoch3Wraps), needs_rotate: [id('item/3')] } },
];

const genesisPersonal: ChainStep = {
  type: 'genesis', ...by(alicePhone),
  body: { vault_kind: 'personal', owner_account: 'acct_alice', recovery_sign_pub: recoverySignPub, devices: [rec(alicePhone)], wraps_digest: digestOf('personal/0') },
};
export const PERSONAL_RECOVERY: ChainStep[] = [
  genesisPersonal,
  { type: 'device_add', ...byRecovery, body: { device: rec(aliceNewPhone), sas: '', wraps_digest: digestOf('personal/1') } },
  // The recovered device removes the lost one itself, after verifying the change log up to log_fence.
  { type: 'device_remove', ...by(aliceNewPhone), body: { device_id: alicePhone.record.device_id, reason: 'lost', ...fenceAt('personal', 5) } },
  { type: 'rekey', ...by(aliceNewPhone), body: { new_key_epoch: 2, wraps_digest: b64(seed('personal/wraps')), needs_rotate: [] } },
  { type: 'device_add', ...by(aliceNewPhone), body: { device: rec(alicePhone), sas: b64(seed('personal/sas')), wraps_digest: digestOf('personal/4') } },
  { type: 'recovery_rotate', ...by(aliceNewPhone), body: { recovery_sign_pub: recoverySignPub2 } },
  { type: 'device_add', ...byRecovery2, body: { device: rec(aliceTablet), sas: '', wraps_digest: digestOf('personal/6') } },
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
  const anyDigest = b64(seed('wraps/x'));
  const strangerAdd: JsonObject = { device: { ...rec(stranger), account: 'acct_bob', role: 'editor' }, sas: b64(seed('sas/x')), wraps_digest: anyDigest };
  const P = PERSONAL_RECOVERY;
  const personal = (prefix: number, step: ChainStep) => withStep(prefix, step, P, VAULT_PERSONAL);
  const { wraps_digest: _wd, ...addWithoutDigest } = SHARED[3]!.body;
  const { wraps_digest: _gd, ...genesisWithoutDigest } = genesisShared.body;
  const formerRecoveryDevice: JsonObject = { ...rec(aliceTablet), device_id: recoveryAuthor, sign_pub: recoverySignPub };
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
    bad('removed_device_reappears_in_member_add', 'forbidden', withStep(6, { type: 'member_add', ...by(alicePhone), body: { account: 'acct_dave', role: 'reader', devices: [daveLaptop], wraps_digest: anyDigest } })),
    bad('key_epoch_decrease', 'rollback', withStep(7, { ...SHARED[7]!, override: { key_epoch: 1 } })),
    bad('key_epoch_change_without_rekey', 'bad_request', withStep(1, { ...SHARED[1]!, override: { key_epoch: 2 } })),
    bad('rekey_skips_epoch', 'bad_request', withStep(6, { type: 'rekey', ...by(alicePhone), body: { new_key_epoch: 3, wraps_digest: b64(seed('w')), needs_rotate: [] } })),
    bad('invalid_remove_reason', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'other', ...fenceAt('shared', 4) } })),
    bad('device_remove_without_log_fence', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'lost', log_head: fenceAt('shared', 4).log_head } })),
    bad('device_remove_string_log_fence', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'lost', log_fence: '4', log_head: fenceAt('shared', 4).log_head } })),
    bad('device_remove_without_log_head', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'lost', log_fence: 4 } })),
    bad('device_remove_empty_log_head_above_zero', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'lost', log_fence: 4, log_head: '' } })),
    bad('device_remove_log_head_at_zero_fence', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'lost', log_fence: 0, log_head: fenceAt('shared', 4).log_head } })),
    bad('device_remove_short_log_head', 'bad_request', withStep(5, { ...SHARED[5]!, body: { device_id: aliceLaptop.record.device_id, reason: 'lost', log_fence: 4, log_head: b64(seed('short').slice(0, 16)) } })),
    bad('member_remove_without_log_fence', 'bad_request', withStep(7, { ...SHARED[7]!, body: { account: 'acct_carol', log_head: fenceAt('shared', 7).log_head } })),
    bad('member_remove_without_log_head', 'bad_request', withStep(7, { ...SHARED[7]!, body: { account: 'acct_carol', log_fence: 7 } })),
    bad('recovery_key_authors_device_remove', 'forbidden', personal(2, { ...P[2]!, ...byRecovery })),
    bad('demote_last_owner', 'forbidden', withStep(1, { type: 'role_set', ...by(alicePhone), body: { account: 'acct_alice', role: 'editor' } })),
    bad('remove_last_owner_device', 'forbidden', personal(1, { type: 'device_remove', ...by(alicePhone), body: { device_id: alicePhone.record.device_id, reason: 'retired', log_fence: 0, log_head: '' } })),
    bad('member_add_in_personal_vault', 'forbidden', personal(1, { type: 'member_add', ...by(alicePhone), body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop)], wraps_digest: anyDigest } })),
    bad('recovery_key_authors_member_add', 'forbidden', withStep(1, { type: 'member_add', ...byRecovery, body: { account: 'acct_bob', role: 'editor', devices: [rec(bobLaptop)], wraps_digest: anyDigest } })),
    bad('recovery_key_adds_non_owner', 'forbidden', withStep(2, { type: 'device_add', ...byRecovery, body: { device: { ...rec(stranger), account: 'acct_bob', role: 'editor' }, sas: '', wraps_digest: anyDigest } })),
    bad('recovery_device_add_with_sas', 'bad_request', personal(1, { ...P[1]!, body: { ...P[1]!.body, sas: b64(seed('sas/x')) } })),
    bad('owner_device_add_without_sas', 'bad_request', withStep(3, { ...SHARED[3]!, body: { ...SHARED[3]!.body, sas: '' } })),
    bad('device_add_without_wraps_digest', 'bad_request', withStep(3, { ...SHARED[3]!, body: addWithoutDigest })),
    bad('member_add_malformed_wraps_digest', 'bad_request', withStep(1, { ...SHARED[1]!, body: { ...SHARED[1]!.body, wraps_digest: 'not-a-digest' } })),
    bad('genesis_without_wraps_digest', 'bad_request', buildChain(VAULT_SHARED, [{ ...genesisShared, body: genesisWithoutDigest }])),
    bad('old_recovery_key_after_rotation', 'forbidden', personal(6, { ...P[6]!, ...byRecovery })),
    bad('recovery_key_authors_recovery_rotate', 'forbidden', personal(5, { ...P[5]!, ...byRecovery })),
    bad('non_owner_authors_recovery_rotate', 'forbidden', withStep(4, { type: 'recovery_rotate', ...by(bobLaptop), body: { recovery_sign_pub: recoverySignPub2 } })),
    bad('recovery_rotate_to_same_key', 'bad_request', personal(5, { ...P[5]!, body: { recovery_sign_pub: recoverySignPub } })),
    bad('recovery_rotate_to_device_key', 'bad_request', personal(5, { ...P[5]!, body: { recovery_sign_pub: alicePhone.record.sign_pub } })),
    bad('recovery_rotate_to_removed_device_key', 'bad_request', withStep(6, { type: 'recovery_rotate', ...by(alicePhone), body: { recovery_sign_pub: aliceLaptop.record.sign_pub } })),
    bad('recovery_rotate_back_to_former_key', 'bad_request', personal(7, { type: 'recovery_rotate', ...by(aliceNewPhone), body: { recovery_sign_pub: recoverySignPub } })),
    bad('device_key_collides_with_former_recovery_key', 'bad_request', personal(7, { type: 'device_add', ...by(aliceNewPhone), body: { device: formerRecoveryDevice, sas: b64(seed('sas/x')), wraps_digest: anyDigest } })),
    bad('recovery_rotate_extra_field', 'bad_request', personal(5, { ...P[5]!, body: { recovery_sign_pub: recoverySignPub2, reason: 'leak' } })),
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
      'Membership log (spec §3.5, §4). devices: secrets and records used. recovery / rotated_recovery: the owner recovery signing key before and after the personal chain\'s recovery_rotate. chains: verifying `events` with `options` (trusted_anchor, witnessed_checkpoint) MUST yield `expected_state` exactly (removals lists every removal with the removed sign_pub, removed_seq, the key_epoch current at removal and the signed log_fence and log_head (the change-log head at the fence, "" at fence 0, from removal-fence.json change_logs); the recovery key may author only device_add). genesis, device_add and member_add bodies carry wraps_digest (wrap sets: device-add-wraps.json). invalid: verification MUST fail with expect_error. wrap_checks: validate `wraps` against the final state of chain `chain` (options.key_epoch null = any retained epoch 1..key_epoch); positives also give wraps_digest = b64 sha256(utf8("akv1/wraps\\n") || cjson(wraps sorted by rcpt, then key_epoch)). sas: transcript, 6-digit code and digest for `input`.',
    devices: [alicePhone, aliceLaptop, bobLaptop, bobCi, carolPhone, aliceNewPhone, aliceTablet, stranger].map(deviceFixture),
    recovery: { sign_seed: b64(recoverySign.secretKey), sign_pub: recoverySignPub, author: recoveryAuthor },
    rotated_recovery: { sign_seed: b64(recoverySign2.secretKey), sign_pub: recoverySignPub2, author: byRecovery2.author },
    chains: [
      chainCase('shared_full', sharedChain, { trustedAnchor: anchor, witnessedCheckpoint: { membership_seq: 4, membership_head: membershipEventHash(sharedChain[4]!) } }),
      chainCase('personal_recovery_key_reenrollment_and_rotation', personalChain, { trustedAnchor: anchor }),
    ],
    invalid: invalidChains(),
    wrap_checks: wrapChecks(),
    sas: [{ input: sasInput, transcript: utf8Decode(sasTranscript(sasInput)), code: sasCode(sasInput), digest: sasDigest(sasInput) }],
  };
}
