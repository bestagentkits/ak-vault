/** removal-fence.json: change-log records by removed authors against each removal's signed log_fence. */
import { sealItem, signRecord, verifyLoggedRecord, verifyMembershipChain, type MembershipEvent, type SignedRecord } from '../../src/index.js';
import { aliceLaptop, aliceNewPhone, alicePhone, BASE_TS, bobLaptop, carolPhone, flipByte, id, key32, negative, nonce, stranger, VAULT_PERSONAL, VAULT_SHARED, type VectorDevice } from './fixtures.js';
import { personalChain, sharedChain } from './membership.js';

type ChainName = 'shared' | 'personal';
const CHAINS: Record<ChainName, MembershipEvent[]> = { shared: sharedChain, personal: personalChain };
const VAULTS: Record<ChainName, string> = { shared: VAULT_SHARED, personal: VAULT_PERSONAL };

function record(label: string, chain: ChainName, author: VectorDevice, keyEpoch: number): SignedRecord {
  const vault = VAULTS[chain];
  const vk = vault === VAULT_SHARED ? key32(`vk/epoch${keyEpoch}`) : key32(`vk/${vault}/epoch${keyEpoch}`);
  const ctx = { vault_id: vault, item_id: id(`fence/item/${label}`), base_revision: 0, key_epoch: keyEpoch, author: author.record.device_id, tombstone: false };
  const env = sealItem({ ...ctx, vk, payload: { name: 'API_KEY', value: `fence-${label}`, meta: {}, sensitivity: 'normal' }, nonce: nonce(`fence/record/${label}`) });
  return signRecord({ ...ctx, ts: BASE_TS, resolves: [], env }, author.signSecret);
}

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
  const laptopE1 = record('laptop-e1', 'shared', aliceLaptop, 1);
  const carolE2 = record('carol-e2', 'shared', carolPhone, 2);
  const phoneE1 = record('phone-e1', 'personal', alicePhone, 1);

  return {
    version: 1,
    description:
      'Removal fence (spec §5, §6). chains: membership.json chains (shared = chains[0], personal = chains[1]); state = verifyMembershipChain(chain); state.removals lists each removal with the removed sign_pub, the key_epoch current at removal and the signed log_fence of the removing event. verifyLoggedRecord(record, state, log_seq): record parses; same vault; log_seq >= 1 (bad_request); the author is a current device, or a removed device whose record key_epoch is not newer than the key_epoch of its last removal (forbidden); the signature verifies under that device key (invalid_signature); for every removal of the author with removal.key_epoch >= record.key_epoch, log_seq > removal.log_fence is forbidden. cases MUST pass; invalid MUST fail with expect_error.',
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
  };
}
