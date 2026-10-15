/**
 * Red-team: a server that withholds updates from a device that never saw them.
 * This pins the documented limitation ("Withholding never-seen updates" in
 * docs/security/threat-model.md): a frozen but internally consistent prefix
 * verifies for a device with no witnessed checkpoint, so the protocol does not
 * detect it on its own. Detection needs a second-channel checkpoint (another
 * device's, SAS transfer or the recovery bundle), which turns it into `rollback`.
 */
import { describe, expect, it } from 'vitest';
import {
  b64encode, buildGenesisEvent, checkRollback, createDeviceKeys, nextMembershipEvent, randomBytes, randomId,
  signCheckpoint, verifyCheckpoint, verifyMembershipChain, type CheckpointView, type MembershipEvent,
} from '../src/index.js';
import { expectCode } from './helpers.js';

const vaultId = randomId();
const owner = createDeviceKeys({ account: 'acct-synthetic', role: 'owner', kind: 'human' });
const lost = createDeviceKeys({ account: 'acct-synthetic', role: 'owner', kind: 'human' });
const recovery = createDeviceKeys({ account: 'acct-synthetic', role: 'owner', kind: 'human' });
const digest = () => b64encode(randomBytes(32));

/** genesis -> device_add(lost) -> device_remove(lost) -> rekey: the full history. */
function fullChain(): MembershipEvent[] {
  const genesis = buildGenesisEvent(
    { vault_id: vaultId, ts: 1, author: owner.record.device_id, body: { vault_kind: 'personal', owner_account: 'acct-synthetic', recovery_sign_pub: recovery.record.sign_pub, devices: [{ ...owner.record }], wraps_digest: digest() } },
    owner.signSecret,
  );
  const chain: MembershipEvent[] = [genesis];
  const next = (type: 'device_add' | 'device_remove' | 'rekey', body: Record<string, unknown>) =>
    chain.push(nextMembershipEvent(verifyMembershipChain(chain), { type, ts: chain.length + 1, author: owner.record.device_id, body: body as never }, owner.signSecret));
  next('device_add', { device: { ...lost.record }, sas: digest(), wraps_digest: digest() });
  next('device_remove', { device_id: lost.record.device_id, reason: 'stolen', log_fence: 0, log_head: '' });
  next('rekey', { new_key_epoch: 2, wraps_digest: digest(), needs_rotate: [] });
  return chain;
}

describe('red team: withheld updates (documented limitation)', () => {
  const chain = fullChain();
  const truth = verifyMembershipChain(chain);
  // The server freezes a new device before the removal and rekey.
  const frozen = chain.slice(0, 2);

  it('a frozen prefix verifies for a device with no witnessed checkpoint: not detected', () => {
    const seen = verifyMembershipChain(frozen, { vaultId, trustedAnchor: owner.record.sign_pub });
    expect(seen.seq).toBe(1);
    expect(seen.devices.map((d) => d.device_id)).toContain(lost.record.device_id);
    expect(seen.rekey_required).toBe(false);
    expect(truth.removed_device_ids).toEqual([lost.record.device_id]);
  });

  it('a second-channel checkpoint at the true head turns the same prefix into rollback', () => {
    const peer = signCheckpoint(
      { vault_id: vaultId, membership_seq: truth.seq, membership_head: truth.head, log_seq: 3, state_digest: digest(), key_epoch: truth.key_epoch, ts: 10, author: owner.record.device_id },
      owner.signSecret,
    );
    expect(verifyCheckpoint(peer, truth)).toEqual(peer);
    expectCode(() => verifyMembershipChain(frozen, { vaultId, witnessedCheckpoint: peer }), 'rollback');
    const frozenView: CheckpointView = { vault_id: vaultId, membership_seq: 1, membership_head: verifyMembershipChain(frozen).head, log_seq: 1, state_digest: digest(), key_epoch: 1 };
    expectCode(() => checkRollback(peer, frozenView), 'rollback');
  });
});
