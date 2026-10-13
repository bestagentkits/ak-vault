/**
 * Removal fences, the recovery identity (bundle and membership reads only), a full
 * recovery of a vault that grew after its bundle was sealed, and recovery-key
 * rotation landing atomically with the resealed bundle.
 */
import {
  b64encode,
  deviceIdFromSignPub,
  generateRecoveryKey,
  openRecoveryBundle,
  randomBytes,
  randomId,
  sha256b64,
  signCheckpoint,
  signKeyPairFromSeed,
  unwrapFromDevice,
  verifyDeviceWraps,
  verifyMembershipChain,
  type MembershipEvent,
} from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call, createDevice, type TestDevice } from './helpers/api-client.js';
import { putTestBundle, sealTestBundle } from './helpers/recovery-bundle.js';
import { signerOf, VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'API_KEY', value: 'synthetic-value' };
const keyHeader = (d: TestDevice) => ({ headers: { 'AKV-Device-Key': d.keys.record.sign_pub } });

describe('removal fence', () => {
  it('a removal must sign the current change-log head', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.write(laptop, randomId(), 0, v)).status).toBe(200);
    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
    const stale = await fx.removeDevice(laptop, 1);
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe('conflict');
    expect((await fx.removeDevice(laptop, 3)).json.error.code).toBe('bad_request');
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect(fx.state.removals).toEqual([expect.objectContaining({ device_id: laptop.keys.record.device_id, key_epoch: 1, log_fence: 2 })]);
  });

  it('refuses writes by a removed device, also when another device submits them', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const early = fx.record(laptop, randomId(), 0, v);
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    // The remover posts a checkpoint right after the removal, while writes wait for the rekey.
    const cp = signCheckpoint(
      { vault_id: fx.vaultId, membership_seq: fx.state.seq, membership_head: fx.state.head, log_seq: 0, state_digest: sha256b64(randomBytes(4)), key_epoch: 1, ts: Date.now(), author: fx.owner.keys.record.device_id },
      fx.owner.keys.signSecret,
    );
    expect(fx.state.rekey_required).toBe(true);
    expect((await fx.post(fx.owner, '/checkpoints', cp)).status).toBe(201);
    expect((await fx.rekey()).status).toBe(201);
    expect((await fx.put(laptop, early)).status).toBe(403);
    const relayed = await fx.put(fx.owner, early);
    expect(relayed.status).toBe(403);
    expect(relayed.json.error.code).toBe('forbidden');
    expect((await fx.put(fx.owner, fx.record(laptop, randomId(), 0, v, { keyEpoch: 2 }))).status).toBe(403);
  });
});

describe('recovery identity', () => {
  it('may read the bundle and membership, nothing else', async () => {
    const fx = await VaultFixture.create();
    expect((await putTestBundle(fx, fx.owner, sealTestBundle(fx, 1))).status).toBe(200);
    const fresh = createDevice(fx.owner.account, 'owner');
    expect((await fx.get(fresh, '/membership', keyHeader(fresh))).status).toBe(200);
    expect((await fx.get(fresh, '/recovery', keyHeader(fresh))).status).toBe(200);
    expect((await fx.get(fresh, '/membership')).status).toBe(403);
    const cp = { vault_id: fx.vaultId };
    const refused = [
      await fx.get(fresh, '/wraps', keyHeader(fresh)),
      await fx.get(fresh, '/wraps?membership_seq=0', keyHeader(fresh)),
      await fx.get(fresh, '/changes', keyHeader(fresh)),
      await fx.get(fresh, '/checkpoints', keyHeader(fresh)),
      await fx.get(fresh, '/audit', keyHeader(fresh)),
      await fx.get(fresh, `/items/${randomId()}`, keyHeader(fresh)),
      await fx.post(fresh, '/checkpoints', cp, keyHeader(fresh)),
      await fx.post(fresh, '/audit', { start_seq: 0, prev: '', entries: [] }, keyHeader(fresh)),
      await call(fresh, 'PUT', `/v1/vaults/${fx.vaultId}/items/${randomId()}`, fx.record(fresh, randomId(), 0, v), keyHeader(fresh)),
      await putTestBundle(fx, fresh, sealTestBundle(fx, 2), fx.state.seq, keyHeader(fresh)),
      await fx.append(fx.buildEvent('role_set', { account: fx.owner.account, role: 'owner' }, signerOf(fresh)), undefined, fresh, keyHeader(fresh)),
    ];
    expect(refused.map((r) => r.status)).toEqual(refused.map(() => 403));
  });

  it('recovers a vault that gained a device after the bundle was sealed', async () => {
    const fx = await VaultFixture.create();
    const rk = generateRecoveryKey();
    expect((await putTestBundle(fx, fx.owner, sealTestBundle(fx, 1, rk))).status).toBe(200);
    const laptop = await fx.addDevice();
    expect((await fx.write(laptop, randomId(), 0, v)).status).toBe(200);

    // Every device lost: verify the chain from the pinned anchor, then open the bundle against it.
    const fresh = createDevice(fx.owner.account, 'owner');
    const events = (await fx.get(fresh, '/membership', keyHeader(fresh))).json.events as MembershipEvent[];
    const chain = verifyMembershipChain(events, { trustedAnchor: fx.owner.keys.record.sign_pub, vaultId: fx.vaultId });
    const bundle = (await fx.get(fresh, '/recovery', keyHeader(fresh))).json.bundle;
    const opened = openRecoveryBundle({ bundle, vaultId: fx.vaultId, rk, recoverySignPub: chain.recovery_sign_pub });
    const enroll = fx.enrollEvent(fresh, [1], { id: chain.recovery_author, secret: opened.recovery_sign_sk });
    expect((await fx.append(enroll.event, enroll.wraps, fresh)).status).toBe(201);
    const set = (await fx.get(fresh, `/wraps?membership_seq=${fx.state.seq}`)).json.wraps;
    const [wrap] = verifyDeviceWraps(enroll.event, set);
    expect(unwrapFromDevice({ wrap: wrap!, vaultId: fx.vaultId, deviceId: fresh.keys.record.device_id, kxSecret: fresh.keys.kxSecret })).toEqual(opened.vk['1']);

    // The recovered device removes the lost ones itself (the recovery key may not), then rekeys.
    const removeByRecovery = fx.buildEvent('device_remove', { device_id: laptop.keys.record.device_id, reason: 'lost', log_fence: 1 }, { id: chain.recovery_author, secret: opened.recovery_sign_sk });
    expect((await fx.append(removeByRecovery, undefined, fresh)).status).toBe(403);
    expect((await fx.removeDevice(laptop, undefined, fresh)).status).toBe(201);
    expect((await fx.removeDevice(fx.owner, undefined, fresh)).status).toBe(201);
    expect((await fx.rekey(fresh)).status).toBe(201);
    expect((await fx.write(fresh, randomId(), 0, v)).status).toBe(200);
    expect((await fx.write(laptop, randomId(), 0, v)).status).toBe(403);
  });
});

describe('recovery_rotate', () => {
  it('lands only with a resealed bundle, and only the new key enrolls afterwards', async () => {
    const fx = await VaultFixture.create();
    expect((await putTestBundle(fx, fx.owner, sealTestBundle(fx, 1))).status).toBe(200);
    const rotated = signKeyPairFromSeed(randomBytes(32));
    const event = fx.buildEvent('recovery_rotate', { recovery_sign_pub: b64encode(rotated.publicKey) });
    expect((await fx.append(event)).status).toBe(400);
    const sameSeq = await fx.append(event, undefined, fx.owner, {}, { bundle: sealTestBundle(fx, 1, undefined, rotated.secretKey) as never });
    expect(sameSeq.json.error.code).toBe('conflict');
    expect((await fx.get(fx.owner, '/membership')).json.membership.seq).toBe(0);
    const ok = await fx.append(event, undefined, fx.owner, {}, { bundle: sealTestBundle(fx, 2, undefined, rotated.secretKey) as never });
    expect(ok.status).toBe(201);
    expect(ok.json.bundle_seq).toBe(2);
    expect(fx.state.recovery_author).toBe(deviceIdFromSignPub(rotated.publicKey));
    expect((await fx.get(fx.owner, '/recovery')).json.bundle.bundle_seq).toBe(2);
    const roleSet = fx.buildEvent('role_set', { account: fx.owner.account, role: 'owner' });
    expect((await fx.append(roleSet, undefined, fx.owner, {}, { bundle: sealTestBundle(fx, 3) as never })).status).toBe(400);

    const fresh = createDevice(fx.owner.account, 'owner');
    const old = fx.enrollEvent(fresh, [1], { id: fx.recoveryAuthorId(), secret: fx.recovery.secretKey });
    expect((await fx.append(old.event, old.wraps, fresh)).status).toBe(403);
    const viaNew = fx.enrollEvent(fresh, [1], { id: deviceIdFromSignPub(rotated.publicKey), secret: rotated.secretKey });
    expect((await fx.append(viaNew.event, viaNew.wraps, fresh)).status).toBe(201);
  });

  it('refuses a bundle sealed before the latest recovery_rotate, so a stale owner device cannot break recovery', async () => {
    const fx = await VaultFixture.create();
    expect((await putTestBundle(fx, fx.owner, sealTestBundle(fx, 1))).status).toBe(200);
    const rotated = signKeyPairFromSeed(randomBytes(32));
    const rotate = fx.buildEvent('recovery_rotate', { recovery_sign_pub: b64encode(rotated.publicKey) });
    expect((await fx.append(rotate, undefined, fx.owner, {}, { bundle: sealTestBundle(fx, 2, undefined, rotated.secretKey) as never })).status).toBe(201);
    await fx.addDevice(); // seq 2
    // A device that has not replayed seq 1 still reseals with the old recovery key.
    const stale = await putTestBundle(fx, fx.owner, sealTestBundle(fx, 3), 0);
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe('conflict');
    expect((await putTestBundle(fx, fx.owner, sealTestBundle(fx, 3, undefined, rotated.secretKey), 3)).json.error.code).toBe('bad_request');
    const missing = await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/recovery`, { bundle: sealTestBundle(fx, 3, undefined, rotated.secretKey) });
    expect(missing.json.error.code).toBe('bad_request');
    expect((await fx.get(fx.owner, '/recovery')).json.bundle.bundle_seq).toBe(2);
    expect((await putTestBundle(fx, fx.owner, sealTestBundle(fx, 3, undefined, rotated.secretKey), 1)).status).toBe(200);
  });

  it('a non-owner device cannot rotate the recovery key', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const rotated = signKeyPairFromSeed(randomBytes(32));
    const event = fx.buildEvent('recovery_rotate', { recovery_sign_pub: b64encode(rotated.publicKey) }, signerOf(editor));
    expect((await fx.append(event, undefined, editor, {}, { bundle: sealTestBundle(fx, 1, undefined, rotated.secretKey) as never })).status).toBe(403);
  });
});
