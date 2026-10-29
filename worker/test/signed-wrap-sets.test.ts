/**
 * Signed wrap sets: every wrap is stored as part of the set one owner-signed event
 * committed to, served back complete (removed recipients included) so any member
 * can recompute the digest, and the change log stays contiguous.
 */
import { b64encode, randomBytes, randomId, signMembershipEvent, unwrapFromDevice, verifyDeviceWraps, verifyMembershipChain, verifyRekeyWraps, type MembershipEvent } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { createDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'API_KEY', value: 'synthetic-value' };

describe('signed wrap sets', () => {
  it('serves each event set as signed, including wraps of later-removed devices', async () => {
    const fx = await VaultFixture.create('shared');
    const phone = await fx.addDevice(); // seq 1
    const laptop = await fx.addDevice(); // seq 2
    expect((await fx.removeDevice(phone)).status).toBe(201); // seq 3
    expect((await fx.rekey()).status).toBe(201); // seq 4: wraps for owner and laptop
    expect((await fx.removeDevice(laptop)).status).toBe(201); // seq 5
    expect((await fx.rekey()).status).toBe(201); // seq 6
    const newbie = await fx.addDevice(); // seq 7

    const events = (await fx.get(newbie, '/membership')).json.events as MembershipEvent[];
    const rekeySet = await fx.get(newbie, '/wraps?membership_seq=4');
    expect(rekeySet.status).toBe(200);
    expect(rekeySet.json.wraps.map((w: { rcpt: string }) => w.rcpt)).toContain(laptop.keys.record.device_id);
    expect(verifyRekeyWraps(events[4], rekeySet.json.wraps, { state: verifyMembershipChain(events.slice(0, 5)) })).toHaveLength(2);

    const laptopAdd = await fx.get(newbie, '/wraps?membership_seq=2');
    expect(verifyDeviceWraps(events[2], laptopAdd.json.wraps)).toHaveLength(1);

    const ownSet = (await fx.get(newbie, '/wraps?membership_seq=7')).json.wraps;
    const [wrap] = verifyDeviceWraps(events[7], ownSet);
    expect(unwrapFromDevice({ wrap: wrap!, vaultId: fx.vaultId, deviceId: newbie.keys.record.device_id, kxSecret: newbie.keys.kxSecret })).toEqual(fx.vk.get(3));

    // Listing mode keeps the current-device filter and names each wrap's set.
    const listed = (await fx.get(newbie, '/wraps')).json.wraps as { membership_seq: number; wrap: { rcpt: string } }[];
    expect(listed.some((w) => w.wrap.rcpt === laptop.keys.record.device_id)).toBe(false);
    expect(listed.find((w) => w.wrap.rcpt === newbie.keys.record.device_id)?.membership_seq).toBe(7);
  });

  it('answers 404 for an event without a set, 400 for mixed filters, 403 for non-members', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await fx.get(fx.owner, '/wraps?membership_seq=2')).status).toBe(404);
    expect((await fx.get(fx.owner, '/wraps?membership_seq=99')).status).toBe(404);
    expect((await fx.get(fx.owner, `/wraps?membership_seq=0&rcpt=${fx.owner.keys.record.device_id}`)).status).toBe(400);
    expect((await fx.get(laptop, '/wraps?membership_seq=1')).status).toBe(403);
    const stranger = createDevice(`acct-${randomId()}`);
    expect((await fx.get(stranger, '/wraps?membership_seq=0')).status).toBe(403);
  });

  it('refuses an unknown membership event type', async () => {
    const fx = await VaultFixture.create();
    const { sig: _sig, ...unsigned } = fx.buildEvent('role_set', { account: fx.owner.account, role: 'owner', ...(await fx.fence()) });
    const unknown = signMembershipEvent({ ...unsigned, type: 'grant_all' as never }, fx.owner.keys.signSecret);
    const res = await fx.append(unknown);
    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe('unsupported_version');
  });
});

describe('change log positions', () => {
  it('stay contiguous across accepted, conflicting and refused writes', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, v)).status).toBe(200);
    expect((await fx.write(fx.owner, id, 0, { ...v, value: 'synthetic-branch' })).status).toBe(409);
    const foreign = fx.record(fx.owner, id, 1, v);
    expect((await fx.put(fx.owner, { ...foreign, sig: b64encode(randomBytes(64)) })).status).toBe(400);
    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
    const changes = (await fx.get(fx.owner, '/changes')).json.changes as { log_seq: number }[];
    expect(changes.map((c) => c.log_seq)).toEqual([1, 2, 3]);
  });
});
