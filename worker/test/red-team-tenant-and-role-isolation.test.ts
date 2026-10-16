/**
 * Red-team tenant and role isolation over the whole route table, not one route
 * at a time: a machine identity reading a vault it is not enrolled in (same
 * owner account), a valid token of another tenant, and reader/machine devices
 * trying every write route. Each refusal is checked to leave the vault unchanged.
 */
import { b64encode, buildGenesisEvent, randomBytes, randomId, wrapsDigest, wrapToDevice, type JsonObject } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call } from './helpers/api-client.js';
import { putTestBundle, sealTestBundle } from './helpers/recovery-bundle.js';
import { codes, every, READ_ROUTES, readEverything, snapshot, statuses, WRITE_ROUTES, writeEverything } from './helpers/red-team-routes.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'SYNTHETIC_TOKEN', value: 'synthetic-value' };

describe('red team: machine identity outside its vault', () => {
  it('a machine enrolled in one vault of an account cannot read or write another vault of that account', async () => {
    const enrolled = await VaultFixture.create();
    const other = await VaultFixture.create('personal', enrolled.owner.account);
    const machine = await enrolled.addDevice({ kind: 'machine' });
    const itemId = randomId();
    const reads = [...READ_ROUTES, `/items/${itemId}`];
    expect((await other.write(other.owner, itemId, 0, v)).status).toBe(200);
    expect((await enrolled.write(enrolled.owner, itemId, 0, v)).status).toBe(200);

    // Without a presented key the recovery route treats it as an unauthenticated recovery identity (401).
    expect(statuses(await readEverything(other, machine, itemId))).toEqual({ ...every(reads, 403), '/recovery': 401 });
    const before = await snapshot(other);
    expect(statuses(await writeEverything(other, machine, itemId))).toEqual(every(WRITE_ROUTES, 403));
    expect(await snapshot(other)).toEqual(before);

    // #42: a machine session is marked `session_kind: machine` in its vault token, and the
    // recovery-identity path refuses it, so it fetches neither the other vault's encrypted
    // bundle nor its membership log. A token without the claim is a legacy email-OTP session.
    expect((await putTestBundle(other, other.owner, sealTestBundle(other, 1))).status).toBe(200);
    const presented = { headers: { 'AKV-Device-Key': machine.keys.record.sign_pub } };
    const marked = { ...presented, sessionKind: 'machine' };
    expect(statuses(await readEverything(other, machine, itemId, marked))).toEqual(every(reads, 403));
    expect(statuses(await readEverything(other, machine, itemId, presented))).toEqual({ ...every(reads, 403), '/recovery': 200, '/membership': 200 });

    // In its own vault it reads (recovery stays owner-human only).
    expect(statuses(await readEverything(enrolled, machine, itemId))).toEqual({ ...every(reads, 200), '/recovery': 403 });
  });
});

describe('red team: cross-tenant token', () => {
  it("a valid token and proof of another tenant's device is refused on every route, genesis included", async () => {
    const victim = await VaultFixture.create('shared');
    const tenant = await VaultFixture.create('shared');
    const itemId = randomId();
    expect((await victim.write(victim.owner, itemId, 0, v)).status).toBe(200);

    expect(statuses(await readEverything(victim, tenant.owner, itemId))).toEqual(every([...READ_ROUTES, `/items/${itemId}`], 403));
    const before = await snapshot(victim);
    expect(statuses(await writeEverything(victim, tenant.owner, itemId))).toEqual(every(WRITE_ROUTES, 403));

    // A well-formed genesis for the victim's vault ID, authored and signed by the other tenant.
    const wraps = [wrapToDevice({ vk: randomBytes(32), vaultId: victim.vaultId, keyEpoch: 1, recipient: tenant.owner.keys.record })];
    const genesis = buildGenesisEvent(
      {
        vault_id: victim.vaultId,
        ts: Date.now(),
        author: tenant.owner.keys.record.device_id,
        body: { vault_kind: 'shared', owner_account: tenant.owner.account, recovery_sign_pub: b64encode(tenant.recovery.publicKey), devices: [tenant.owner.keys.record as unknown as JsonObject], wraps_digest: wrapsDigest(wraps) },
      },
      tenant.owner.keys.signSecret,
    );
    const takeover = await call(tenant.owner, 'PUT', `/v1/vaults/${victim.vaultId}`, { event: genesis as unknown as JsonObject, wraps: wraps as unknown as JsonObject[] });
    expect([takeover.status, takeover.json.error.code]).toEqual([409, 'conflict']);

    expect(await snapshot(victim)).toEqual(before);
  });
});

describe('red team: read-only identities', () => {
  it('reader and machine devices are refused on every write route and the vault does not move', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const machine = await fx.addDevice({ kind: 'machine' });
    const itemId = randomId();
    expect((await fx.write(fx.owner, itemId, 0, v)).status).toBe(200);
    const before = await snapshot(fx);
    for (const device of [reader, machine]) {
      const results = await writeEverything(fx, device, itemId);
      expect(statuses(results)).toEqual(every(WRITE_ROUTES, 403));
      expect(codes(results)).toEqual(every(WRITE_ROUTES, 'forbidden'));
    }
    expect(await snapshot(fx)).toEqual(before);
    // Both still read the item.
    expect((await fx.get(reader, `/items/${itemId}`)).status).toBe(200);
    expect((await fx.get(machine, `/items/${itemId}`)).status).toBe(200);
  });
});
