/**
 * Red-team tenant and role isolation over the whole route table, not one route
 * at a time: a machine identity reading a vault it is not enrolled in (same
 * owner account), a valid token of another tenant, and reader/machine devices
 * trying every write route. Each refusal is checked to leave the vault unchanged.
 */
import { appendAuditEntry, randomId, sha256b64, signCheckpoint, type JsonObject } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call, type CallResult, type TestDevice } from './helpers/api-client.js';
import { putTestBundle, sealTestBundle } from './helpers/recovery-bundle.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'SYNTHETIC_TOKEN', value: 'synthetic-value' };
const READ_ROUTES = ['/membership', '/wraps', '/changes', '/checkpoints', '/audit', '/recovery'];

/** Every read route of `fx`, plus one item read, as `device`. */
async function readEverything(fx: VaultFixture, device: TestDevice, itemId: string): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const sub of [...READ_ROUTES, `/items/${itemId}`]) out[sub] = (await call(device, 'GET', `/v1/vaults/${fx.vaultId}${sub}`)).status;
  return out;
}

function checkpointBy(fx: VaultFixture, device: TestDevice) {
  return signCheckpoint(
    { vault_id: fx.vaultId, membership_seq: fx.state.seq, membership_head: fx.state.head, log_seq: 0, state_digest: sha256b64(new Uint8Array(1)), key_epoch: fx.keyEpoch, ts: Date.now(), author: device.keys.record.device_id },
    device.keys.signSecret,
  );
}

/** Every write route of `fx`, attempted by `device` with a well-formed body of its own. */
async function writeEverything(fx: VaultFixture, device: TestDevice, itemId: string): Promise<Record<string, CallResult>> {
  const audit = appendAuditEntry({ vk: fx.vk.get(fx.keyEpoch)!, vaultId: fx.vaultId, keyEpoch: fx.keyEpoch, head: null, event: { op: 'item.reveal' } });
  const { event, wraps } = fx.enrollEvent(fx.newDevice(), [fx.keyEpoch], { id: device.keys.record.device_id, secret: device.keys.signSecret });
  return {
    create: await fx.write(device, randomId(), 0, v),
    update: await fx.write(device, itemId, 1, v),
    tombstone: await fx.write(device, itemId, 1, null),
    checkpoint: await fx.post(device, '/checkpoints', checkpointBy(fx, device)),
    audit: await fx.post(device, '/audit', { start_seq: 0, prev: '', entries: [audit.entry as unknown as JsonObject] }),
    membership: await call(device, 'POST', `/v1/vaults/${fx.vaultId}/membership`, { event: event as unknown as JsonObject, wraps: wraps as unknown as JsonObject[] }),
    recovery: await putTestBundle(fx, device, sealTestBundle(fx, 1)),
  };
}

const statuses = (results: Record<string, CallResult>) => Object.fromEntries(Object.entries(results).map(([k, r]) => [k, r.status]));
const every = (keys: string[], status: number) => Object.fromEntries(keys.map((k) => [k, status]));

/** Server state a refused request must not move. */
async function snapshot(fx: VaultFixture) {
  const changes = await fx.get(fx.owner, '/changes');
  const membership = await fx.get(fx.owner, '/membership');
  const checkpoints = await fx.get(fx.owner, '/checkpoints');
  const audit = await fx.get(fx.owner, '/audit');
  return { head: changes.json.head, events: membership.json.events.length, checkpoints: checkpoints.json.checkpoints.length, audit: audit.json, recovery: (await fx.get(fx.owner, '/recovery')).status };
}

describe('red team: machine identity outside its vault', () => {
  it('a machine enrolled in one vault of an account cannot read or write another vault of that account', async () => {
    const enrolled = await VaultFixture.create();
    const other = await VaultFixture.create('personal', enrolled.owner.account);
    const machine = await enrolled.addDevice({ kind: 'machine' });
    const itemId = randomId();
    expect((await other.write(other.owner, itemId, 0, v)).status).toBe(200);
    expect((await enrolled.write(enrolled.owner, itemId, 0, v)).status).toBe(200);

    // Without a presented key the recovery route treats it as an unauthenticated recovery identity (401).
    expect(await readEverything(other, machine, itemId)).toEqual({ ...every([...READ_ROUTES, `/items/${itemId}`], 403), '/recovery': 401 });
    const before = await snapshot(other);
    expect(statuses(await writeEverything(other, machine, itemId))).toEqual(every(['create', 'update', 'tombstone', 'checkpoint', 'audit', 'membership', 'recovery'], 403));
    expect(await snapshot(other)).toEqual(before);

    // Documented limitation (threat model, "Recovery bundle ciphertext"): any owner-account
    // token plus a key it holds can take the recovery-identity path. A machine device of the
    // owner account therefore fetches the other vault's encrypted bundle and membership log,
    // and nothing else. Tracked for machine identities in the red-team evidence.
    expect((await putTestBundle(other, other.owner, sealTestBundle(other, 1))).status).toBe(200);
    const presented = { headers: { 'AKV-Device-Key': machine.keys.record.sign_pub } };
    const asRecovery: Record<string, number> = {};
    for (const sub of [...READ_ROUTES, `/items/${itemId}`]) asRecovery[sub] = (await other.get(machine, sub, presented)).status;
    expect(asRecovery).toEqual({ ...every([...READ_ROUTES, `/items/${itemId}`], 403), '/recovery': 200, '/membership': 200 });

    // In its own vault it reads (recovery stays owner-human only).
    const own = await readEverything(enrolled, machine, itemId);
    expect(own).toEqual({ ...every([...READ_ROUTES, `/items/${itemId}`], 200), '/recovery': 403 });
  });
});

describe('red team: cross-tenant token', () => {
  it("a valid token and proof of another tenant's device is refused on every route", async () => {
    const victim = await VaultFixture.create('shared');
    const tenant = await VaultFixture.create('shared');
    const itemId = randomId();
    expect((await victim.write(victim.owner, itemId, 0, v)).status).toBe(200);

    expect(await readEverything(victim, tenant.owner, itemId)).toEqual(every([...READ_ROUTES, `/items/${itemId}`], 403));
    const before = await snapshot(victim);
    const writes = statuses(await writeEverything(victim, tenant.owner, itemId));
    expect(writes).toEqual(every(['create', 'update', 'tombstone', 'checkpoint', 'audit', 'membership', 'recovery'], 403));
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
      expect(statuses(results)).toEqual(every(['create', 'update', 'tombstone', 'checkpoint', 'audit', 'membership', 'recovery'], 403));
      for (const r of Object.values(results)) expect(r.json.error.code).toBe('forbidden');
    }
    expect(await snapshot(fx)).toEqual(before);
    // Both still read the item.
    expect((await fx.get(reader, `/items/${itemId}`)).status).toBe(200);
    expect((await fx.get(machine, `/items/${itemId}`)).status).toBe(200);
  });
});
