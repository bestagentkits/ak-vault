/** Role, scope, tenant and owner-only enforcement (spec §4, §8, §11). */
import { randomBytes, randomId, sha256b64, type JsonObject } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call, createDevice } from './helpers/api-client.js';
import { sealTestBundle } from './helpers/recovery-bundle.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const v = { name: 'DB_PASSWORD', value: 'synthetic' };

describe('read-only devices', () => {
  it('a reader in a shared vault can pull but not write', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const id = randomId();
    await fx.write(fx.owner, id, 0, v);
    expect((await fx.get(reader, `/items/${id}`)).status).toBe(200);
    expect((await fx.get(reader, '/changes')).status).toBe(200);
    const write = await fx.write(reader, id, 1, v);
    expect(write.status).toBe(403);
    expect(write.json.error.code).toBe('forbidden');
  });

  it('a machine device can read but never write, even on an owner account', async () => {
    const fx = await VaultFixture.create();
    const machine = await fx.addDevice({ kind: 'machine' });
    const id = randomId();
    await fx.write(fx.owner, id, 0, v);
    expect((await fx.get(machine, `/items/${id}`)).status).toBe(200);
    expect((await fx.write(machine, id, 1, v)).status).toBe(403);
    expect((await fx.write(machine, randomId(), 0, v)).status).toBe(403);
    const { event, wraps } = fx.enrollEvent(fx.newDevice());
    expect((await fx.append(event, wraps, machine)).status).toBe(403);
    expect((await fx.get(machine, '/recovery')).status).toBe(403);
  });

  it('a machine cannot sign membership changes', async () => {
    const fx = await VaultFixture.create();
    const machine = await fx.addDevice({ kind: 'machine' });
    const event = fx.buildEvent('device_add', { device: createDevice(fx.owner.account).keys.record as unknown as JsonObject, sas: sha256b64(randomBytes(8)) }, { id: machine.keys.record.device_id, secret: machine.keys.signSecret });
    expect((await fx.append(event, undefined, machine)).status).toBe(403);
  });
});

describe('scope and tenant isolation', () => {
  it('a read-only token cannot write and a write-only token cannot read', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.write(fx.owner, randomId(), 0, v, { scope: 'vault:read' })).status).toBe(403);
    expect((await fx.get(fx.owner, '/changes', { scope: 'vault:write' })).status).toBe(403);
  });

  it("another tenant's device cannot touch a vault it does not belong to", async () => {
    const a = await VaultFixture.create();
    const b = await VaultFixture.create();
    const id = randomId();
    await a.write(a.owner, id, 0, v);
    expect((await call(b.owner, 'GET', `/v1/vaults/${a.vaultId}/items/${id}`)).status).toBe(403);
    expect((await call(b.owner, 'GET', `/v1/vaults/${a.vaultId}/changes`)).status).toBe(403);
    expect((await call(b.owner, 'PUT', `/v1/vaults/${a.vaultId}/items/${id}`, b.record(b.owner, id, 1, v))).status).toBe(403);
  });

  it("a device presenting another account's sub is refused", async () => {
    const fx = await VaultFixture.create();
    const imposter = { ...fx.owner, account: `acct-${randomId()}` };
    expect((await fx.get(imposter, '/changes')).status).toBe(403);
  });

  it('a removed device loses access immediately', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await fx.get(laptop, '/changes')).status).toBe(403);
  });

  it('wraps are accepted only inside a signed event: there is no standalone wrap upload', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    for (const device of [fx.owner, editor]) {
      const res = await fx.post(device, '/wraps', { wraps: [fx.wrapFor(editor)] });
      expect(res.status).toBe(404);
    }
    expect((await fx.write(editor, randomId(), 0, v)).status).toBe(200);
  });
});

describe('recovery bundle', () => {
  const bundle = sealTestBundle;
  const put = (fx: VaultFixture, device: VaultFixture['owner'], body: unknown) => call(device, 'PUT', `/v1/vaults/${fx.vaultId}/recovery`, body);

  it('owner stores and fetches it; bundle_seq must increase', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.get(fx.owner, '/recovery')).status).toBe(404);
    const b1 = bundle(fx, 1);
    expect((await put(fx, fx.owner, b1)).status).toBe(200);
    expect((await fx.get(fx.owner, '/recovery')).json.bundle).toEqual(b1);
    const again = await put(fx, fx.owner, bundle(fx, 1));
    expect(again.json.error.code).toBe('conflict');
    expect((await put(fx, fx.owner, bundle(fx, 3))).status).toBe(200);
    const back = await put(fx, fx.owner, b1);
    expect(back.status).toBe(409);
    expect(back.json.error.code).toBe('rollback');
  });

  it('non-owners cannot read or replace it, and a bundle for another vault is refused', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await put(fx, editor, bundle(fx, 1))).status).toBe(403);
    expect((await fx.get(editor, '/recovery')).status).toBe(403);
    const other = VaultFixture.local();
    expect((await put(fx, fx.owner, bundle(other, 1))).status).toBe(400);
    expect((await put(fx, fx.owner, { v: 1, vault_id: fx.vaultId })).status).toBe(400);
  });
});
