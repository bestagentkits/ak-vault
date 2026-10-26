/**
 * `browser` (dashboard) sessions: they read and write items like any human
 * device, but never create vaults, change membership, touch the recovery
 * identity, publish seal keys, drain the sealed queue or hold a relay connection.
 */
import { describe, expect, it } from 'vitest';
import { buildSealKeyDoc, deriveSealKeyPair, randomId, sealOp } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { call, type CallOptions } from './helpers/api-client.js';
import { upgrade } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const BROWSER: CallOptions = { sessionKind: 'browser' };

describe('browser session kind', () => {
  it('cannot create a vault', async () => {
    const fx = VaultFixture.local();
    const res = await fx.putGenesis(BROWSER);
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('forbidden');
    // The refused genesis left nothing behind: the same genesis still succeeds.
    expect((await fx.putGenesis()).status).toBe(201);
  });

  it('cannot change membership or read or replace the recovery bundle', async () => {
    const fx = await VaultFixture.create();
    const device = fx.newDevice();
    const { event, wraps } = fx.enrollEvent(device);
    expect((await fx.append(event, wraps, fx.owner, BROWSER)).status).toBe(403);
    expect((await fx.append(event, wraps)).status).toBe(201);
    expect((await fx.get(fx.owner, '/recovery', BROWSER)).status).toBe(403);
    expect((await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/recovery`, { bundle: {} }, BROWSER)).status).toBe(403);
  });

  it('cannot add, remove or re-role a member or rekey a shared vault, and the chain does not move', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const seq = fx.state.seq;

    const candidate = fx.newDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const add = fx.enrollEvent(candidate);
    expect(add.event.type).toBe('member_add');
    expect((await fx.append(add.event, add.wraps, fx.owner, BROWSER)).status).toBe(403);

    const roleSet = fx.buildEvent('role_set', { account: editor.account, role: 'reader' });
    expect((await fx.append(roleSet, undefined, fx.owner, BROWSER)).status).toBe(403);

    const removal = fx.buildEvent('member_remove', { account: editor.account, ...(await fx.fence()) });
    expect((await fx.append(removal, undefined, fx.owner, BROWSER)).status).toBe(403);

    const rekey = fx.rekeyEvent();
    expect((await fx.append(rekey.event, rekey.wraps, fx.owner, BROWSER)).status).toBe(403);

    // Nothing was applied. Replaying the member_add from a CLI session succeeds, so the refusal above
    // was the session kind and not an invalid event. The later events are built on the pre-add head and
    // are not replayed; their 403s are the same route-level check.
    const log = await fx.get(fx.owner, `/membership?from=0&limit=1000`, BROWSER);
    expect(log.json.events).toHaveLength(seq + 1);
    expect((await fx.append(add.event, add.wraps)).status).toBe(201);
  });

  it('cannot publish a seal key or drain or acknowledge sealed ops', async () => {
    const fx = await VaultFixture.create();
    const doc = buildSealKeyDoc({ vk: fx.vk.get(1)!, vaultId: fx.vaultId, keyEpoch: 1, membershipSeq: fx.state.seq, author: fx.owner.keys.record.device_id, ts: Date.now() }, fx.owner.keys.signSecret);
    expect((await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/seal-key`, { seal_key: doc }, BROWSER)).status).toBe(403);
    expect((await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/seal-key`, { seal_key: doc })).status).toBe(200);

    const wire = sealOp(deriveSealKeyPair(fx.vk.get(1)!, fx.vaultId, 1).publicKey, {
      vaultId: fx.vaultId,
      keyEpoch: 1,
      origin: { kind: 'mcp', account: fx.owner.account, client_id: 'c', grant_id: 'g' },
      ts: Date.now(),
      op: { op: 'delete', name: 'A' },
    });
    expect(await env.VAULT.get(env.VAULT.idFromName(fx.vaultId)).enqueueSealed(wire)).toBe('queued');
    expect((await fx.get(fx.owner, '/sealed', BROWSER)).status).toBe(403);
    expect((await fx.post(fx.owner, `/sealed/${wire.sealed_id}/ack`, { outcome: 'applied' }, BROWSER)).status).toBe(403);
    expect((await fx.get(fx.owner, '/sealed')).json.sealed).toHaveLength(1);
  });

  it('cannot hold a relay connection', async () => {
    const fx = await VaultFixture.create();
    expect((await upgrade(fx.owner, { sessionKind: 'browser' })).status).toBe(403);
  });

  it('reads and writes items, membership, changes, seal key and lookup', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, { name: 'A', value: '1' }, BROWSER)).status).toBe(200);
    expect((await fx.get(fx.owner, `/items/${id}`, BROWSER)).status).toBe(200);
    expect((await fx.get(fx.owner, '/membership', BROWSER)).status).toBe(200);
    expect((await fx.get(fx.owner, '/changes', BROWSER)).status).toBe(200);
    expect((await fx.get(fx.owner, '/seal-key', BROWSER)).status).toBe(404); // none published, but not refused
    expect((await fx.get(fx.owner, `/lookup?tag=${'A'.repeat(22)}&key_epoch=1`, BROWSER)).status).toBe(200);
  });
});
