/**
 * Sealed write fallback (spec §3.6, §9.8): with no device online, `secrets_set`
 * and `secrets_delete` are sealed to the vault's current seal key and queued; a
 * device of the same account opens them. Nothing is sealed without a seal key,
 * for a reader account, while a rekey is pending, or without a named vault.
 */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { deriveSealKeyPair, openSealedOp, randomId, sealOp, type SealedOpWire } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { type TestDevice } from './helpers/api-client.js';
import { callTool, mintMcpToken, publishSealKey, structured } from './helpers/mcp-client.js';
import { readyRelay } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

async function queued(fx: VaultFixture, device: TestDevice = fx.owner): Promise<SealedOpWire[]> {
  const res = await fx.get(device, '/sealed');
  expect(res.status).toBe(200);
  return (res.json.sealed as { op: SealedOpWire }[]).map((s) => s.op);
}

function open(fx: VaultFixture, wire: SealedOpWire) {
  return openSealedOp(deriveSealKeyPair(fx.vk.get(wire.key_epoch)!, fx.vaultId, wire.key_epoch).secretKey, wire, { vaultId: fx.vaultId });
}

describe('MCP sealed write fallback', () => {
  it('seals a set and a delete to the current seal key; the account device opens them', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write', clientId: 'client-s', grantId: 'grant-s' });

    const set = await callTool(token, 'secrets_set', { name: 'API_KEY', value: 'sealed-value', sensitivity: 'high', vault_id: fx.vaultId });
    const setResult = structured(set);
    expect(set.json.result.isError).toBe(false);
    expect(setResult).toEqual({ status: 'queued', sealed_id: expect.any(String) });
    const del = structured(await callTool(token, 'secrets_delete', { name: 'OLD_KEY', vault_id: fx.vaultId }));
    expect(del.status).toBe('queued');

    const ops = await queued(fx);
    expect(ops.map((o) => o.sealed_id)).toEqual([setResult.sealed_id, del.sealed_id]);
    const opened = ops.map((w) => open(fx, w));
    expect(opened[0]!.op).toEqual({ op: 'set', name: 'API_KEY', value: 'sealed-value', sensitivity: 'high' });
    expect(opened[1]!.op).toEqual({ op: 'delete', name: 'OLD_KEY' });
    for (const o of opened) {
      expect(o.wire.origin).toEqual({ kind: 'mcp', account: fx.owner.account, client_id: 'client-s', grant_id: 'grant-s' });
      expect(o.wire.key_epoch).toBe(fx.keyEpoch);
      expect(Math.abs(o.wire.ts - Date.now())).toBeLessThan(60_000);
    }
  });

  it('seals when the online device does not offer the write tool', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const conn = await readyRelay(fx.owner, [fx.vaultId], ['search', 'list']);
    const token = await mintMcpToken({ sub: fx.owner.account });
    // The device's vault is the only one online, so vault_id may be omitted.
    expect(structured(await callTool(token, 'secrets_set', { name: 'K', value: 'v' })).status).toBe('queued');
    conn.close();
  });

  it('without vault_id and no device online the write is invalid_args and nothing is queued', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: fx.owner.account });
    const res = await callTool(token, 'secrets_set', { name: 'K', value: 'v' });
    expect(res.json.result.structuredContent.code).toBe('invalid_args');
    expect(await queued(fx)).toEqual([]);
  });

  it('without a seal key the write answers no_device_online with the sync hint', async () => {
    const fx = await VaultFixture.create();
    const token = await mintMcpToken({ sub: fx.owner.account });
    const res = await callTool(token, 'secrets_delete', { name: 'K', vault_id: fx.vaultId });
    expect(res.json.result.isError).toBe(true);
    expect(res.json.result.structuredContent.code).toBe('no_device_online');
    expect(res.json.result.structuredContent.message).toContain('ak secrets sync now');
  });

  it('never seals for a reader account', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: reader.account });
    const res = await callTool(token, 'secrets_set', { name: 'K', value: 'v', vault_id: fx.vaultId });
    expect(res.json.result.structuredContent.code).toBe('no_device_online');
    expect(await queued(fx)).toEqual([]);
  });

  it('an editor account seals; the op is served only to that account', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: editor.account });
    const res = structured(await callTool(token, 'secrets_set', { name: 'K', value: 'v', vault_id: fx.vaultId }));
    expect(res.status).toBe('queued');
    expect((await queued(fx, editor)).map((o) => o.sealed_id)).toEqual([res.sealed_id]);
    expect(await queued(fx)).toEqual([]);
  });

  it('never seals while a rekey is pending', async () => {
    const fx = await VaultFixture.create();
    const second = await fx.addDevice();
    await publishSealKey(fx);
    expect((await fx.removeDevice(second)).status).toBe(201);
    const token = await mintMcpToken({ sub: fx.owner.account });
    const res = await callTool(token, 'secrets_set', { name: 'K', value: 'v', vault_id: fx.vaultId });
    expect(res.json.result.structuredContent.code).toBe('no_device_online');
    expect(await queued(fx)).toEqual([]);
  });

  it('answers sealed_queue_full once the vault holds sealed_queue_max operations', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const stub = env.VAULT.get(env.VAULT.idFromName(fx.vaultId));
    const { publicKey } = deriveSealKeyPair(fx.vk.get(fx.keyEpoch)!, fx.vaultId, fx.keyEpoch);
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.sealed_queue_max; i++) {
      const wire = sealOp(publicKey, { vaultId: fx.vaultId, keyEpoch: fx.keyEpoch, origin: { kind: 'mcp', account: fx.owner.account, client_id: 'c', grant_id: 'g' }, ts: Date.now(), op: { op: 'delete', name: `K${i}` } });
      expect(await stub.enqueueSealed(wire)).toBe('queued');
    }
    const token = await mintMcpToken({ sub: fx.owner.account });
    const res = await callTool(token, 'secrets_delete', { name: 'K', vault_id: fx.vaultId });
    expect(res.json.result.structuredContent.code).toBe('sealed_queue_full');
  });
});
