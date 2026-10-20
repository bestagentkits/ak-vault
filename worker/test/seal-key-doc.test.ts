/** Seal-key documents: owner publish, any-device fetch, replacement rules and the MCP RPC view. */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { buildSealKeyDoc, randomBytes, randomId, type SealKeyDoc } from '@ak-vault/protocol';
import { call as rawCall, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

function sealDoc(fx: VaultFixture, author: TestDevice = fx.owner, overrides: { keyEpoch?: number; membershipSeq?: number; vaultId?: string; vk?: Uint8Array } = {}): SealKeyDoc {
  const keyEpoch = overrides.keyEpoch ?? fx.keyEpoch;
  return buildSealKeyDoc(
    {
      vk: overrides.vk ?? fx.vk.get(keyEpoch) ?? randomBytes(32),
      vaultId: overrides.vaultId ?? fx.vaultId,
      keyEpoch,
      membershipSeq: overrides.membershipSeq ?? fx.state.seq,
      author: author.keys.record.device_id,
      ts: Date.now(),
    },
    author.keys.signSecret,
  );
}

/** A request to `/v1/vaults/{vid}{sub}` (the fixture only has GET/POST/item-PUT helpers). */
function call(fx: VaultFixture, device: TestDevice, method: string, sub: string, body?: unknown, opts: CallOptions = {}) {
  return rawCall(device, method, `/v1/vaults/${fx.vaultId}${sub}`, body, opts);
}

describe('seal-key document', () => {
  it('an owner device publishes it and every device of the vault fetches it', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const machine = await fx.addDevice({ kind: 'machine' });
    expect((await fx.get(fx.owner, '/seal-key')).status).toBe(404);

    const doc = sealDoc(fx);
    const res = await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: doc });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ key_epoch: 1, membership_seq: fx.state.seq });
    for (const device of [fx.owner, reader, machine]) {
      const got = await fx.get(device, '/seal-key');
      expect(got.status).toBe(200);
      expect(got.json).toEqual({ seal_key: doc });
    }
  });

  it('only a human owner device that authored the document may publish it', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const ownerMachine = await fx.addDevice({ kind: 'machine' });
    const ownerLaptop = await fx.addDevice();
    expect((await call(fx, editor, 'PUT', '/seal-key', { seal_key: sealDoc(fx, editor) })).json.error.code).toBe('forbidden');
    expect((await call(fx, ownerMachine, 'PUT', '/seal-key', { seal_key: sealDoc(fx, ownerMachine) })).json.error.code).toBe('forbidden');
    // Signed by one owner device, uploaded by another.
    const res = await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: sealDoc(fx, ownerLaptop) });
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('forbidden');
    // An outsider's vault is not reachable.
    const other = await VaultFixture.create();
    expect((await call(fx, other.owner, 'PUT', '/seal-key', { seal_key: sealDoc(fx, other.owner) })).status).toBe(403);
  });

  it('refuses a document for another vault, a past epoch, a chain position ahead of the vault, or a bad signature', async () => {
    const fx = await VaultFixture.create();
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: sealDoc(fx, fx.owner, { vaultId: randomId() }) })).json.error.code).toBe('bad_request');
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: sealDoc(fx, fx.owner, { membershipSeq: fx.state.seq + 5 }) })).json.error.code).toBe('bad_request');
    const forged = { ...sealDoc(fx), seal_pub: sealDoc(fx, fx.owner, { vk: randomBytes(32) }).seal_pub };
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: forged })).status).toBeGreaterThanOrEqual(400);
    const epochOne = sealDoc(fx);
    expect((await fx.rekey()).status).toBe(201);
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: epochOne })).json.error.code).toBe('bad_request');
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: sealDoc(fx) })).status).toBe(200);
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: sealDoc(fx), extra: 1 })).json.error.code).toBe('bad_request');
  });

  it('keeps the newest chain position for an epoch: an older membership_seq is 409', async () => {
    const fx = await VaultFixture.create();
    const early = sealDoc(fx);
    await fx.addDevice();
    const later = sealDoc(fx);
    expect(later.membership_seq).toBeGreaterThan(early.membership_seq);
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: later })).status).toBe(200);
    const stale = await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: early });
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe('conflict');
    expect((await fx.get(fx.owner, '/seal-key')).json.seal_key).toEqual(later);
  });

  it('a mutation without Idempotency-Key is refused and a retry replays', async () => {
    const fx = await VaultFixture.create();
    const doc = sealDoc(fx);
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: doc }, { idempotencyKey: null })).status).toBe(400);
    const key = randomId();
    const first = await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: doc }, { idempotencyKey: key });
    const again = await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: doc }, { idempotencyKey: key });
    expect(first.status).toBe(200);
    expect(again.status).toBe(200);
    expect(again.json).toEqual(first.json);
  });

  it('the getSealKey RPC serves the current epoch document, and none while a rekey is required', async () => {
    const fx = await VaultFixture.create();
    const stub = env.VAULT.get(env.VAULT.idFromName(fx.vaultId));
    expect(await stub.getSealKey()).toBeNull();
    const device = await fx.addDevice();
    const doc = sealDoc(fx);
    expect((await call(fx, fx.owner, 'PUT', '/seal-key', { seal_key: doc })).status).toBe(200);
    expect(await stub.getSealKey()).toEqual(doc);
    expect((await fx.removeDevice(device)).status).toBe(201);
    expect(await stub.getSealKey()).toBeNull();
    expect(await env.VAULT.get(env.VAULT.idFromName(randomId())).getSealKey()).toBeNull();
  });
});
