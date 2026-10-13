/** Genesis, owner-signed membership appends, injected recipients, removal and rekey. */
import { b64encode, createDeviceKeys, randomBytes, randomId, signMembershipEvent, wrapToDevice, type JsonObject } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call, createDevice } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const item = () => randomId();

describe('genesis', () => {
  it('creates a vault and replays a retried request from the idempotency store', async () => {
    const fx = VaultFixture.local();
    const key = randomId();
    const first = await fx.putGenesis({ idempotencyKey: key });
    expect(first.status).toBe(201);
    expect(first.json.membership).toMatchObject({ seq: 0, key_epoch: 1, rekey_required: false });
    const retry = await fx.putGenesis({ idempotencyKey: key });
    expect(retry.status).toBe(201);
    expect(retry.json).toEqual(first.json);
    expect(retry.headers.get('Idempotent-Replayed')).toBe('true');
  });

  it('refuses a second genesis for an existing vault', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.putGenesis()).status).toBe(409);
  });

  it('requires the token subject to be the owner account and did the genesis author', async () => {
    const fx = VaultFixture.local();
    const wrongSub = await fx.putGenesis({ token: await mintToken({ sub: 'someone-else', did: fx.owner.keys.record.device_id }) });
    expect(wrongSub.status).toBe(403);
    const other = createDevice(fx.owner.account);
    const wrongDid = await call(other, 'PUT', `/v1/vaults/${fx.vaultId}`, fx.genesisBody());
    expect(wrongDid.status).toBe(403);
    expect((await fx.putGenesis({ scope: 'vault:read' })).status).toBe(403);
  });

  it('rejects a tampered genesis signature and a path/vault mismatch', async () => {
    const fx = VaultFixture.local();
    const body = fx.genesisBody();
    const ev = { ...(body['event'] as JsonObject), ts: 1 };
    expect((await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}`, { ...body, event: ev })).json.error.code).toBe('invalid_signature');
    expect((await call(fx.owner, 'PUT', `/v1/vaults/${randomId()}`, body)).status).toBe(400);
  });

  it('requires an Idempotency-Key on mutations', async () => {
    const fx = VaultFixture.local();
    const res = await fx.putGenesis({ idempotencyKey: null });
    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe('bad_request');
  });
});

describe('membership appends', () => {
  it('accepts an owner-signed device_add with a wrap and serves the chain', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const res = await fx.get(laptop, '/membership');
    expect(res.status).toBe(200);
    expect(res.json.events).toHaveLength(2);
    expect(res.json.membership.seq).toBe(1);
    const wraps = await fx.get(laptop, `/wraps?rcpt=${laptop.keys.record.device_id}`);
    expect(wraps.json.wraps).toHaveLength(1);
  });

  it('rejects a bad signature, wrong prev and a stale (already superseded) event', async () => {
    const fx = await VaultFixture.create();
    const dev = createDevice(fx.owner.account).keys.record as unknown as JsonObject;
    const ev = fx.buildEvent('device_add', { device: dev, sas: b64encode(randomBytes(32)) });
    const badSig = await fx.append({ ...ev, sig: b64encode(randomBytes(64)) });
    expect(badSig.json.error.code).toBe('invalid_signature');
    const { sig: _sig, ...unsigned } = ev;
    const wrongPrev = signMembershipEvent({ ...unsigned, prev: b64encode(randomBytes(32)) }, fx.owner.keys.signSecret);
    expect((await fx.append(wrongPrev)).json.error.code).toBe('bad_request');
    await fx.addDevice();
    const stale = await call(fx.owner, 'POST', `/v1/vaults/${fx.vaultId}/membership`, { event: ev });
    expect(stale.status).toBe(400);
  });

  it('rejects events authored by a non-owner device', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const ev = fx.buildEvent('device_add', { device: createDevice(editor.account, 'editor').keys.record as unknown as JsonObject, sas: b64encode(randomBytes(32)) }, { id: editor.keys.record.device_id, secret: editor.keys.signSecret });
    expect((await fx.append(ev, undefined, editor)).status).toBe(403);
    expect((await fx.append(ev)).status).toBe(403);
  });

  it('refuses an injected wrap recipient (device no owner-signed event added)', async () => {
    const fx = await VaultFixture.create();
    const intruder = createDeviceKeys({ account: fx.owner.account, role: 'owner', kind: 'human' });
    const wrap = wrapToDevice({ vk: fx.vk.get(1)!, vaultId: fx.vaultId, keyEpoch: 1, recipient: intruder.record });
    const res = await fx.post(fx.owner, '/wraps', { wraps: [wrap] });
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('forbidden');
    const viaEvent = await fx.append(fx.buildEvent('device_add', { device: createDevice(fx.owner.account).keys.record as unknown as JsonObject, sas: b64encode(randomBytes(32)) }), [wrap]);
    expect(viaEvent.status).toBe(403);
  });

  it('a removed device is denied and writes wait for rekey', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.write(laptop, item(), 0, { name: 'a', value: 'b' })).status).toBe(200);
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await fx.get(laptop, '/changes')).status).toBe(403);
    const blocked = await fx.write(fx.owner, item(), 0, { name: 'a', value: 'b' });
    expect(blocked.status).toBe(409);
    expect(blocked.json.error.code).toBe('rekey_required');
    // Old-epoch writes stay refused after the rekey (stale key_epoch).
    const stale = fx.record(fx.owner, item(), 0, { name: 'a', value: 'b' });
    expect((await fx.rekey()).status).toBe(201);
    expect((await fx.put(fx.owner, stale)).json.error.code).toBe('bad_request');
    expect((await fx.write(fx.owner, item(), 0, { name: 'a', value: 'b' })).status).toBe(200);
  });

  it('a rekey must carry a complete wrap set matching wraps_digest', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    await fx.removeDevice(laptop);
    const { event, wraps } = fx.rekeyEvent();
    expect((await fx.append(event)).status).toBe(400);
    expect((await fx.append(event, [])).status).toBe(400);
    const swapped = wrapToDevice({ vk: randomBytes(32), vaultId: fx.vaultId, keyEpoch: 2, recipient: fx.owner.keys.record });
    expect((await fx.append(event, [swapped])).status).toBe(400);
    expect((await fx.append(event, wraps)).status).toBe(201);
    expect(fx.state.rekey_required).toBe(false);
  });

  it('a fresh device enrolls itself with a recovery-key-signed device_add', async () => {
    const fx = await VaultFixture.create();
    const fresh = createDevice(fx.owner.account, 'owner');
    const event = fx.buildEvent('device_add', { device: fresh.keys.record as unknown as JsonObject, sas: '' }, { id: fx.recoveryAuthorId(), secret: fx.recovery.secretKey });
    const res = await fx.append(event, [fx.wrapFor(fresh)], fresh);
    expect(res.status).toBe(201);
    expect((await fx.get(fresh, '/wraps')).status).toBe(200);
    // The same path cannot add a device for somebody else's account.
    const other = createDevice(`acct-${randomId()}`, 'owner');
    const bad = fx.buildEvent('device_add', { device: createDevice(fx.owner.account, 'owner').keys.record as unknown as JsonObject, sas: '' }, { id: fx.recoveryAuthorId(), secret: fx.recovery.secretKey });
    expect((await fx.append(bad, undefined, other)).status).toBe(403);
  });

  it('pages membership events', async () => {
    const fx = await VaultFixture.create();
    await fx.addDevice();
    await fx.addDevice();
    const page = await fx.get(fx.owner, '/membership?from=1&limit=1');
    expect(page.json.events).toHaveLength(1);
    expect(page.json.events[0].seq).toBe(1);
    expect(page.json.has_more).toBe(true);
    expect((await fx.get(fx.owner, '/membership?limit=abc')).status).toBe(400);
  });
});
