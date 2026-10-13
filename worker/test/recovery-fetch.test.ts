/**
 * Recovery bundle fetch by a device that is not (yet) in membership: allowed only
 * for the owner account, a never-removed device ID, a presented `AKV-Device-Key`
 * whose kid equals the token `did`, a proof by that key and `vault:read` scope.
 */
import { randomBytes, randomId } from '@ak-vault/protocol';
import { beforeAll, describe, expect, it } from 'vitest';
import { call, createDevice, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { sealTestBundle } from './helpers/recovery-bundle.js';
import { VaultFixture } from './helpers/vault-fixture.js';

let fx: VaultFixture;

beforeAll(async () => {
  fx = await VaultFixture.create('shared');
  const put = await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/recovery`, sealTestBundle(fx, 1));
  if (put.status !== 200) throw new Error(`bundle upload failed: ${put.status}`);
});

const keyHeader = (device: TestDevice) => ({ 'AKV-Device-Key': device.keys.record.sign_pub });
const fetchBundle = (device: TestDevice, opts: CallOptions = {}) => fx.get(device, '/recovery', opts);

describe('recovery fetch by a not-yet-enrolled device', () => {
  it('serves the bundle to a fresh owner-account device that proves its presented key', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    const res = await fetchBundle(fresh, { headers: keyHeader(fresh) });
    expect(res.status).toBe(200);
    expect(res.json.bundle.vault_id).toBe(fx.vaultId);
  });

  it('refuses another account, even with a valid key and proof', async () => {
    const stranger = createDevice(`acct-${randomId()}`, 'owner');
    expect((await fetchBundle(stranger, { headers: keyHeader(stranger) })).status).toBe(403);
  });

  it('refuses a presented key whose kid is not the token did', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    const other = createDevice(fx.owner.account, 'owner');
    const res = await fetchBundle(fresh, { headers: keyHeader(other) });
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe('unauthorized');
  });

  it('refuses a missing or malformed AKV-Device-Key header', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    expect((await fetchBundle(fresh)).status).toBe(401);
    expect((await fetchBundle(fresh, { headers: { 'AKV-Device-Key': `${fresh.keys.record.sign_pub}=` } })).status).toBe(401);
    expect((await fetchBundle(fresh, { headers: { 'AKV-Device-Key': 'not base64url!' } })).status).toBe(401);
  });

  it('refuses a proof not signed by the presented key', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    const res = await fetchBundle(fresh, { headers: keyHeader(fresh), proofSecret: randomBytes(32) });
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe('invalid_signature');
  });

  it('refuses a replayed proof jti', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    const first = await fetchBundle(fresh, { headers: keyHeader(fresh) });
    expect(first.status).toBe(200);
    expect((await fetchBundle(fresh, { headers: keyHeader(fresh), token: first.token, proof: first.proof })).status).toBe(401);
  });

  it('requires vault:read scope', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    expect((await fetchBundle(fresh, { headers: keyHeader(fresh), scope: 'vault:write' })).status).toBe(403);
  });

  it('current devices keep the role check: a non-owner member is refused, header or not', async () => {
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await fetchBundle(editor)).status).toBe(403);
    expect((await fetchBundle(editor, { headers: keyHeader(editor) })).status).toBe(403);
    // A device of another member's account presenting a fresh key is not the owner account.
    const editorFresh = createDevice(editor.account, 'editor');
    expect((await fetchBundle(editorFresh, { headers: keyHeader(editorFresh) })).status).toBe(403);
    expect((await fetchBundle(fx.owner)).status).toBe(200);
  });

  it('a token for the owner account naming a did that is not kid(sign_pub) of any presented key is refused', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    const token = await mintToken({ sub: fx.owner.account, did: createDevice(fx.owner.account).keys.record.device_id });
    expect((await fetchBundle(fresh, { headers: keyHeader(fresh), token })).status).toBe(401);
  });

  it('a removed device cannot use this path', async () => {
    const laptop = await fx.addDevice();
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await fetchBundle(laptop, { headers: keyHeader(laptop) })).status).toBe(403);
  });
});
