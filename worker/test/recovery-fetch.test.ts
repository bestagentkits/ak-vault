/**
 * Recovery bundle fetch by a device that is not (yet) in membership: allowed only
 * for the owner account, a never-removed device ID, a presented `AKV-Device-Key`
 * whose kid equals the token `did`, a proof by that key and `vault:read` scope.
 */
import { randomBytes, randomId } from '@ak-vault/protocol';
import { beforeAll, describe, expect, it } from 'vitest';
import { call, createDevice, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { putTestBundle, sealTestBundle } from './helpers/recovery-bundle.js';
import { VaultFixture } from './helpers/vault-fixture.js';

let fx: VaultFixture;

beforeAll(async () => {
  fx = await VaultFixture.create('shared');
  const put = await putTestBundle(fx, fx.owner, sealTestBundle(fx, 1));
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

describe('recovery identity is for human email-OTP sessions only', () => {
  const READS = ['/recovery', '/membership'];

  it.each(['api_key_device', 'machine'])('refuses a not-yet-enrolled %s device on both recovery reads and leaks nothing', async (kind) => {
    const fresh = createDevice(fx.owner.account, 'owner');
    for (const path of READS) {
      const res = await fx.get(fresh, path, { headers: keyHeader(fresh), sessionKind: kind });
      expect(res.status).toBe(403);
      expect(JSON.stringify(res.json)).not.toContain('bundle');
    }
  });

  it('accepts an explicit email_otp session and a token without the claim', async () => {
    const explicit = createDevice(fx.owner.account, 'owner');
    expect((await fetchBundle(explicit, { headers: keyHeader(explicit), sessionKind: 'email_otp' })).status).toBe(200);
    const legacy = createDevice(fx.owner.account, 'owner');
    expect((await fetchBundle(legacy, { headers: keyHeader(legacy) })).status).toBe(200);
  });

  it('fails closed on an unknown session kind', async () => {
    const fresh = createDevice(fx.owner.account, 'owner');
    expect((await fetchBundle(fresh, { headers: keyHeader(fresh), sessionKind: 'service' })).status).toBe(401);
  });

  it('an api_key_device session may still create a vault and read it as a member', async () => {
    const created = VaultFixture.local('personal', `acct-${randomId()}`);
    expect((await created.putGenesis({ sessionKind: 'api_key_device' })).status).toBe(201);
    expect((await created.get(created.owner, '/membership', { sessionKind: 'api_key_device' })).status).toBe(200);
  });

  it.each(['api_key_device', 'machine'])('refuses recovery enrollment by a %s session', async (kind) => {
    const recoverer = { id: fx.state.recovery_author, secret: fx.recovery.secretKey };
    const seqBefore = (await fx.get(fx.owner, '/membership')).json.membership.seq;
    const blocked = createDevice(fx.owner.account, 'owner');
    const attempt = fx.enrollEvent(blocked, [1], recoverer);
    expect((await fx.append(attempt.event, attempt.wraps, blocked, { sessionKind: kind })).status).toBe(403);
    expect((await fx.get(fx.owner, '/membership')).json.membership.seq).toBe(seqBefore);
  });

  it('accepts recovery enrollment by an email_otp session', async () => {
    const recoverer = { id: fx.state.recovery_author, secret: fx.recovery.secretKey };

    const human = createDevice(fx.owner.account, 'owner');
    const ok = fx.enrollEvent(human, [1], recoverer);
    expect((await fx.append(ok.event, ok.wraps, human, { sessionKind: 'email_otp' })).status).toBe(201);
  });

  it('a member-signed device_add approves an api_key_device, which then acts as a member under its role', async () => {
    const approved = await fx.addDevice({ account: fx.owner.account });
    expect((await fx.get(approved, `/items/${randomId()}`, { sessionKind: 'api_key_device' })).status).toBe(404);
    // Pinned: an approved owner-role device is a member and may read the bundle.
    expect((await fetchBundle(approved, { sessionKind: 'api_key_device' })).status).toBe(200);
  });
});
