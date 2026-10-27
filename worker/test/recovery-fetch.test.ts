/**
 * Recovery bundle fetch by a device that is not (yet) in membership: allowed only
 * for the owner account, a never-removed device ID, a presented `AKV-Device-Key`
 * whose kid equals the token `did`, a proof by that key and `vault:read` scope.
 */
import { b64encode, randomBytes, randomId, signKeyPairFromSeed, type JsonObject } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { ApiError } from '../src/http/errors.js';
import { putRecovery } from '../src/vault/recovery-store.js';
import { beforeAll, describe, expect, it } from 'vitest';
import { call, createDevice, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { putTestBundle, sealTestBundle } from './helpers/recovery-bundle.js';
import { signerOf, VaultFixture } from './helpers/vault-fixture.js';

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
  });
});

describe('recovery operations by members need an email_otp session, whatever the role', () => {
  const rotateEvent = (vault: VaultFixture, by: TestDevice) => {
    const rotated = signKeyPairFromSeed(randomBytes(32));
    const event = vault.buildEvent('recovery_rotate', { recovery_sign_pub: b64encode(rotated.publicKey) }, signerOf(by));
    return { event, bundle: sealTestBundle(vault, 2, undefined, rotated.secretKey) as never };
  };

  it.each(['api_key_device', 'machine'])('refuses an owner-role %s session on GET /recovery, PUT /recovery and recovery_rotate', async (kind) => {
    const vault = await VaultFixture.create();
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 1))).status).toBe(200);
    const device = await vault.addDevice({ account: vault.owner.account, role: 'owner' });
    const opts = { sessionKind: kind };

    const read = await vault.get(device, '/recovery', opts);
    expect(read.status).toBe(403);
    expect(read.json.error.code).toBe('forbidden');
    expect(JSON.stringify(read.json)).not.toContain('bundle');
    // Presenting its own key does not turn a member into the recovery identity.
    expect((await vault.get(device, '/recovery', { ...opts, headers: keyHeader(device) })).status).toBe(403);

    const put = await putTestBundle(vault, device, sealTestBundle(vault, 2), vault.state.seq, opts);
    expect(put.status).toBe(403);
    expect(put.json.error.code).toBe('forbidden');

    const seqBefore = vault.state.seq;
    const rotate = rotateEvent(vault, device);
    const refused = await vault.append(rotate.event, undefined, device, opts, { bundle: rotate.bundle });
    expect(refused.status).toBe(403);
    expect(refused.json.error.code).toBe('forbidden');

    // Nothing changed: the chain did not advance and the stored bundle is still seq 1.
    expect((await vault.get(vault.owner, '/membership')).json.membership.seq).toBe(seqBefore);
    expect((await vault.get(vault.owner, '/recovery')).json.bundle.bundle_seq).toBe(1);
    // The device stays a normal member for items.
    const id = randomId();
    expect((await vault.write(device, id, 0, { name: 'A', value: 'synthetic' }, opts)).status).toBe(200);
    expect((await vault.get(device, `/items/${id}`, opts)).status).toBe(200);
  });

  it.each([['email_otp', { sessionKind: 'email_otp' }], ['a token without session_kind', {}]] as const)(
    'an owner-role device with %s performs all three recovery operations',
    async (_label, opts) => {
      const vault = await VaultFixture.create();
      const device = await vault.addDevice({ account: vault.owner.account, role: 'owner' });
      expect((await putTestBundle(vault, device, sealTestBundle(vault, 1), vault.state.seq, opts)).status).toBe(200);
      expect((await vault.get(device, '/recovery', opts)).json.bundle.bundle_seq).toBe(1);
      const rotate = rotateEvent(vault, device);
      const ok = await vault.append(rotate.event, undefined, device, opts, { bundle: rotate.bundle });
      expect(ok.status).toBe(201);
      expect(ok.json.bundle_seq).toBe(2);
    },
  );

  it.each(['api_key_device', 'machine'])('refuses a %s recovery_rotate without a bundle as forbidden, not as a malformed rotation', async (kind) => {
    const vault = await VaultFixture.create();
    const device = await vault.addDevice({ account: vault.owner.account, role: 'owner' });
    const { event } = rotateEvent(vault, device);
    const res = await vault.append(event, undefined, device, { sessionKind: kind });
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('forbidden');
    // An email_otp session reaches the mutation step, which requires the resealed bundle.
    expect((await vault.append(event, undefined, device)).status).toBe(400);
  });

  it.each(['api_key_device', 'machine'])('refuses a %s session before checking its proof', async (kind) => {
    const vault = await VaultFixture.create();
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 1))).status).toBe(200);
    const device = await vault.addDevice({ account: vault.owner.account, role: 'owner' });
    const opts = { sessionKind: kind, proofSecret: randomBytes(32) };
    expect((await vault.get(device, '/recovery', opts)).status).toBe(403);
    expect((await putTestBundle(vault, device, sealTestBundle(vault, 2), vault.state.seq, opts)).status).toBe(403);
    const rotate = rotateEvent(vault, device);
    expect((await vault.append(rotate.event, undefined, device, opts, { bundle: rotate.bundle })).status).toBe(403);
    // The same bad proof on a route that is not a recovery operation fails the proof check.
    expect((await vault.get(device, '/membership', opts)).status).toBe(401);
  });

  it.each(['api_key_device', 'machine'])('refuses a %s session that sends a bundle on any membership event', async (kind) => {
    const vault = await VaultFixture.create();
    const device = await vault.addDevice({ account: vault.owner.account, role: 'owner' });
    const { event, wraps } = vault.enrollEvent(vault.newDevice(), undefined, signerOf(device));
    const res = await vault.append(event, wraps, device, { sessionKind: kind }, { bundle: sealTestBundle(vault, 1) as never });
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('forbidden');
    // The same body from an email_otp session reaches the mutation step, which refuses a stray bundle.
    expect((await vault.append(event, wraps, device, {}, { bundle: sealTestBundle(vault, 1) as never })).status).toBe(400);
  });

  it.each(['api_key_device', 'machine'])('a %s session may still append other membership events as an owner', async (kind) => {
    const vault = await VaultFixture.create();
    const device = await vault.addDevice({ account: vault.owner.account, role: 'owner' });
    const added = vault.newDevice();
    const { event, wraps } = vault.enrollEvent(added, undefined, signerOf(device));
    expect((await vault.append(event, wraps, device, { sessionKind: kind })).status).toBe(201);
  });
});

describe('genesis seal: a non-human session may store the first bundle of a vault, nothing more', () => {
  it.each(['api_key_device', 'machine'])('a vault created by a %s session gets its first bundle; read, replace and rotate stay refused', async (kind) => {
    const opts = { sessionKind: kind };
    const vault = VaultFixture.local('personal', `acct-${randomId()}`);
    expect((await vault.putGenesis(opts)).status).toBe(201);

    const sealed = await putTestBundle(vault, vault.owner, sealTestBundle(vault, 1), vault.state.seq, opts);
    expect(sealed.status).toBe(200);
    expect(sealed.json.bundle_seq).toBe(1);

    const second = await putTestBundle(vault, vault.owner, sealTestBundle(vault, 2), vault.state.seq, opts);
    expect(second.status).toBe(403);
    expect(second.json.error.code).toBe('forbidden');
    expect((await vault.get(vault.owner, '/recovery', opts)).status).toBe(403);
    const rotate = (() => {
      const rotated = signKeyPairFromSeed(randomBytes(32));
      return { event: vault.buildEvent('recovery_rotate', { recovery_sign_pub: b64encode(rotated.publicKey) }), bundle: sealTestBundle(vault, 2, undefined, rotated.secretKey) as never };
    })();
    expect((await vault.append(rotate.event, undefined, vault.owner, opts, { bundle: rotate.bundle })).status).toBe(403);

    // The stored bundle is still the genesis seal, and an email_otp owner session may replace it.
    expect((await vault.get(vault.owner, '/recovery')).json.bundle.bundle_seq).toBe(1);
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 2), vault.state.seq, { sessionKind: 'email_otp' })).status).toBe(200);
  });

  it('an exact retry of the genesis seal is replayed, a different body under the same key is not', async () => {
    const opts = { sessionKind: 'api_key_device' };
    const vault = VaultFixture.local('personal', `acct-${randomId()}`);
    expect((await vault.putGenesis(opts)).status).toBe(201);
    const bundle = sealTestBundle(vault, 1);
    const first = await putTestBundle(vault, vault.owner, bundle, vault.state.seq, { ...opts, idempotencyKey: 'seal-retry' });
    expect(first.status).toBe(200);
    const retry = await putTestBundle(vault, vault.owner, bundle, vault.state.seq, { ...opts, idempotencyKey: 'seal-retry' });
    expect(retry.status).toBe(200);
    expect(retry.headers.get('Idempotent-Replayed')).toBe('true');
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 2), vault.state.seq, { ...opts, idempotencyKey: 'seal-retry' })).status).toBe(403);
  });

  it('a non-human genesis seal still needs an owner-role device and a valid proof', async () => {
    const vault = await VaultFixture.create('shared');
    const editor = await vault.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    expect((await putTestBundle(vault, editor, sealTestBundle(vault, 1), vault.state.seq, { sessionKind: 'api_key_device' })).status).toBe(403);
    const bad = await putTestBundle(vault, vault.owner, sealTestBundle(vault, 1), vault.state.seq, { sessionKind: 'api_key_device', proofSecret: randomBytes(32) });
    expect(bad.status).toBe(401);
    expect((await vault.get(vault.owner, '/recovery')).status).toBe(404);
  });

  it('the bundle store itself refuses a first-only PUT once a bundle exists (in-transaction re-check)', async () => {
    const vault = await VaultFixture.create();
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 1))).status).toBe(200);
    const body = { bundle: sealTestBundle(vault, 2), membership_seq: vault.state.seq } as unknown as JsonObject;
    const code = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(vault.vaultId)), (_i: unknown, state: DurableObjectState) => {
      try {
        putRecovery(state.storage.sql, vault.state, vault.vaultId, body, true);
        return 'stored';
      } catch (err) {
        return err instanceof ApiError ? err.code : 'other';
      }
    });
    expect(code).toBe('forbidden');
    expect((await vault.get(vault.owner, '/recovery')).json.bundle.bundle_seq).toBe(1);
  });

  it('email_otp and a token without session_kind replace a stored bundle as before', async () => {
    const vault = await VaultFixture.create();
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 1), vault.state.seq, { sessionKind: 'email_otp' })).status).toBe(200);
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 2))).status).toBe(200);
    expect((await putTestBundle(vault, vault.owner, sealTestBundle(vault, 3), vault.state.seq, { sessionKind: 'email_otp' })).status).toBe(200);
    expect((await vault.get(vault.owner, '/recovery')).json.bundle.bundle_seq).toBe(3);
  });
});
