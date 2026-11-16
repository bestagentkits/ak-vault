/**
 * The lease identity (spec §9 item 4, §9.6): the only callers of the four sandbox lease
 * routes are a non-member key of a member account, in an `api_key_device` or `email_otp`
 * session, with the key presented and proven, the revocation registry always consulted,
 * and a per-account budget. Every lease route is 404 unless both flags are on.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomBytes, randomId } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS as L } from '../src/limits.js';
import { call, type TestDevice } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { rateCounters } from './helpers/replay-state.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { sendRevocation } from './helpers/webhook.js';
import { LEASES_ON, SUBJECT, VALUE, buildRequest, leasesPath, memberCall, newSandbox, postedLease, sandboxCall, sealPubFor, signGrant, type Sandbox } from './helpers/lease-client.js';

const BUDGET = L.lease_identity_requests_per_window;
const broken = {
  idFromName: () => {
    throw new Error('registry unavailable');
  },
} as unknown as DurableObjectNamespace<never>;

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function freezeIntoWindow(): void {
  vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
}

/** A sandbox that is really an enrolled (or removed) device, presenting its own key. */
function asSandbox(device: TestDevice): Sandbox {
  return { device, leaseSecret: device.keys.kxSecret, leasePub: new Uint8Array(32) };
}

const sealKey = (fx: VaultFixture, sb: Sandbox, opts = {}) => sandboxCall(sb, 'GET', leasesPath(fx, '/seal-key'), undefined, opts);

describe('sandbox leases: flags', () => {
  it('answers 404 on every lease route unless remote access and the lease flag are both on', async () => {
    const fx = await VaultFixture.create();
    const sb = newSandbox(fx.owner.account);
    const id = randomId();
    const routes: [string, string, unknown?][] = [
      ['GET', '/seal-key'],
      ['POST', '', { request: {} }],
      ['GET', `/${id}/status`],
      ['POST', `/${id}/fetch`, {}],
      ['GET', ''],
      ['GET', `/${id}`],
      ['POST', `/${id}/grant`, { grant: {} }],
      ['POST', `/${id}/revoke`, {}],
    ];
    for (const flags of [{ VAULT_LEASES_ENABLED: 'false' }, { VAULT_LEASES_ENABLED: 'TRUE' }, { VAULT_LEASES_ENABLED: 'true', VAULT_REMOTE_ACCESS_ENABLED: 'false' }]) {
      for (const [method, rest, body] of routes) {
        const res = await sandboxCall(sb, method, leasesPath(fx, rest), body, { env: flags });
        expect(res.status).toBe(404);
        expect(res.json.error.code).toBe('not_found');
      }
    }
    // Unset (the deployed default) is off too.
    expect((await call(fx.owner, 'GET', leasesPath(fx))).status).toBe(404);
    expect((await memberCall(fx.owner, 'GET', leasesPath(fx))).status).toBe(200);
  });
});

describe('sandbox leases: lease identity', () => {
  it('serves the seal key, or not_found before one is published', async () => {
    const fx = await VaultFixture.create();
    const sb = newSandbox(fx.owner.account);
    expect((await sealKey(fx, sb)).status).toBe(404);
    await sealPubFor(fx, sb);
    const res = await sealKey(fx, sb, { sessionKind: 'email_otp' });
    expect(res.status).toBe(200);
    expect(res.json.seal_key.key_epoch).toBe(fx.keyEpoch);
  });

  it('refuses a missing or mismatched AKV-Device-Key, and a proof under another key', async () => {
    const fx = await VaultFixture.create();
    const sb = newSandbox(fx.owner.account);
    const missing = await call(sb.device, 'GET', leasesPath(fx, '/seal-key'), undefined, { sessionKind: 'api_key_device', env: LEASES_ON });
    expect(missing.status).toBe(401);
    const other = newSandbox(fx.owner.account).device.keys.record.sign_pub;
    expect((await sealKey(fx, sb, { headers: { 'AKV-Device-Key': other } })).status).toBe(401);
    expect((await sealKey(fx, sb, { headers: { 'AKV-Device-Key': 'not base64url!' } })).status).toBe(401);
    expect((await sealKey(fx, sb, { proofSecret: randomBytes(32) })).status).toBe(401);
  });

  it('refuses a current or removed device of the vault, and an account that is not a member', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await sealKey(fx, asSandbox(fx.owner))).json.error.code).toBe('forbidden');
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await sealKey(fx, asSandbox(laptop))).json.error.code).toBe('forbidden');
    expect((await sealKey(fx, newSandbox(`acct-${randomId()}`))).json.error.code).toBe('forbidden');
  });

  it('admits only api_key_device and email_otp sessions; machine and browser are forbidden, input is not a sync token', async () => {
    const fx = await VaultFixture.create();
    await sealPubFor(fx, newSandbox(fx.owner.account));
    for (const kind of ['api_key_device', 'email_otp']) expect((await sealKey(fx, newSandbox(fx.owner.account), { sessionKind: kind })).status).toBe(200);
    for (const kind of ['machine', 'browser']) {
      const res = await sealKey(fx, newSandbox(fx.owner.account), { sessionKind: kind });
      expect(res.status).toBe(403);
    }
    expect((await sealKey(fx, newSandbox(fx.owner.account), { sessionKind: 'input' })).status).toBe(401);
    // The member routes are not open to the lease identity.
    const sb = newSandbox(fx.owner.account);
    expect((await sandboxCall(sb, 'GET', leasesPath(fx))).status).toBe(403);
  });

  it('refuses a revoked session and always consults the registry, even for a short-lived token', async () => {
    const fx = await VaultFixture.create();
    const sb = newSandbox(fx.owner.account);
    await sealPubFor(fx, sb);
    expect((await sendRevocation({ revoke_sids: [sb.device.sid] })).status).toBe(200);
    expect((await sealKey(fx, sb)).status).toBe(401);

    const fresh = newSandbox(fx.owner.account);
    const now = Math.floor(Date.now() / 1000);
    const short = await mintToken({ sub: fresh.device.account, did: fresh.device.keys.record.device_id, sid: fresh.device.sid, claims: { session_kind: 'api_key_device', iat: now, nbf: now, exp: now + 60 } });
    expect((await sealKey(fx, fresh, { token: short, env: { REVOCATIONS: broken } })).status).toBe(503);
    // A member route with the same short lifetime still skips the lookup.
    const ownerShort = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid, claims: { iat: now, nbf: now, exp: now + 60 } });
    expect((await memberCall(fx.owner, 'GET', leasesPath(fx), undefined, { token: ownerShort, env: { REVOCATIONS: broken } })).status).toBe(200);
  });

  it('spends one per-account budget across fresh request keys; refused proofs spend nothing', async () => {
    freezeIntoWindow();
    const fx = await VaultFixture.create();
    await sealPubFor(fx, newSandbox(fx.owner.account));
    const before = (await rateCounters(fx.vaultId, 'lease_identity'))[0]?.count ?? 0;
    for (let i = 0; i < 5; i++) expect((await sealKey(fx, newSandbox(fx.owner.account), { proofSecret: randomBytes(32) })).status).toBe(401);
    expect((await rateCounters(fx.vaultId, 'lease_identity'))[0]?.count ?? 0).toBe(before);
    for (let i = before; i < BUDGET; i++) expect((await sealKey(fx, newSandbox(fx.owner.account))).status).toBe(200);
    const limited = await sealKey(fx, newSandbox(fx.owner.account));
    expect(limited.status).toBe(429);
    expect(limited.headers.get('Retry-After')).toBe('50');
    // Members are unaffected.
    expect((await memberCall(fx.owner, 'GET', leasesPath(fx))).status).toBe(200);
  });

  it('echoes and logs no secret, reference, purpose, value, token or proof', async () => {
    const logs: string[] = [];
    for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));
    const fx = await VaultFixture.create();
    const { sb, wire } = await postedLease(fx);
    const bodies: string[] = [];
    const credentials: string[] = [];
    const record = (r: { json: unknown; token: string | null; proof: string | null }) => {
      bodies.push(JSON.stringify(r.json));
      if (r.token) credentials.push(r.token);
      if (r.proof) credentials.push(r.proof);
    };
    record(await sandboxCall(sb, 'POST', leasesPath(fx), { request: { ...wire, ct: 'SENTINEL_LEASE_REF_7c2a' } }));
    record(await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), { SENTINEL_LEASE_VAR: VALUE }));
    record(await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant: { bogus: VALUE } }));
    record(await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant: signGrant(fx.owner, wire, 'allow') }));
    record(await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {}));
    record(await sandboxCall(sb, 'GET', leasesPath(fx, `/${wire.lease_id}/status`)));
    record(await memberCall(fx.owner, 'GET', leasesPath(fx, '?state=all')));
    record(await sandboxCall(sb, 'POST', leasesPath(fx), { request: buildRequest(fx, newSandbox(fx.owner.account), wire.epk) }));

    const all = [...bodies, ...logs].join('\n');
    for (const leak of [SUBJECT.secrets[0]!.ref, SUBJECT.purpose, VALUE]) expect(all).not.toContain(leak);
    const logText = logs.join('\n');
    for (const leak of [SUBJECT.secrets[0]!.var, ...credentials]) expect(logText).not.toContain(leak);
    expect(bodies.join('\n')).not.toContain('SENTINEL_LEASE_VAR');
  });
});
