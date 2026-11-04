/**
 * Short-lived vault tokens (lifetime at most 120 s, spec §9 item 3): revocation was checked
 * when the token was issued, so the Worker serves it without a registry lookup, and only
 * while now < exp. Longer tokens keep the per-request lookup.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { call } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { sendRevocation } from './helpers/webhook.js';

const broken = {
  idFromName: () => {
    throw new Error('registry unavailable');
  },
} as unknown as DurableObjectNamespace<never>;

afterEach(() => {
  vi.useRealTimers();
});

async function tokenFor(fx: VaultFixture, lifetime: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid, claims: { iat: now, nbf: now, exp: now + lifetime } });
}

function read(fx: VaultFixture, token: string, envOverride?: Record<string, unknown>) {
  return call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}/membership`, undefined, { token, ...(envOverride ? { env: envOverride } : {}) });
}

describe('short-lived vault tokens', () => {
  it('a 120 s token is served without consulting the registry', async () => {
    const fx = await VaultFixture.create();
    expect((await read(fx, await tokenFor(fx, 120), { REVOCATIONS: broken })).status).toBe(200);
  });

  it('a longer token still consults the registry on every request', async () => {
    const fx = await VaultFixture.create();
    expect((await read(fx, await tokenFor(fx, 121), { REVOCATIONS: broken })).status).toBe(503);
  });

  it('a revocation takes effect when the short token expires, with no skew', async () => {
    const fx = await VaultFixture.create();
    const token = await tokenFor(fx, 120);
    expect((await sendRevocation({ revoke_sids: [fx.owner.sid] })).status).toBe(200);
    expect((await read(fx, token)).status).toBe(200);
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 120_000 });
    const expired = await read(fx, token);
    expect(expired.status).toBe(401);
    expect(expired.json.error.code).toBe('unauthorized');
  });

  it('a token with exp not after iat is not short-lived and consults the registry', async () => {
    const fx = await VaultFixture.create();
    const now = Math.floor(Date.now() / 1000);
    const token = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid, claims: { iat: now + 30, nbf: now, exp: now + 30 } });
    expect((await read(fx, token, { REVOCATIONS: broken })).status).toBe(503);
  });
});
