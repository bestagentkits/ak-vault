/** Live revocation: webhook authentication and its effect on the next request, plus registry failure. */
import { randomId, utf8Encode } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call } from './helpers/api-client.js';
import { mintToken } from './helpers/issuer.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { sendRevocation } from './helpers/webhook.js';

async function readAs(fx: VaultFixture, token?: string) {
  return call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}/membership`, undefined, token ? { token } : {});
}

describe('revocation webhook', () => {
  it('a revoked session is refused on its next request even with an unexpired token', async () => {
    const fx = await VaultFixture.create();
    expect((await readAs(fx)).status).toBe(200);
    const res = await sendRevocation({ revoke_sids: [fx.owner.sid] });
    expect(res.status).toBe(200);
    const after = await readAs(fx);
    expect(after.status).toBe(401);
    expect(after.json.error.code).toBe('unauthorized');
  });

  it('a revoked device is refused in every session', async () => {
    const fx = await VaultFixture.create();
    expect((await sendRevocation({ revoke_dids: [fx.owner.keys.record.device_id] })).status).toBe(200);
    fx.owner.sid = `sid-${randomId()}`;
    expect((await readAs(fx)).status).toBe(401);
  });

  it('min_iat revokes older tokens of the account only', async () => {
    const fx = await VaultFixture.create();
    const now = Math.floor(Date.now() / 1000);
    const old = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, claims: { iat: now - 30 } });
    expect((await sendRevocation({ min_iat: [{ sub: fx.owner.account, iat: now - 10 }] })).status).toBe(200);
    expect((await readAs(fx, old)).status).toBe(401);
    expect((await readAs(fx)).status).toBe(200);
    // A replayed or older min_iat cannot lower the bar.
    expect((await sendRevocation({ min_iat: [{ sub: fx.owner.account, iat: 1 }] })).status).toBe(200);
    expect((await readAs(fx, old)).status).toBe(401);
  });

  it('rejects a bad HMAC, a stale timestamp, a wrong secret and malformed bodies', async () => {
    const sid = `sid-${randomId()}`;
    expect((await sendRevocation({ revoke_sids: [sid] }, { signature: 'AAAA' })).status).toBe(401);
    expect((await sendRevocation({ revoke_sids: [sid] }, { secret: 'another-secret-that-is-long-enough-000' })).status).toBe(401);
    expect((await sendRevocation({ revoke_sids: [sid] }, { ts: Math.floor(Date.now() / 1000) - 301 })).status).toBe(401);
    expect((await sendRevocation({ revoke_sids: [] })).status).toBe(400);
    expect((await sendRevocation({ v: 2, revoke_sids: [sid] })).status).toBe(400);
    expect((await sendRevocation({}, { raw: utf8Encode('{"v":1,"event_id":"x","revoke_sids":[1],"revoke_dids":[],"min_iat":[]}') })).status).toBe(400);
  });

  it('refuses a replayed event', async () => {
    const event_id = randomId();
    expect((await sendRevocation({ event_id, revoke_sids: ['s1'] })).status).toBe(200);
    const replay = await sendRevocation({ event_id, revoke_sids: ['s1'] });
    expect(replay.status).toBe(409);
  });

  it('accepts the previous secret during a rotation overlap', async () => {
    const previous = 'previous-webhook-secret-0123456789abcdef';
    const res = await sendRevocation({ revoke_sids: [`sid-${randomId()}`] }, { secret: previous, env: { REVOCATION_WEBHOOK_SECRET_PREVIOUS: previous } });
    expect(res.status).toBe(200);
  });

  it('fails closed when no secret is configured, and stays on with the kill switch', async () => {
    expect((await sendRevocation({ revoke_sids: ['s'] }, { env: { REVOCATION_WEBHOOK_SECRET: '' } })).status).toBe(503);
    expect((await sendRevocation({ revoke_sids: [`sid-${randomId()}`] }, { env: { VAULT_SYNC_ENABLED: 'false' } })).status).toBe(200);
  });
});

describe('registry failure', () => {
  it('returns 503 when the revocation registry cannot be reached', async () => {
    const fx = await VaultFixture.create();
    const broken = {
      idFromName: () => {
        throw new Error('registry unavailable');
      },
    } as unknown as DurableObjectNamespace<never>;
    const res = await call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}/membership`, undefined, { env: { REVOCATIONS: broken as never } });
    expect(res.status).toBe(503);
    expect(res.headers.get('Retry-After')).toBe('5');
  });
});
