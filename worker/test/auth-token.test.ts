/** Token (ES256 JWT) and proof-of-possession checks: wrong iss/aud/alg/kid, time claims, replay, theft. */
import { b64encode, buildProof, randomBytes, utf8Encode } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { beforeAll, describe, expect, it } from 'vitest';
import { clearJwksCache } from '../src/auth/jwks.js';
import { BASE, call } from './helpers/api-client.js';
import { mintToken, signJwt, TEST_AUDIENCE, TEST_ISSUER } from './helpers/issuer.js';
import { VaultFixture } from './helpers/vault-fixture.js';

declare global {
  namespace Cloudflare {
    interface Env {
      TEST_DEPLOYED_AUDIENCES: string;
      TEST_DEPLOYED_ISSUERS: string;
    }
  }
}

let fx: VaultFixture;
const did = () => fx.owner.keys.record.device_id;
const sub = () => fx.owner.account;
const membershipPath = () => `/v1/vaults/${fx.vaultId}/membership`;

async function withToken(token: string | null) {
  return call(fx.owner, 'GET', membershipPath(), undefined, { token });
}

beforeAll(async () => {
  fx = await VaultFixture.create();
});

describe('token verification', () => {
  it('accepts a valid token and proof', async () => {
    expect((await withToken(await mintToken({ sub: sub(), did: did() }))).status).toBe(200);
  });

  it.each([
    ['wrong audience', { aud: 'https://other.agentkit.best' }],
    ['audience list with extra entry', { aud: [TEST_AUDIENCE, 'https://other.example'] }],
    ['wrong issuer', { iss: 'https://evil.example' }],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 120 }],
    ['not yet valid', { nbf: Math.floor(Date.now() / 1000) + 600 }],
    ['issued in the future', { iat: Math.floor(Date.now() / 1000) + 600 }],
    ['missing sid', { sid: undefined }],
    ['missing jti', { jti: undefined }],
    ['missing did', { did: undefined }],
    ['malformed did', { did: 'not-a-device-id' }],
    ['unknown scope', { scope: 'vault:read vault:admin' }],
    ['empty scope', { scope: '' }],
    ['unknown session kind', { session_kind: 'admin' }],
    ['non-string session kind', { session_kind: 7 }],
    ['empty session kind', { session_kind: '' }],
    ['null session kind', { session_kind: null }],
    ['missing session kind', { session_kind: undefined }],
  ])('rejects %s', async (_name, claims) => {
    const res = await withToken(await mintToken({ sub: sub(), did: did(), claims }));
    expect(res.status).toBe(401);
    expect(res.json).toEqual({ error: { code: 'unauthorized', message: 'authentication failed' } });
  });

  it.each(['email_otp', 'api_key_device', 'machine'])('accepts the %s session kind on a member route', async (kind) => {
    expect((await withToken(await mintToken({ sub: sub(), did: did(), claims: { session_kind: kind } }))).status).toBe(200);
  });

  it('rejects alg none, HS256 and unknown kid', async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: TEST_ISSUER, aud: TEST_AUDIENCE, sub: sub(), did: did(), sid: 's', jti: 'j', scope: 'vault:read', iat: now, nbf: now, exp: now + 60 };
    const part = (v: unknown) => b64encode(utf8Encode(JSON.stringify(v)));
    const none = `${part({ alg: 'none', typ: 'JWT' })}.${part(claims)}.`;
    expect((await withToken(none)).status).toBe(401);
    const hsInput = `${part({ alg: 'HS256', typ: 'JWT', kid: 'test-issuer-key-1' })}.${part(claims)}`;
    const hmacKey = await crypto.subtle.importKey('raw', utf8Encode('guessable'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const hs = `${hsInput}.${b64encode(new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, utf8Encode(hsInput))))}`;
    expect((await withToken(hs)).status).toBe(401);
    expect((await withToken(await signJwt({ alg: 'ES256', kid: 'unknown-kid' }, claims))).status).toBe(401);
    expect((await withToken(await signJwt({ alg: 'ES256' }, claims))).status).toBe(401);
    expect((await withToken(await signJwt({ alg: 'ES256', kid: 'test-issuer-key-1', jku: 'https://evil.example/jwks' }, claims))).status).toBe(401);
  });

  it('keeps production and staging audiences apart', async () => {
    const { production, staging } = JSON.parse(env.TEST_DEPLOYED_AUDIENCES) as Record<'production' | 'staging', string>;
    expect(production).toBe('https://vault.agentkit.best');
    expect(staging).toBe('https://vault-staging.agentkit.best');
    for (const [deployed, other] of [[production, staging], [staging, production]] as const) {
      const as = (aud: string) => mintToken({ sub: sub(), did: did(), claims: { aud } });
      const opts = { env: { VAULT_AUDIENCE: deployed } };
      expect((await call(fx.owner, 'GET', membershipPath(), undefined, { ...opts, token: await as(deployed) })).status).toBe(200);
      const refused = await call(fx.owner, 'GET', membershipPath(), undefined, { ...opts, token: await as(other) });
      expect(refused.status).toBe(401);
      expect(refused.json).toEqual({ error: { code: 'unauthorized', message: 'authentication failed' } });
    }
  });

  it('trusts each environment\'s own ak-web issuer, with keys fetched from its JWKS', () => {
    type PerEnv = Record<'production' | 'staging', string | null>;
    const { issuer, jwksUrl, inlineJwks } = JSON.parse(env.TEST_DEPLOYED_ISSUERS) as { issuer: PerEnv; jwksUrl: PerEnv; inlineJwks: PerEnv };
    expect(issuer).toEqual({ production: 'https://agentkit.best', staging: 'https://staging.agentkit.best' });
    expect(jwksUrl).toEqual({ production: 'https://agentkit.best/.well-known/jwks.json', staging: 'https://staging.agentkit.best/.well-known/jwks.json' });
    // No deployed environment may pin inline keys: they would bypass the issuer's rotation.
    expect(inlineJwks).toEqual({ production: null, staging: null });
  });

  it('rejects a tampered payload and a missing bearer', async () => {
    const token = await mintToken({ sub: sub(), did: did() });
    const [h, , s] = token.split('.');
    const forged = `${h}.${b64encode(utf8Encode(JSON.stringify({ sub: 'someone-else' })))}.${s}`;
    expect((await withToken(forged)).status).toBe(401);
    expect((await call(fx.owner, 'GET', membershipPath(), undefined, { token: null, proof: null })).status).toBe(401);
  });

  // workerd logs "Uncaught (in promise) ... Network connection lost" for any failed
  // subrequest even when the caller catches it; the Worker handles the error.
  it('fails closed with 503 when the JWKS endpoint is unreachable', async () => {
    clearJwksCache();
    const res = await call(fx.owner, 'GET', membershipPath(), undefined, { env: { VAULT_JWKS_JSON: '', VAULT_JWKS_URL: 'https://127.0.0.1:9/keys.json' } });
    clearJwksCache();
    expect(res.status).toBe(503);
    expect(res.json.error.code).toBe('unauthorized');
    const plain = await call(fx.owner, 'GET', membershipPath(), undefined, { env: { VAULT_JWKS_JSON: '', VAULT_JWKS_URL: 'http://insecure.example/jwks' } });
    clearJwksCache();
    expect(plain.status).toBe(503);
  });
});

describe('proof of possession', () => {
  it('rejects a missing proof', async () => {
    expect((await call(fx.owner, 'GET', membershipPath(), undefined, { proof: null })).status).toBe(401);
  });

  it('rejects a replayed proof jti', async () => {
    const first = await call(fx.owner, 'GET', membershipPath());
    expect(first.status).toBe(200);
    const replay = await call(fx.owner, 'GET', membershipPath(), undefined, { token: first.token, proof: first.proof });
    expect(replay.status).toBe(401);
    expect(replay.json.error.code).toBe('unauthorized');
  });

  it('rejects a proof bound to another URL, method or body', async () => {
    expect((await call(fx.owner, 'GET', membershipPath(), undefined, { proofUrl: `${BASE}/v1/vaults/${fx.vaultId}/wraps` })).status).toBe(401);
    const token = await mintToken({ sub: sub(), did: did() });
    const postProof = buildProof({ htm: 'POST', htu: `${BASE}${membershipPath()}`, ts: Date.now(), token, body: new Uint8Array(), secretKey: fx.owner.keys.signSecret });
    expect((await call(fx.owner, 'GET', membershipPath(), undefined, { token, proof: postProof })).status).toBe(401);
    const res = await fx.write(fx.owner, b64encode(randomBytes(16)), 0, { name: 'n', value: 'v' }, { proofBody: utf8Encode('{}') });
    expect(res.status).toBe(401);
  });

  it('rejects a stale proof timestamp', async () => {
    const token = await mintToken({ sub: sub(), did: did() });
    const old = buildProof({ htm: 'GET', htu: `${BASE}${membershipPath()}`, ts: Date.now() - 5 * 60_000, token, body: new Uint8Array(), secretKey: fx.owner.keys.signSecret });
    expect((await call(fx.owner, 'GET', membershipPath(), undefined, { token, proof: old })).status).toBe(401);
  });

  it('a stolen token without the device key is refused (invalid_signature)', async () => {
    const res = await call(fx.owner, 'GET', membershipPath(), undefined, { proofSecret: randomBytes(32) });
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe('invalid_signature');
  });

  it('a token whose did names a non-member device is forbidden', async () => {
    const other = await VaultFixture.create();
    const res = await call(other.owner, 'GET', membershipPath(), undefined, {
      token: await mintToken({ sub: sub(), did: other.owner.keys.record.device_id }),
    });
    expect(res.status).toBe(403);
  });
});
