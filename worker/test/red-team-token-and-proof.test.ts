/**
 * Red-team token and proof attacks not already in auth-token.test.ts: an
 * attacker key presenting the trusted `kid`, embedded-key and algorithm
 * confusion headers, and proofs moved to another query string, token or vault.
 * Plus a stolen token without the device key across every vault route.
 */
import { b64encode, buildProof, randomBytes, randomId, utf8Encode } from '@ak-vault/protocol';
import { beforeAll, describe, expect, it } from 'vitest';
import { BASE, call } from './helpers/api-client.js';
import { mintToken, TEST_AUDIENCE, TEST_ISSUER } from './helpers/issuer.js';
import { codes, every, readEverything, snapshot, statuses, WRITE_ROUTES, writeEverything } from './helpers/red-team-routes.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const UNAUTHORIZED = { error: { code: 'unauthorized', message: 'authentication failed' } };
let fx: VaultFixture;
let attacker: { key: CryptoKey; publicJwk: JsonWebKey };

beforeAll(async () => {
  fx = await VaultFixture.create();
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  attacker = { key: pair.privateKey, publicJwk: (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey };
});

const part = (v: unknown) => b64encode(utf8Encode(JSON.stringify(v)));

function claims(): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return { iss: TEST_ISSUER, aud: TEST_AUDIENCE, sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid, jti: randomId(), scope: 'vault:read vault:write', iat: now, nbf: now, exp: now + 300 };
}

/** ES256 token signed by the attacker's key, with any header the attacker likes. */
async function attackerToken(header: Record<string, unknown>): Promise<string> {
  const input = `${part(header)}.${part(claims())}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, attacker.key, utf8Encode(input)));
  return `${input}.${b64encode(sig)}`;
}

const membershipPath = () => `/v1/vaults/${fx.vaultId}/membership`;

describe('red team: token forgery and confusion', () => {
  it('refuses an attacker ES256 key that presents the trusted kid, an embedded jwk or a jku', async () => {
    const forged = [
      await attackerToken({ alg: 'ES256', typ: 'JWT', kid: 'test-issuer-key-1' }),
      await attackerToken({ alg: 'ES256', typ: 'JWT', kid: 'test-issuer-key-1', jwk: attacker.publicJwk }),
      await attackerToken({ alg: 'ES256', typ: 'JWT', jwk: attacker.publicJwk }),
      await attackerToken({ alg: 'ES256', typ: 'JWT', kid: 'test-issuer-key-1', jku: 'https://evil.example/jwks.json', x5u: 'https://evil.example/cert' }),
    ];
    for (const token of forged) {
      const res = await call(fx.owner, 'GET', membershipPath(), undefined, { token });
      expect(res.status).toBe(401);
      expect(res.json).toEqual(UNAUTHORIZED);
    }
  });

  it('refuses a genuine ES256 signature relabelled as another algorithm', async () => {
    const genuine = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid });
    const [, payload, sig] = genuine.split('.');
    for (const alg of ['ES384', 'ES512', 'RS256', 'PS256', 'EdDSA', 'es256', 'ES256 ']) {
      const relabelled = `${part({ alg, typ: 'JWT', kid: 'test-issuer-key-1' })}.${payload}.${sig}`;
      const res = await call(fx.owner, 'GET', membershipPath(), undefined, { token: relabelled });
      expect(res.status).toBe(401);
      expect(res.json).toEqual(UNAUTHORIZED);
    }
  });
});

describe('red team: proof binding', () => {
  it('a proof for one query string is refused on another', async () => {
    const token = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid });
    const signed = `${BASE}/v1/vaults/${fx.vaultId}/changes?cursor=0`;
    const proof = buildProof({ htm: 'GET', htu: signed, ts: Date.now(), token, body: new Uint8Array(), secretKey: fx.owner.keys.signSecret });
    const moved = await call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}/changes?cursor=0&limit=500`, undefined, { token, proof });
    expect(moved.status).toBe(401);
    expect((await call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}/changes?cursor=0`, undefined, { token, proof })).status).toBe(200);
  });

  it('a proof made for one token is refused with another token of the same device', async () => {
    const first = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid });
    const second = await mintToken({ sub: fx.owner.account, did: fx.owner.keys.record.device_id, sid: fx.owner.sid });
    const proof = buildProof({ htm: 'GET', htu: `${BASE}${membershipPath()}`, ts: Date.now(), token: first, body: new Uint8Array(), secretKey: fx.owner.keys.signSecret });
    const moved = await call(fx.owner, 'GET', membershipPath(), undefined, { token: second, proof });
    // A proof bound to another token is a binding failure (unauthorized), not a bad signature.
    expect([moved.status, moved.json]).toEqual([401, UNAUTHORIZED]);
    // Positive control: a refused proof is not spent, and it works with the token it was made for.
    expect((await call(fx.owner, 'GET', membershipPath(), undefined, { token: first, proof })).status).toBe(200);
  });

  it('a device enrolled in two vaults cannot move a proof between them', async () => {
    const other = await VaultFixture.create('personal', fx.owner.account);
    // Enroll this very device (same keys) in the second vault.
    const shared = { ...fx.owner, sid: `sid-${randomId()}` };
    const { event, wraps } = other.enrollEvent(shared);
    expect((await other.append(event, wraps)).status).toBe(201);
    const token = await mintToken({ sub: shared.account, did: shared.keys.record.device_id, sid: shared.sid });
    const proof = buildProof({ htm: 'GET', htu: `${BASE}/v1/vaults/${fx.vaultId}/changes`, ts: Date.now(), token, body: new Uint8Array(), secretKey: shared.keys.signSecret });
    expect((await call(shared, 'GET', `/v1/vaults/${other.vaultId}/changes`, undefined, { token, proof })).status).toBe(401);
    expect((await call(shared, 'GET', `/v1/vaults/${fx.vaultId}/changes`, undefined, { token, proof })).status).toBe(200);
    // And the proof is now spent in its own vault.
    expect((await call(shared, 'GET', `/v1/vaults/${fx.vaultId}/changes`, undefined, { token, proof })).status).toBe(401);
  });
});

describe('red team: stolen token without the device key', () => {
  it('gets no data and changes nothing on any vault route', async () => {
    const itemId = randomId();
    expect((await fx.write(fx.owner, itemId, 0, { name: 'SYNTHETIC_KEY', value: 'synthetic' })).status).toBe(200);
    // The thief holds a valid token for the owner device but signs proofs with a key of its own.
    const thief = { proofSecret: randomBytes(32) };
    const before = await snapshot(fx);
    const reads = await readEverything(fx, fx.owner, itemId, thief);
    expect(statuses(reads)).toEqual(every(Object.keys(reads), 401));
    expect(codes(reads)).toEqual(every(Object.keys(reads), 'invalid_signature'));
    const writes = await writeEverything(fx, fx.owner, itemId, thief);
    expect(statuses(writes)).toEqual(every(WRITE_ROUTES, 401));
    expect(codes(writes)).toEqual(every(WRITE_ROUTES, 'invalid_signature'));
    expect(await snapshot(fx)).toEqual(before);
  });
});
