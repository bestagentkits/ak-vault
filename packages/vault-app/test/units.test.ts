/** Unit checks for config, OAuth helpers, device keys, the token request and write metadata. */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  b64encode,
  randomBytes,
  sha256,
  signingInput,
  unwrapFromDeviceAsync,
  utf8Encode,
  verifyDetached,
  wrapToDevice,
  buildNextProfile,
  randomId,
  type ItemPayload,
} from '@ak-vault/protocol';
import { parseAppConfig } from '../src/config.js';
import { deviceKx, deviceSigner, generateDeviceKeys, isDeviceKeyMaterial, signPubB64 } from '../src/keys/webcrypto-device-keys.js';
import { decideAdvance, isWitnessedFork, memoryDeviceStore, mergeWitnessed, type StoredDevice, type WitnessedState } from '../src/keys/device-store.js';
import { beginSignIn, parseAuthServerMetadata, pkceChallenge } from '../src/oauth/pkce-client.js';
import { validItemName } from '../src/sync/item-names.js';
import { nextMeta } from '../src/sync/write-ops.js';
import { buildTokenRequest, VAULT_TOKEN_REQUEST_CONTEXT } from '../src/vault/token-exchange.js';
import { ISSUER, ORIGIN, memoryPendingStore } from './helpers/fake-world.js';

const CONFIG = { v: 1, issuer: ISSUER, client_id: `${ORIGIN}/app/client.json`, redirect_uri: `${ORIGIN}/app/`, resource: `${ORIGIN}/app`, scope: 'vault-app:session' };
const AS = { issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth/authorize`, token_endpoint: `${ISSUER}/oauth/token`, revocation_endpoint: `${ISSUER}/oauth/revoke`, code_challenge_methods_supported: ['S256'] };

describe('config', () => {
  it('accepts only values derived from the page origin', () => {
    expect(parseAppConfig(CONFIG, ORIGIN).clientId).toBe(`${ORIGIN}/app/client.json`);
    for (const bad of [
      { ...CONFIG, client_id: 'https://evil.test/app/client.json' },
      { ...CONFIG, redirect_uri: `${ORIGIN}/app/callback` },
      { ...CONFIG, resource: ORIGIN },
      { ...CONFIG, scope: 'vault-app:session vault:write' },
      { ...CONFIG, issuer: 'http://id.example.test' },
      { ...CONFIG, issuer: `${ISSUER}/path` },
      { ...CONFIG, v: 2 },
      null,
      [],
    ]) {
      expect(() => parseAppConfig(bad, ORIGIN)).toThrow('config_invalid');
    }
  });
});

describe('oauth helpers', () => {
  it('PKCE S256 challenge is base64url(SHA-256(ascii verifier)) without padding', () => {
    const verifier = 'dBjftJeZ4CVP-mJ92IyV1GmSL2ExmtXGmz7eu2jQqKs';
    expect(pkceChallenge(verifier)).toBe(createHash('sha256').update(verifier).digest('base64url'));
  });

  it('validates authorization server metadata', () => {
    expect(parseAuthServerMetadata(AS, ISSUER).token_endpoint).toBe(`${ISSUER}/oauth/token`);
    expect(() => parseAuthServerMetadata({ ...AS, issuer: 'https://other.test' }, ISSUER)).toThrow('signin_issuer_mismatch');
    expect(() => parseAuthServerMetadata({ ...AS, token_endpoint: 'https://evil.test/token' }, ISSUER)).toThrow('config_invalid');
    expect(() => parseAuthServerMetadata({ ...AS, code_challenge_methods_supported: ['plain'] }, ISSUER)).toThrow('config_invalid');
  });

  it('starts every sign-in with fresh state and verifier', () => {
    const store = memoryPendingStore();
    const config = parseAppConfig(CONFIG, ORIGIN);
    const as = parseAuthServerMetadata(AS, ISSUER);
    const a = new URL(beginSignIn(config, as, store));
    const first = store.value!;
    const b = new URL(beginSignIn(config, as, store));
    expect(a.searchParams.get('state')).not.toBe(b.searchParams.get('state'));
    expect(first.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.searchParams.get('code_challenge')).toBe(b64encode(sha256(utf8Encode(first.verifier))));
  });
});

describe('device keys', () => {
  it('are non-extractable WebCrypto keys whose signatures and exchange match the protocol library', async () => {
    const keys = await generateDeviceKeys();
    expect(keys.signKey.extractable).toBe(false);
    expect(keys.kxKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', keys.signKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', keys.kxKey)).rejects.toThrow();
    expect(isDeviceKeyMaterial(keys)).toBe(true);

    const msg = signingInput('akv1/test', { a: 1 });
    const sig = await deviceSigner(keys).sign(msg);
    expect(verifyDetached('akv1/test', { a: 1 }, b64encode(sig), signPubB64(keys))).toBe(true);

    const vk = randomBytes(32);
    const did = 'AAAAAAAAAAAAAAAAAAAAAA';
    const wrap = wrapToDevice({ vk, vaultId: did, keyEpoch: 1, recipient: { device_id: did, kx_pub: keys.kxPub } });
    expect(await unwrapFromDeviceAsync({ wrap, vaultId: did, deviceId: did, kx: deviceKx(keys) })).toEqual(vk);
  });

  it('survive the store as keys, and a tampered entry reads as absent', async () => {
    const store = memoryDeviceStore();
    const keys = await generateDeviceKeys();
    await store.put({ v: 1, account: 'a', keys, label: 'x', nonceJ: b64encode(randomBytes(16)), enrollment: null });
    expect((await store.get('a'))!.keys.signKey.extractable).toBe(false);
    expect(await store.get('b')).toBeNull();
    store.entries.set('a', { ...store.entries.get('a')!, keys: { ...keys, signKey: 'raw' as unknown as CryptoKey } });
    expect(await store.get('a')).toBeNull();
  });
});

describe('token request', () => {
  it('signs aud, sorted scope, sid, sign_pub and ts', async () => {
    const keys = await generateDeviceKeys();
    const config = parseAppConfig(CONFIG, ORIGIN);
    const body = await buildTokenRequest({ config, sid: 'grant-1', signPub: signPubB64(keys), signer: deviceSigner(keys), nowS: 1_700_000_000 });
    expect(Object.keys(body).sort()).toEqual(['scope', 'sig', 'sign_pub', 'ts']);
    const signed = { aud: ORIGIN, scope: ['vault:read', 'vault:write'], sid: 'grant-1', sign_pub: signPubB64(keys), ts: 1_700_000_000 };
    expect(verifyDetached(VAULT_TOKEN_REQUEST_CONTEXT, signed, body['sig'] as string, signPubB64(keys))).toBe(true);
    expect(verifyDetached(VAULT_TOKEN_REQUEST_CONTEXT, { ...signed, sid: 'grant-2' }, body['sig'] as string, signPubB64(keys))).toBe(false);
  });
});

describe('write metadata', () => {
  const prev: ItemPayload = {
    name: 'n',
    value: 'old',
    sensitivity: 'high',
    meta: { schema: 'agentkit.secret/v1', created_ms: 5, creator: 'ci', rotate_ttl_days: 30, value_encoding: 'base64', profile: { tags: { value: ['raw'], by: 'd', at: 1, src: 'local' } }, kind: 'x', custom: 1 },
  };
  const verified = buildNextProfile({}, { tags: ['a'] }, { deviceId: randomId(), ts: 1, src: 'local' });
  it('follows the CLI mapping', () => {
    expect(nextMeta(null, true, 9, null)).toEqual({ schema: 'agentkit.secret/v1', created_ms: 9 });
    const m = nextMeta(prev, true, 9, verified);
    expect(m).toEqual({ schema: 'agentkit.secret/v1', created_ms: 5, rotated_ms: 9, creator: 'ci', rotate_ttl_days: 30, custom: 1, profile: verified });
    expect(nextMeta(prev, false, 9, verified)).not.toHaveProperty('rotated_ms');
  });

  it('carries the verified profile, never the raw one', () => {
    expect(nextMeta(prev, false, 9, null)).not.toHaveProperty('profile');
    expect(nextMeta(prev, false, 9, {})).not.toHaveProperty('profile');
    expect(JSON.stringify(nextMeta(prev, false, 9, verified))).not.toContain('raw');
  });

  it('applies the CLI name rules', () => {
    for (const ok of ['GITHUB_TOKEN', 'prod db password', 'ключ']) expect(validItemName(ok)).toBe(true);
    for (const bad of ['', ' lead', 'trail ', 'a/b', 'nul\u0000', 'bidi‮', 'line ', 'esc\u001b[31m', '\ud800']) expect(validItemName(bad), JSON.stringify(bad)).toBe(false);
  });
});

describe('sync position compare-and-save', () => {
  const at = (log_seq: number, log_head: string, membership_seq = 3): WitnessedState => ({ membership_seq, membership_head: 'm3', log_seq, log_head, key_epoch: 1 });

  async function enrolled(witnessed: WitnessedState | null): Promise<StoredDevice> {
    const keys = await generateDeviceKeys();
    const enrollment = { origin: ORIGIN, vaultId: 'v', initiator: 'i', nonceI: 'ni', trustAnchor: 't', offerCheckpoint: null as never, sas: '123456', confirmed: true, witnessed };
    return { v: 1, account: 'a', keys, label: 'x', nonceJ: 'nj', enrollment };
  }
  const withPosition = (d: StoredDevice, w: WitnessedState): StoredDevice => ({ ...d, enrollment: { ...d.enrollment!, witnessed: w } });

  it('saves an equal or newer position, refuses an older one and flags a fork', async () => {
    const base = await enrolled(at(5, 'h5'));
    expect(decideAdvance(base, withPosition(base, at(5, 'h5'))).outcome).toBe('saved');
    expect(decideAdvance(base, withPosition(base, at(6, 'h6'))).outcome).toBe('saved');
    expect(decideAdvance(base, withPosition(base, at(4, 'h4'))).outcome).toBe('older');
    expect(decideAdvance(base, withPosition(base, at(5, 'other'))).outcome).toBe('fork');
    expect(isWitnessedFork(at(5, 'a', 3), at(6, 'b', 3))).toBe(false);
  });

  it('refuses to write for a missing, re-enrolled or different device', async () => {
    const base = await enrolled(at(5, 'h5'));
    const next = withPosition(base, at(6, 'h6'));
    expect(decideAdvance(null, next).outcome).toBe('stale');
    expect(decideAdvance({ ...base, enrollment: null }, next).outcome).toBe('stale');
    expect(decideAdvance({ ...base, nonceJ: 'restarted' }, next).outcome).toBe('stale');
    expect(decideAdvance({ ...base, keys: await generateDeviceKeys() }, next).outcome).toBe('stale');
  });

  it('keeps each component\'s furthest counter when two pulls are ahead on different ones', async () => {
    const base = await enrolled(at(8, 'l8', 5));
    const merged = mergeWitnessed(at(8, 'l8', 5), { ...at(6, 'l6', 6), membership_head: 'm6' });
    expect(merged).toEqual({ membership_seq: 6, membership_head: 'm6', log_seq: 8, log_head: 'l8', key_epoch: 1 });
    const result = decideAdvance(base, withPosition(base, { ...at(6, 'l6', 6), membership_head: 'm6' }));
    expect(result.outcome).toBe('saved');
    expect(result.position).toEqual(merged);
    expect(mergeWitnessed(at(5, 'x'), at(5, 'y'))).toBeNull();
  });
});
