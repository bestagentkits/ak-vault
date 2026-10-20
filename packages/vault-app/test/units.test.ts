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
  type ItemPayload,
} from '@ak-vault/protocol';
import { parseAppConfig } from '../src/config.js';
import { deviceKx, deviceSigner, generateDeviceKeys, isDeviceKeyMaterial, signPubB64 } from '../src/keys/webcrypto-device-keys.js';
import { memoryDeviceStore } from '../src/keys/device-store.js';
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
    meta: { schema: 'agentkit.secret/v1', created_ms: 5, creator: 'ci', rotate_ttl_days: 30, value_encoding: 'base64', profile: { tags: { value: ['a'], by: 'd', at: 1, src: 'local' } }, kind: 'x', custom: 1 },
  };
  it('follows the CLI mapping', () => {
    expect(nextMeta(null, true, 9)).toEqual({ schema: 'agentkit.secret/v1', created_ms: 9 });
    const m = nextMeta(prev, true, 9);
    expect(m).toEqual({ schema: 'agentkit.secret/v1', created_ms: 5, rotated_ms: 9, creator: 'ci', rotate_ttl_days: 30, custom: 1, profile: prev.meta['profile'] });
    expect(nextMeta(prev, false, 9)).not.toHaveProperty('rotated_ms');
  });

  it('applies the CLI name rules', () => {
    for (const ok of ['GITHUB_TOKEN', 'prod db password', 'ключ']) expect(validItemName(ok)).toBe(true);
    for (const bad of ['', ' lead', 'trail ', 'a/b', 'nul\u0000', 'bidi‮', 'line ', 'esc\u001b[31m', '\ud800']) expect(validItemName(bad), JSON.stringify(bad)).toBe(false);
  });
});
