/** JWKS loading: a failed load is negatively cached for 30 s, stays fail-closed, and recovers after the backoff. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearJwksCache, getIssuerKey } from '../src/auth/jwks.js';
import { ApiError } from '../src/http/errors.js';

const ENV = { VAULT_JWKS_URL: 'https://issuer.example/.well-known/jwks.json' };

async function jwksResponse(kid: string): Promise<Response> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = (await crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).publicKey)) as JsonWebKey;
  return Response.json({ keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid, alg: 'ES256', use: 'sig' }] });
}

async function expectUnavailable(promise: Promise<unknown>): Promise<void> {
  const err = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ApiError);
  expect((err as ApiError).status).toBe(503);
}

afterEach(() => {
  vi.restoreAllMocks();
  clearJwksCache();
});

describe('JWKS negative cache', () => {
  it('does not refetch during the 30 s backoff after a failure, then recovers', async () => {
    clearJwksCache();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('issuer down'));
    const t0 = 1_000_000;
    await expectUnavailable(getIssuerKey(ENV, 'k1', t0));
    await expectUnavailable(getIssuerKey(ENV, 'k1', t0 + 1_000));
    await expectUnavailable(getIssuerKey(ENV, 'k1', t0 + 29_999));
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    await expectUnavailable(getIssuerKey(ENV, 'k1', t0 + 30_000));
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    fetchSpy.mockResolvedValue(await jwksResponse('k1'));
    expect(await getIssuerKey(ENV, 'k1', t0 + 60_000)).toBeDefined();
    expect(fetchSpy).toHaveBeenCalledTimes(3);
  });

  it('never serves expired keys while the issuer is down', async () => {
    clearJwksCache();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(await jwksResponse('k1'));
    const t0 = 2_000_000;
    expect(await getIssuerKey(ENV, 'k1', t0)).toBeDefined();
    fetchSpy.mockRejectedValue(new Error('issuer down'));
    // Within the 5 min TTL the loaded key is used without a fetch.
    expect(await getIssuerKey(ENV, 'k1', t0 + 60_000)).toBeDefined();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    // After the TTL the request is refused, and the failure is cached.
    await expectUnavailable(getIssuerKey(ENV, 'k1', t0 + 5 * 60_000 + 1));
    await expectUnavailable(getIssuerKey(ENV, 'k1', t0 + 5 * 60_000 + 2));
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});
