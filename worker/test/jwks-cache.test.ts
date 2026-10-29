/**
 * JWKS loading: a failed load is negatively cached for 30 s, stays fail-closed, and
 * recovers after the backoff; a redirect from the configured URL is never followed.
 */
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

describe('JWKS redirects', () => {
  const TARGETS = {
    'https, same origin': 'https://issuer.example/other/jwks.json',
    'plain http': 'http://issuer.example/.well-known/jwks.json',
    'another origin': 'https://attacker.example/.well-known/jwks.json',
  };

  /**
   * A fetch that behaves like the platform: with the default `redirect: 'follow'` it
   * follows the 3xx and serves valid keys from the target; with `manual` it returns the
   * 3xx itself. Loading through the old default would therefore succeed.
   */
  function redirectingFetch(location: string, status: number, keys: Response): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
    return async (_input, init) => {
      if (init?.redirect === 'manual') return new Response(null, { status, headers: { Location: location } });
      return keys;
    };
  }

  for (const [label, location] of Object.entries(TARGETS)) {
    for (const status of [301, 302, 307, 308]) {
      it(`refuses a ${status} redirect to ${label}`, async () => {
        clearJwksCache();
        const keys = await jwksResponse('k1');
        const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(redirectingFetch(location, status, keys));
        await expectUnavailable(getIssuerKey(ENV, 'k1', 3_000_000));
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(fetchSpy.mock.calls[0]?.[1]?.redirect).toBe('manual');
        // The refusal is negatively cached like any other load failure.
        await expectUnavailable(getIssuerKey(ENV, 'k1', 3_001_000));
        expect(fetchSpy).toHaveBeenCalledTimes(1);
      });
    }
  }

  it('refuses a response the platform marks as redirected', async () => {
    clearJwksCache();
    const keys = await jwksResponse('k1');
    Object.defineProperty(keys, 'redirected', { value: true });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(keys);
    await expectUnavailable(getIssuerKey(ENV, 'k1', 4_000_000));
    await expectUnavailable(getIssuerKey(ENV, 'k1', 4_001_000));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('refuses an opaque-redirect response', async () => {
    clearJwksCache();
    // A WHATWG `manual` fetch answers a redirect with type `opaqueredirect` and status 0,
    // which the Response constructor cannot build, so the fields are overridden.
    const opaque = await jwksResponse('k1');
    Object.defineProperty(opaque, 'type', { value: 'opaqueredirect' });
    Object.defineProperty(opaque, 'status', { value: 0 });
    Object.defineProperty(opaque, 'ok', { value: false });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(opaque);
    await expectUnavailable(getIssuerKey(ENV, 'k1', 5_000_000));
    await expectUnavailable(getIssuerKey(ENV, 'k1', 5_001_000));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('still loads keys served directly with 200', async () => {
    clearJwksCache();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(await jwksResponse('k1'));
    expect(await getIssuerKey(ENV, 'k1', 6_000_000)).toBeDefined();
  });
});
