/**
 * Audience separation between `/mcp` and the sync API. Tokens here are forged or
 * unsigned, so every refusal is proven by the signature and claim checks before any
 * vault state is read. The same four refusals with real tokens minted by ak-web
 * (both directions, plus revoked grant) run in `worker/scripts/staging-smoke.ts
 * --remote-access`, step 3, because minting needs a signed-in device session.
 */
import { expect, test } from '@playwright/test';
import { BASE_URL, gate } from './support/env.js';
import { parseBearerChallenge } from './support/challenge.js';

const g = await gate();

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** An unsigned token with the given audience: structure only, never a valid credential. */
function unsignedToken(aud: string): string {
  const now = Math.floor(Date.now() / 1000);
  return `${b64url({ alg: 'none', typ: 'at+jwt' })}.${b64url({ iss: 'https://staging.agentkit.best', aud, sub: 'e2e-probe', exp: now + 300, iat: now })}.`;
}

const VAULT_ID = 'AAAAAAAAAAAAAAAAAAAAAA';

test.describe('audience refusals with forged tokens', () => {
  test.skip(g.remote !== null, g.remote ?? '');

  test('an unsigned token minted for the sync API is refused on /mcp', async ({ request }) => {
    const res = await request.post(`${BASE_URL}/mcp`, {
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      headers: { Authorization: `Bearer ${unsignedToken(BASE_URL)}` },
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(res.status()).toBe(401);
    expect(parseBearerChallenge(res.headers()['www-authenticate'])?.params['error']).toBe('invalid_token');
  });

  test('an unsigned token minted for /mcp is refused by the sync API', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/v1/vaults/${VAULT_ID}/changes`, {
      headers: { Authorization: `Bearer ${unsignedToken(`${BASE_URL}/mcp`)}` },
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(res.status()).toBe(401);
  });

  test('an unsigned token minted for the origin without the /mcp path is refused on /mcp', async ({ request }) => {
    const res = await request.post(`${BASE_URL}/mcp`, {
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      headers: { Authorization: `Bearer ${unsignedToken(`${BASE_URL}/`)}` },
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(res.status()).toBe(401);
  });

  test('a token with an HS256 header (not the ES256 at+jwt the issuer signs) is refused on /mcp', async ({ request }) => {
    const claims = b64url({ aud: `${BASE_URL}/mcp`, sub: 'e2e-probe' });
    const res = await request.post(`${BASE_URL}/mcp`, {
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      headers: { Authorization: `Bearer ${b64url({ alg: 'HS256', typ: 'at+jwt' })}.${claims}.c2ln` },
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(res.status()).toBe(401);
    // The error must not echo the presented token or its claims.
    expect(await res.text()).not.toContain(claims);
  });
});

// Real-token refusals (sync token on /mcp, MCP token on /v1, app token on both, revoked
// grant) are not repeated here: they run in worker/scripts/staging-smoke.ts --remote-access.
