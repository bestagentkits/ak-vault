/** MCP access tokens (at+jwt for `<audience>/mcp`): exact claims, short lifetime, and no crossover with sync tokens. */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { randomId } from '@ak-vault/protocol';
import { verifyMcpToken, verifyToken } from '../src/auth/jwt-verify.js';
import { mintToken, signJwt, TEST_AUDIENCE, TEST_ISSUER } from './helpers/issuer.js';

const KID = 'test-issuer-key-1';

function mcpClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  const grant = `grant-${randomId()}`;
  const claims: Record<string, unknown> = {
    iss: TEST_ISSUER,
    aud: `${TEST_AUDIENCE}/mcp`,
    sub: `acct-${randomId()}`,
    client_id: 'https://client.example/metadata.json',
    grant_id: grant,
    sid: grant,
    scope: 'vault-mcp:read vault-mcp:use',
    jti: randomId(),
    iat: now,
    nbf: now,
    exp: now + 300,
    ...overrides,
  };
  for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
  return claims;
}

function mcpToken(overrides: Record<string, unknown> = {}, header: Record<string, unknown> = {}): Promise<string> {
  return signJwt({ alg: 'ES256', typ: 'at+jwt', kid: KID, ...header }, mcpClaims(overrides));
}

describe('MCP token verifier', () => {
  it('accepts an at+jwt token for the MCP resource and returns its claims', async () => {
    const claims = mcpClaims();
    const token = await signJwt({ alg: 'ES256', typ: 'at+jwt', kid: KID }, claims);
    const verified = await verifyMcpToken(token, env);
    expect(verified).toMatchObject({ sub: claims['sub'], client_id: claims['client_id'], grant_id: claims['grant_id'], sid: claims['grant_id'], scope: ['vault-mcp:read', 'vault-mcp:use'] });
  });

  it('refuses the wrong typ, audience, issuer, scope, lifetime or claim set', async () => {
    const bad = [
      mcpToken({}, { typ: 'JWT' }),
      mcpToken({ aud: TEST_AUDIENCE }),
      mcpToken({ iss: 'https://elsewhere.invalid' }),
      mcpToken({ scope: 'vault:read' }),
      mcpToken({ scope: 'vault-mcp:read vault-mcp:admin' }),
      mcpToken({ scope: '' }),
      mcpToken({ exp: Math.floor(Date.now() / 1000) + 601 }),
      mcpToken({ sid: 'other' }),
      mcpToken({ did: 'device' }),
      mcpToken({ client_id: undefined }),
      mcpToken({ client_id: 'bad\nclient' }),
      mcpToken({ exp: Math.floor(Date.now() / 1000) - 120, iat: Math.floor(Date.now() / 1000) - 300, nbf: Math.floor(Date.now() / 1000) - 300 }),
    ];
    for (const token of bad) await expect(verifyMcpToken(await token, env)).rejects.toMatchObject({ code: 'unauthorized' });
  });

  it('a sync token is not an MCP token and an MCP token is not a sync token', async () => {
    const sync = await mintToken({ sub: 'acct-1', did: randomId() });
    await expect(verifyMcpToken(sync, env)).rejects.toMatchObject({ code: 'unauthorized' });
    await expect(verifyToken(await mcpToken(), env)).rejects.toMatchObject({ code: 'unauthorized' });
  });
});
