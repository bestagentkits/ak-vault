/** RFC 9728 protected-resource metadata and the 401 `resource_metadata` challenge of `/mcp`. */
import { describe, expect, it } from 'vitest';
import { fetchRaw } from './helpers/api-client.js';
import { TEST_AUDIENCE, TEST_ISSUER } from './helpers/issuer.js';
import { MCP_RESOURCE, mcpPost, mintMcpToken, modern } from './helpers/mcp-client.js';

const PRM_URL = `${TEST_AUDIENCE}/.well-known/oauth-protected-resource/mcp`;
const EXPECTED_PRM = {
  resource: MCP_RESOURCE,
  authorization_servers: [TEST_ISSUER],
  scopes_supported: ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use'],
  bearer_methods_supported: ['header'],
  resource_name: 'AgentKit Vault',
};

describe('protected-resource metadata', () => {
  it('/.well-known/oauth-protected-resource/mcp names the MCP resource, the issuer and the three scopes', async () => {
    const res = await fetchRaw('/.well-known/oauth-protected-resource/mcp');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('application/json');
    expect(res.headers.get('Cache-Control')).toBe('public, max-age=300');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual(EXPECTED_PRM);
    // RFC 9728 §3.3: the resource identifier is the URL the metadata was requested for, minus the well-known part.
    expect(new URL(body['resource'] as string).origin).toBe(TEST_AUDIENCE);
    expect(new URL(body['resource'] as string).pathname).toBe('/mcp');
  });

  it('does not serve the root /.well-known/oauth-protected-resource (it would describe the origin, not /mcp)', async () => {
    for (const method of ['GET', 'HEAD']) {
      const res = await fetchRaw('/.well-known/oauth-protected-resource', { method });
      expect(res.status, method).toBe(404);
      expect(res.headers.get('Content-Type') ?? '').not.toContain('application/json');
    }
  });

  it('answers HEAD without a body and refuses other methods with 405', async () => {
    const head = await fetchRaw('/.well-known/oauth-protected-resource/mcp', { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe('');
    const post = await fetchRaw('/.well-known/oauth-protected-resource/mcp', { method: 'POST', body: '{}' });
    expect(post.status).toBe(405);
    expect(post.headers.get('Allow')).toBe('GET, HEAD');
  });

  it('is hidden with remote access off', async () => {
    for (const path of ['/.well-known/oauth-protected-resource/mcp', '/mcp']) {
      const res = await fetchRaw(path, { method: path === '/mcp' ? 'POST' : 'GET', body: path === '/mcp' ? '{}' : null }, { VAULT_REMOTE_ACCESS_ENABLED: 'false' });
      expect(res.status, path).toBe(404);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe('not_found');
    }
  });
});

describe('401 challenge', () => {
  const BARE = `Bearer resource_metadata="${PRM_URL}", scope="vault-mcp:read"`;
  const INVALID_TOKEN = `Bearer error="invalid_token", resource_metadata="${PRM_URL}", scope="vault-mcp:read"`;
  const expectChallenge = (res: { status: number; headers: Headers; json: { error: { code: string } } }, challenge = BARE) => {
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe('unauthorized');
    expect(res.headers.get('WWW-Authenticate')).toBe(challenge);
  };

  it('a request without a token gets the bare resource_metadata challenge before anything else', async () => {
    expectChallenge(await modern(null, 'server/discover'));
    expectChallenge(await mcpPost(null, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }, { version: null }));
    // Even a malformed body is challenged first: nothing is parsed before the token.
    expectChallenge(await mcpPost(null, null, { rawBody: '{not json' }));
    // A non-bearer credential or an empty bearer value presents no token.
    expectChallenge(await modern(await mintMcpToken({ sub: 'acct-x' }), 'server/discover', {}, { headers: { Authorization: 'Basic abc' } }));
    expectChallenge(await modern(null, 'server/discover', {}, { headers: { Authorization: 'Bearer ' } }));
  });

  it('an invalid, expired, wrongly-typed or revoked bearer token adds error="invalid_token" (RFC 6750 §3.1)', async () => {
    const now = Math.floor(Date.now() / 1000);
    expectChallenge(await modern('not.a.jwt', 'server/discover'), INVALID_TOKEN);
    expectChallenge(await modern(await mintMcpToken({ sub: 'acct-x', claims: { iat: now - 900, nbf: now - 900, exp: now - 400 } }), 'server/discover'), INVALID_TOKEN);
    expectChallenge(await modern(await mintMcpToken({ sub: 'acct-x', header: { typ: 'JWT' } }), 'server/discover'), INVALID_TOKEN);
    expectChallenge(await modern(await mintMcpToken({ sub: 'acct-x', claims: { aud: TEST_AUDIENCE } }), 'server/discover'), INVALID_TOKEN);
  });

  it('refuses a token passed in the query string', async () => {
    const token = await mintMcpToken({ sub: 'acct-x' });
    expectChallenge(await modern(null, 'server/discover', {}, { url: `${TEST_AUDIENCE}/mcp?access_token=${token}` }));
    expectChallenge(await modern(token, 'server/discover', {}, { url: `${TEST_AUDIENCE}/mcp?access_token=${token}` }), INVALID_TOKEN);
  });
});
