/**
 * Discovery surface of `/mcp`: the 401 challenge syntax, the protected-resource
 * metadata on both paths, and the authorization-server metadata, each checked
 * against a JSON Schema. Runs without a signed-in account; the authorization-server
 * block needs the ak-web staging issuer to answer.
 */
import { expect, test } from '@playwright/test';
import { AK_WEB_ORIGIN, BASE_URL, gate } from './support/env.js';
import { parseBearerChallenge } from './support/challenge.js';
import { schemaErrors } from './support/metadata-schemas.js';

const g = await gate();
const PRM_PATH = '/.well-known/oauth-protected-resource/mcp';
const MCP_RESOURCE = `${BASE_URL}/mcp`;
const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'e2e', version: '0' } },
};

test.describe('MCP challenge and discovery', () => {
  test.skip(g.remote !== null, g.remote ?? '');

  test('unauthenticated POST /mcp answers 401 with the exact Bearer challenge', async ({ request }) => {
    const res = await request.post(`${BASE_URL}/mcp`, { data: INITIALIZE, maxRedirects: 0, failOnStatusCode: false });
    expect(res.status()).toBe(401);
    const challenge = parseBearerChallenge(res.headers()['www-authenticate']);
    expect(challenge).not.toBeNull();
    expect(challenge!.scheme).toBe('Bearer');
    // A request that presented no token gets no error code (RFC 6750 §3.1).
    expect(challenge!.names).toEqual(['resource_metadata', 'scope']);
    expect(challenge!.params['resource_metadata']).toBe(`${BASE_URL}${PRM_PATH}`);
    expect(challenge!.params['scope']).toBe('vault-mcp:read');
    expect(res.headers()['mcp-session-id']).toBeUndefined();
  });

  test('a presented but invalid token gets error="invalid_token" in the challenge', async ({ request }) => {
    const garbage = 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImUyZSJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuaW52YWxpZCJ9.AAAA';
    const res = await request.post(`${BASE_URL}/mcp`, {
      data: INITIALIZE,
      headers: { Authorization: `Bearer ${garbage}` },
      maxRedirects: 0,
      failOnStatusCode: false,
    });
    expect(res.status()).toBe(401);
    const challenge = parseBearerChallenge(res.headers()['www-authenticate']);
    expect(challenge?.names).toEqual(['error', 'resource_metadata', 'scope']);
    expect(challenge?.params['error']).toBe('invalid_token');
  });

  test('GET and DELETE on /mcp are 405: the endpoint is stateless POST only', async ({ request }) => {
    for (const method of ['GET', 'DELETE'] as const) {
      const res = await request.fetch(`${BASE_URL}/mcp`, { method, maxRedirects: 0, failOnStatusCode: false });
      expect(res.status(), method).toBe(405);
    }
  });

  test('the challenge names a PRM URL that answers the protected-resource metadata', async ({ request }) => {
    const res = await request.post(`${BASE_URL}/mcp`, { data: INITIALIZE, maxRedirects: 0, failOnStatusCode: false });
    const challenge = parseBearerChallenge(res.headers()['www-authenticate']);
    const prm = await request.get(challenge!.params['resource_metadata']!, { maxRedirects: 0, failOnStatusCode: false });
    expect(prm.status()).toBe(200);
  });
});

test.describe('protected-resource metadata (RFC 9728)', () => {
  test.skip(g.remote !== null, g.remote ?? '');

  test('the path-suffixed document validates and names the MCP resource and issuer', async ({ request }) => {
    const res = await request.get(`${BASE_URL}${PRM_PATH}`, { maxRedirects: 0, failOnStatusCode: false });
    expect(res.status()).toBe(200);
    expect(res.headers()['content-type']).toContain('application/json');
    const doc = (await res.json()) as Record<string, unknown>;
    expect(schemaErrors('protectedResource', doc)).toEqual([]);
    expect(doc['resource']).toBe(MCP_RESOURCE);
    expect(doc['authorization_servers']).toEqual([AK_WEB_ORIGIN]);
    expect(doc['scopes_supported']).toEqual(['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use']);
  });

  test('the origin-level PRM path is not served (it would describe the origin, not /mcp)', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/.well-known/oauth-protected-resource`, { maxRedirects: 0, failOnStatusCode: false });
    expect(res.status()).toBe(404);
  });
});

test.describe('authorization-server metadata (RFC 8414, MCP 2026-07-28)', () => {
  test.skip(g.oauth !== null, g.oauth ?? '');

  test('the ak-web issuer advertises PKCE S256, CIMD and RFC 9207 iss', async ({ request }) => {
    const res = await request.get(`${AK_WEB_ORIGIN}/.well-known/oauth-authorization-server`, { maxRedirects: 0, failOnStatusCode: false });
    expect(res.status()).toBe(200);
    const doc = (await res.json()) as Record<string, unknown>;
    expect(schemaErrors('authorizationServer', doc)).toEqual([]);
    expect(doc['issuer']).toBe(AK_WEB_ORIGIN);
    expect(doc['code_challenge_methods_supported']).toEqual(['S256']);
    expect(doc['client_id_metadata_document_supported']).toBe(true);
    expect(doc['authorization_response_iss_parameter_supported']).toBe(true);
  });
});
