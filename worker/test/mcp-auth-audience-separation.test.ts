/**
 * RFC 8707 audience separation in both directions and live revocation: `/mcp`
 * accepts only MCP access tokens for `<origin>/mcp`, the `/v1` routes refuse them,
 * and revoking the grant (`sid`) or the account (`min_iat`) fails the next call.
 */
import { describe, expect, it } from 'vitest';
import { randomId } from '@ak-vault/protocol';
import { call } from './helpers/api-client.js';
import { mintToken, TEST_AUDIENCE } from './helpers/issuer.js';
import { MCP_RESOURCE, callTool, mintMcpToken, modern } from './helpers/mcp-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { sendRevocation } from './helpers/webhook.js';

const BUILD_WITH_AK_MCP = 'https://build-with-ak.agentkit.best/mcp';

describe('MCP audience separation', () => {
  it('/mcp refuses sync, browser, dashboard and other-resource tokens with the 401 challenge', async () => {
    const fx = await VaultFixture.create();
    const sub = fx.owner.account;
    const did = fx.owner.keys.record.device_id;
    const refused = [
      // A device sync token (audience = the vault origin, carries did).
      await mintToken({ sub, did }),
      // A dashboard browser-session sync token.
      await mintToken({ sub, did, claims: { session_kind: 'browser' } }),
      // A sync token re-targeted at /mcp still carries did and vault scopes.
      await mintToken({ sub, did, claims: { aud: MCP_RESOURCE } }),
      // MCP-shaped tokens for the wrong resource: the vault origin, /app, another MCP server.
      await mintMcpToken({ sub, claims: { aud: TEST_AUDIENCE } }),
      await mintMcpToken({ sub, claims: { aud: `${TEST_AUDIENCE}/app`, scope: 'vault-app:session' } }),
      await mintMcpToken({ sub, claims: { aud: `${TEST_AUDIENCE}/app` } }),
      await mintMcpToken({ sub, claims: { aud: BUILD_WITH_AK_MCP } }),
      await mintMcpToken({ sub, claims: { aud: [MCP_RESOURCE, TEST_AUDIENCE] } }),
      // Wrong issuer, algorithm or key, or an extra claim.
      await mintMcpToken({ sub, claims: { iss: 'https://elsewhere.invalid' } }),
      await mintMcpToken({ sub, header: { alg: 'ES384' } }),
      await mintMcpToken({ sub, header: { kid: 'unknown-kid' } }),
      await mintMcpToken({ sub, claims: { did } }),
      await mintMcpToken({ sub, claims: { session_kind: 'email_otp' } }),
      await mintMcpToken({ sub, claims: { scope: 'vault:read vault:write' } }),
    ];
    for (const [i, token] of refused.entries()) {
      const res = await modern(token, 'tools/list');
      expect(res.status, `token ${i}`).toBe(401);
      expect(res.headers.get('WWW-Authenticate'), `token ${i}`).toContain('resource_metadata=');
    }
  });

  it('reads the Bearer scheme case-insensitively and refuses other schemes', async () => {
    const token = await mintMcpToken({ sub: `acct-${randomId()}` });
    for (const scheme of ['bearer', 'BEARER', 'bEaReR']) {
      expect((await modern(token, 'tools/list', {}, { headers: { Authorization: `${scheme} ${token}` } })).status, scheme).toBe(200);
    }
    for (const header of [`Basic ${token}`, `Bearer${token}`, 'Bearer ', 'Bearer']) {
      const res = await modern(token, 'tools/list', {}, { headers: { Authorization: header } });
      expect(res.status, header).toBe(401);
    }
  });

  it('the /v1 routes refuse an MCP token', async () => {
    const fx = await VaultFixture.create();
    const mcp = await mintMcpToken({ sub: fx.owner.account });
    for (const path of ['/changes', '/membership', '/seal-key', '/sealed', `/lookup?tag=${'A'.repeat(22)}&key_epoch=1`]) {
      const res = await call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}${path}`, undefined, { token: mcp });
      expect(res.status, path).toBe(401);
      expect(res.json.error.code).toBe('unauthorized');
    }
    const put = await fx.put(fx.owner, fx.record(fx.owner, randomId(), 0, { name: 'A', value: '1' }), { token: mcp });
    expect(put.status).toBe(401);
  });

  it('the /v1 routes refuse an /app token', async () => {
    const fx = await VaultFixture.create();
    const app = await mintMcpToken({ sub: fx.owner.account, claims: { aud: `${TEST_AUDIENCE}/app`, scope: 'vault-app:session' } });
    expect((await fx.get(fx.owner, '/changes', { token: app })).status).toBe(401);
  });
});

describe('MCP revocation', () => {
  it('revoking the grant (sid) fails the very next call', async () => {
    const sub = `acct-${randomId()}`;
    const grantId = `grant-${randomId()}`;
    const token = await mintMcpToken({ sub, grantId });
    expect((await modern(token, 'tools/list')).status).toBe(200);
    expect((await sendRevocation({ revoke_sids: [grantId] })).status).toBe(200);
    const after = await callTool(token, 'secrets_list');
    expect(after.status).toBe(401);
    expect(after.headers.get('WWW-Authenticate')).toContain('resource_metadata=');
    // Another grant of the same account keeps working.
    expect((await modern(await mintMcpToken({ sub }), 'tools/list')).status).toBe(200);
  });

  it('a per-account minimum iat refuses older MCP tokens', async () => {
    const sub = `acct-${randomId()}`;
    const now = Math.floor(Date.now() / 1000);
    const old = await mintMcpToken({ sub, claims: { iat: now - 30, nbf: now - 30, exp: now + 200 } });
    expect((await modern(old, 'ping')).status).toBe(200);
    expect((await sendRevocation({ min_iat: [{ sub, iat: now }] })).status).toBe(200);
    expect((await modern(old, 'ping')).status).toBe(401);
  });
});
