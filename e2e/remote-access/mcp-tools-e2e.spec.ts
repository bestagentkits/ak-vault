/**
 * Remote MCP end to end with the signed-in staging account: a scripted public client
 * (ak-web DCR, PKCE, RFC 8707 `resource`) completes consent, then calls `/mcp`. CIMD
 * needs a publicly hosted document, so the CIMD path is proven by Claude Code and
 * Claude.ai in the client matrix instead. The access token stays in memory.
 */
import { expect, test } from '@playwright/test';
import { gate, runNameSentinel, runSentinel, STORAGE_STATE } from './support/env.js';
import { authorizeMcpClient, rpc, type McpSession } from './support/mcp-client.js';

const g = await gate();
const reason = [g.remote, g.oauth, g.account].find((r) => r !== null) ?? '';

test.describe('remote MCP end to end (signed-in account)', () => {
  test.skip(reason !== '', reason);
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE || undefined });

  let session: McpSession | null = null;

  test.beforeAll(async ({ browser, playwright }) => {
    const request = await playwright.request.newContext();
    try {
      session = await authorizeMcpClient(browser, request, STORAGE_STATE);
    } finally {
      await request.dispose();
    }
  });

  test('the consent completes with PKCE, the resource indicator and the RFC 9207 issuer', () => {
    expect(session).not.toBeNull();
  });

  test('the server answers the 2026-07-28 discovery call statelessly', async ({ playwright }) => {
    const request = await playwright.request.newContext();
    try {
      const reply = await rpc(request, session!.accessToken, 1, 'server/discover');
      expect(reply.status).toBe(200);
      expect(reply.json?.result).toBeDefined();
    } finally {
      await request.dispose();
    }
  });

  test('tools/list exposes the seven secrets tools and no others', async ({ playwright }) => {
    const request = await playwright.request.newContext();
    try {
      const reply = await rpc(request, session!.accessToken, 2, 'tools/list');
      expect(reply.status).toBe(200);
      const tools = (reply.json?.result as { tools?: Array<{ name: string }> } | undefined)?.tools ?? [];
      expect(tools).toHaveLength(7);
      for (const tool of tools) expect(tool.name.startsWith('secrets_')).toBe(true);
    } finally {
      await request.dispose();
    }
  });

  test('a write through MCP never returns the value or its name in the tool result', async ({ playwright }) => {
    const request = await playwright.request.newContext();
    try {
      const reply = await rpc(request, session!.accessToken, 3, 'tools/call', {
        name: 'secrets_set',
        arguments: { name: runNameSentinel(), value: runSentinel() },
      });
      expect(reply.body).not.toContain(runSentinel());
      expect(reply.body).not.toContain(runNameSentinel());
    } finally {
      await request.dispose();
    }
  });

  test('calls past the per-client budget are refused with rate_limited', async ({ playwright }) => {
    const request = await playwright.request.newContext();
    try {
      let limited = false;
      for (let i = 0; i < 70 && !limited; i += 1) {
        const reply = await rpc(request, session!.accessToken, 100 + i, 'tools/call', { name: 'secrets_list', arguments: {} });
        limited = reply.body.includes('rate_limited');
      }
      expect(limited).toBe(true);
    } finally {
      await request.dispose();
    }
  });
});

// Not here: no_device_online for reads, the sealed-write drain, the revoked-grant 401 and
// the audit row need an ak relay session that is stopped and restarted, and a connected-apps
// revoke. They are smoke steps 8 and 9 in worker/scripts/staging-smoke.ts --remote-access.
