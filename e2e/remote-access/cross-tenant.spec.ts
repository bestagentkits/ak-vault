/**
 * Cross-tenant refusals with no existence oracle. The unauthenticated check runs on
 * every target: an unknown vault id and another unknown vault id answer the same way.
 * The second-account checks need a second staging test account (VAULT_E2E_SECOND_STORAGE_STATE)
 * and the first account's vault id (VAULT_E2E_VAULT_ID); without them they are skipped
 * and recorded as NEEDS_CONTEXT, not passed.
 */
import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { BASE_URL, gate, SECOND_STORAGE_STATE } from './support/env.js';
import { authorizeMcpClient, rpc, type McpSession } from './support/mcp-client.js';

const g = await gate();
const FIRST_VAULT_ID = process.env['VAULT_E2E_VAULT_ID'] || '';

/** A random vault id in the wire format: 22 url-safe characters. */
function randomVaultId(): string {
  return randomBytes(16).toString('base64url');
}

/** The stable error code of a REST or JSON-RPC refusal; never the message. */
function errorCode(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as { error?: { code?: unknown; data?: { code?: unknown } } };
    const code = parsed.error?.data?.code ?? parsed.error?.code;
    return typeof code === 'string' ? code : null;
  } catch {
    return null;
  }
}

function shape(res: { status: number; body: string }): { status: number; code: string | null } {
  return { status: res.status, code: errorCode(res.body) };
}

function rpcCode(reply: { body: string }): string | null {
  return errorCode(reply.body);
}

test.describe('cross-tenant refusals without an existence oracle', () => {
  test.skip(g.remote !== null, g.remote ?? '');

  test('an unknown vault and another unknown vault answer identically to an unauthenticated lookup', async ({ request }) => {
    const answers: Array<{ status: number; code: string | null }> = [];
    for (const vid of [randomVaultId(), randomVaultId()]) {
      const res = await request.get(`${BASE_URL}/v1/vaults/${vid}/lookup?tag=AAAAAAAAAAAAAAAAAAAAAA&key_epoch=1`, {
        maxRedirects: 0,
        failOnStatusCode: false,
      });
      answers.push(shape({ status: res.status(), body: await res.text() }));
    }
    expect(answers[0]).toEqual(answers[1]);
    expect(answers[0]!.status).toBe(401);
  });
});

test.describe('cross-tenant refusals with a second account', () => {
  test.skip(g.remote !== null, g.remote ?? '');
  test.skip(g.oauth !== null, g.oauth ?? '');
  test.skip(SECOND_STORAGE_STATE === '' || g.account !== null, 'needs a second signed-in staging test account (VAULT_E2E_SECOND_STORAGE_STATE)');
  test.skip(FIRST_VAULT_ID === '', 'needs the first account vault id (VAULT_E2E_VAULT_ID)');

  let other: McpSession | null = null;

  test.beforeAll(async ({ browser, playwright }) => {
    const request = await playwright.request.newContext();
    try {
      other = await authorizeMcpClient(browser, request, SECOND_STORAGE_STATE);
    } finally {
      await request.dispose();
    }
  });

  test('a token of the second account gets the same refusal for the first vault as for a nonexistent one', async ({ playwright }) => {
    const request = await playwright.request.newContext();
    try {
      const token = other!.accessToken;
      const foreign = await rpc(request, token, 1, 'tools/call', { name: 'secrets_list', arguments: { vault_id: FIRST_VAULT_ID } });
      const missing = await rpc(request, token, 2, 'tools/call', { name: 'secrets_list', arguments: { vault_id: randomVaultId() } });
      expect(foreign.status).toBe(missing.status);
      expect(rpcCode(foreign)).toBe(rpcCode(missing));
      // The refusal must not echo the other account's vault id back.
      expect(foreign.body).not.toContain(FIRST_VAULT_ID);
    } finally {
      await request.dispose();
    }
  });
});
