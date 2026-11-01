/**
 * Per-client MCP rate budgets and the per-call audit row and log line: tool,
 * stable outcome, latency and hashed client/account, never names or values.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { randomId } from '@ak-vault/protocol';
import { accountLogTag, clientLogTag } from '../src/http/operational-logger.js';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { relayStub } from '../src/relay/relay-rpc.js';
import { answerNext, callTool, mintMcpToken, modern } from './helpers/mcp-client.js';
import { awaitRateWindowHeadroom } from './helpers/rate-window.js';
import { readyRelay } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

let spy: MockInstance;
beforeEach(() => {
  spy = vi.spyOn(console, 'log');
});
afterEach(() => spy.mockRestore());

function auditRows(sub: string): Promise<Record<string, unknown>[]> {
  return runInDurableObject(relayStub(env, sub), (_i: unknown, state: DurableObjectState) => state.storage.sql.exec('SELECT * FROM client_audit ORDER BY ts').toArray());
}

describe('MCP rate limits', () => {
  it('refuses a client past its per-minute budget with retry_after_s; another client is unaffected', async () => {
    await awaitRateWindowHeadroom();
    const sub = `acct-${randomId()}`;
    const token = await mintMcpToken({ sub, clientId: 'client-busy' });
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.mcp_calls_per_minute_per_client; i++) {
      const res = await callTool(token, 'secrets_list');
      expect(res.json.result.structuredContent.code).toBe('no_device_online');
    }
    const limited = await callTool(token, 'secrets_list');
    expect(limited.status).toBe(200);
    expect(limited.json.result.isError).toBe(true);
    const sc = limited.json.result.structuredContent;
    expect(sc.code).toBe('rate_limited');
    expect(sc.retry_after_s).toBeGreaterThanOrEqual(1);
    expect(sc.retry_after_s).toBeLessThanOrEqual(60);
    const other = await callTool(await mintMcpToken({ sub, clientId: 'client-calm' }), 'secrets_list');
    expect(other.json.result.structuredContent.code).toBe('no_device_online');
  });

  it('secrets_run has its own smaller budget', async () => {
    await awaitRateWindowHeadroom();
    const token = await mintMcpToken({ sub: `acct-${randomId()}` });
    const run = { argv: ['true'], env: [{ var: 'A', name: 'B' }] };
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.mcp_run_calls_per_minute_per_client; i++) {
      expect((await callTool(token, 'secrets_run', run)).json.result.structuredContent.code).toBe('no_device_online');
    }
    expect((await callTool(token, 'secrets_run', run)).json.result.structuredContent.code).toBe('rate_limited');
    expect((await callTool(token, 'secrets_list')).json.result.structuredContent.code).toBe('no_device_online');
  });

  it('meters every JSON-RPC method: tools/list, ping and server/discover spend the same budget as tools', async () => {
    await awaitRateWindowHeadroom();
    const sub = `acct-${randomId()}`;
    const token = await mintMcpToken({ sub, clientId: 'client-chatty' });
    const methods = ['tools/list', 'ping', 'server/discover'];
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.mcp_calls_per_minute_per_client; i++) {
      const method = methods[i % methods.length]!;
      expect((await modern(token, method)).status, method).toBe(200);
    }
    for (const method of methods) {
      const limited = await modern(token, method);
      expect(limited.status, method).toBe(429);
      expect(limited.json).toEqual({ error: { code: 'rate_limited', message: 'too many requests' } });
      const retryAfter = Number(limited.headers.get('Retry-After'));
      expect(retryAfter).toBeGreaterThanOrEqual(1);
      expect(retryAfter).toBeLessThanOrEqual(60);
    }
    // The tool call shares the spent budget and answers as a tool error.
    expect((await callTool(token, 'secrets_list')).json.result.structuredContent.code).toBe('rate_limited');
    // A call refused before its tool runs (unknown tool) is metered too.
    expect((await callTool(token, 'secrets_nope')).status).toBe(429);
    expect((await modern(await mintMcpToken({ sub, clientId: 'client-quiet' }), 'tools/list')).status).toBe(200);
  });

  it('a call refused as rate_limited writes no audit row but keeps its log line', async () => {
    await awaitRateWindowHeadroom();
    const sub = `acct-${randomId()}`;
    const clientId = 'client-flood';
    const token = await mintMcpToken({ sub, clientId });
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.mcp_calls_per_minute_per_client; i++) expect((await modern(token, 'ping')).status).toBe(200);
    spy.mockClear();
    for (let i = 0; i < 3; i++) expect((await callTool(token, 'secrets_list')).json.result.structuredContent.code).toBe('rate_limited');
    expect(await auditRows(sub)).toEqual([]);
    const mcpLines = spy.mock.calls
      .map((args) => JSON.parse(args.map(String).join(' ')) as Record<string, unknown>)
      .filter((l) => l['route'] === '/mcp' && 'tool' in l);
    expect(mcpLines).toHaveLength(3);
    for (const line of mcpLines) expect(line).toMatchObject({ tool: 'list', outcome: 'rate_limited', audited: false, client: clientLogTag(clientId), account: accountLogTag(sub) });
  });
});

describe('MCP audit and logs', () => {
  it('records one audit row and one log line per call, with hashed IDs and no names or values', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const clientId = `https://client-${randomId()}.example/client.json`;
    const token = await mintMcpToken({ sub: fx.owner.account, clientId });
    const NAME = `AUDIT_NAME_${randomId()}`;
    const VALUE = `audit-value-${randomId()}`;

    const pending = callTool(token, 'secrets_set', { name: NAME, value: VALUE });
    await answerNext(conn, () => ({ ok: true, result: { status: 'written', revision: 1 } }));
    await pending;
    await callTool(token, 'secrets_describe', { name: NAME, vault_id: randomId() });
    conn.close();

    const rows = await auditRows(fx.owner.account);
    expect(rows.map((r) => [r['tool'], r['outcome'], r['client_hash']])).toEqual([
      ['set', 'ok', clientLogTag(clientId)],
      ['describe', 'invalid_args', clientLogTag(clientId)],
    ]);
    const lines = spy.mock.calls.map((args) => args.map(String).join(' '));
    const mcpLines = lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l['route'] === '/mcp' && 'tool' in l);
    expect(mcpLines).toHaveLength(2);
    for (const line of mcpLines) {
      expect(Object.keys(line).sort()).toEqual(['account', 'audited', 'client', 'ms', 'outcome', 'route', 'tool']);
      expect(line['client']).toBe(clientLogTag(clientId));
      expect(line['account']).toBe(accountLogTag(fx.owner.account));
      expect(line['audited']).toBe(true);
    }
    const everything = `${lines.join('\n')}\n${JSON.stringify(rows)}`;
    for (const secret of [NAME, VALUE, clientId, fx.owner.account, token, fx.vaultId]) expect(everything).not.toContain(secret);
  });
});
