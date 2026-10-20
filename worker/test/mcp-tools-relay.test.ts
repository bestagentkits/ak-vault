/**
 * MCP tools relayed to an online device: every tool's happy path through a real
 * relay connection that signs its results, per-tool scope refusal, device error
 * codes, offline and disconnected devices, vault selection and the output guard.
 */
import { describe, expect, it } from 'vitest';
import { type JsonObject } from '@ak-vault/protocol';
import { guardResult } from '../src/mcp/tool-dispatch.js';
import { answerNext, callTool, mintMcpToken, structured } from './helpers/mcp-client.js';
import { readyRelay } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const ENTRY = { name: 'GITHUB_TOKEN', profile: { provider: { value: 'github', origin: 'local' } }, updated_at: 1_760_000_000_000 };

interface Case {
  tool: string;
  args: Record<string, unknown>;
  relayArgs: Record<string, unknown>;
  result: JsonObject;
  scope: string;
}

const CASES: Case[] = [
  { tool: 'search', args: { query: 'git', fields: ['name', 'provider'], limit: 5 }, relayArgs: { query: 'git', fields: ['name', 'provider'], limit: 5 }, result: { items: [ENTRY] }, scope: 'vault-mcp:read' },
  { tool: 'list', args: { limit: 10 }, relayArgs: { limit: 10 }, result: { items: [ENTRY], next_cursor: 'page-2' }, scope: 'vault-mcp:read' },
  { tool: 'describe', args: { name: 'GITHUB_TOKEN' }, relayArgs: { name: 'GITHUB_TOKEN' }, result: { name: 'GITHUB_TOKEN', profile: ENTRY.profile, sensitivity: 'high', created_at: 1, rotated_at: 2, last_device_label: 'laptop' }, scope: 'vault-mcp:read' },
  { tool: 'set', args: { name: 'NEW_KEY', value: 'v-123', sensitivity: 'high' }, relayArgs: { name: 'NEW_KEY', value: 'v-123', sensitivity: 'high' }, result: { status: 'written', revision: 3 }, scope: 'vault-mcp:write' },
  { tool: 'delete', args: { name: 'OLD_KEY' }, relayArgs: { name: 'OLD_KEY' }, result: { status: 'deleted' }, scope: 'vault-mcp:write' },
  { tool: 'request', args: { name: 'GITHUB_TOKEN', purpose: 'deploy', ttl_s: 600 }, relayArgs: { name: 'GITHUB_TOKEN', purpose: 'deploy', ttl_s: 600 }, result: { status: 'pending', request_id: 'req-1' }, scope: 'vault-mcp:use' },
  {
    tool: 'run',
    args: { argv: ['gh', 'auth', 'status'], env: [{ var: 'GH_TOKEN', name: 'GITHUB_TOKEN' }], timeout_s: 30 },
    relayArgs: { argv: ['gh', 'auth', 'status'], env: [{ var: 'GH_TOKEN', name: 'GITHUB_TOKEN' }], timeout_s: 30 },
    result: { exit_code: 0, stdout: 'Logged in with [REDACTED]', stderr: '', truncated: false },
    scope: 'vault-mcp:use',
  },
];

describe('MCP tools over the relay', () => {
  for (const c of CASES) {
    it(`secrets_${c.tool} relays to the online device and returns its verified result`, async () => {
      const fx = await VaultFixture.create();
      const conn = await readyRelay(fx.owner, [fx.vaultId]);
      const token = await mintMcpToken({ sub: fx.owner.account, scope: c.scope, clientId: 'client-a', grantId: 'grant-a' });
      for (const args of [c.args, { ...c.args, vault_id: fx.vaultId }]) {
        const pending = callTool(token, `secrets_${c.tool}`, args);
        const frame = await answerNext(conn, () => ({ ok: true, result: c.result }));
        expect(frame['tool']).toBe(c.tool);
        expect(frame['vault_id']).toBe(fx.vaultId);
        expect(frame['args']).toEqual(c.relayArgs);
        expect(frame['caller']).toEqual({ client_id: 'client-a', grant_id: 'grant-a', scopes: [c.scope] });
        const res = await pending;
        expect(res.json.result.isError).toBe(false);
        expect(res.json.result.resultType).toBe('complete');
        expect(structured(res)).toEqual(c.result);
        expect(JSON.parse(res.json.result.content[0].text)).toEqual(c.result);
      }
      conn.close();
    });

    it(`secrets_${c.tool} without ${c.scope} is 403 insufficient_scope naming the scopes needed`, async () => {
      const fx = await VaultFixture.create();
      const others = ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use'].filter((s) => s !== c.scope);
      const token = await mintMcpToken({ sub: fx.owner.account, scope: others.join(' ') });
      const res = await callTool(token, `secrets_${c.tool}`, c.args);
      expect(res.status).toBe(403);
      expect(res.json.error.code).toBe('forbidden');
      const challenge = res.headers.get('WWW-Authenticate')!;
      expect(challenge).toContain('error="insufficient_scope"');
      expect(challenge).toContain(`scope="${[...others, c.scope].join(' ')}"`);
      expect(challenge).toContain('resource_metadata=');
    });
  }

  it('maps device error codes to tool errors', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const token = await mintMcpToken({ sub: fx.owner.account });
    for (const code of ['pending_approval', 'denied', 'not_found', 'conflict', 'unsupported'] as const) {
      const pending = callTool(token, 'secrets_run', { argv: ['make'], env: [{ var: 'K', name: 'K' }] });
      await answerNext(conn, () => ({ ok: false, code }));
      const res = await pending;
      expect(res.status).toBe(200);
      expect(res.json.result.isError).toBe(true);
      expect(res.json.result.structuredContent.code).toBe(code);
    }
    conn.close();
  });

  it('read and use tools answer no_device_online with the relay hint when no device is online', async () => {
    const fx = await VaultFixture.create();
    const token = await mintMcpToken({ sub: fx.owner.account });
    for (const [tool, args] of [
      ['secrets_search', { query: 'x' }],
      ['secrets_list', {}],
      ['secrets_describe', { name: 'X' }],
      ['secrets_request', { name: 'X', purpose: 'p' }],
      ['secrets_run', { argv: ['true'], env: [{ var: 'A', name: 'X' }] }],
    ] as const) {
      for (const withVault of [false, true]) {
        const res = await callTool(token, tool, withVault ? { ...args, vault_id: fx.vaultId } : args);
        expect(res.json.result.isError, tool).toBe(true);
        expect(res.json.result.structuredContent).toEqual({ code: 'no_device_online', message: 'Start `ak secrets sync now --watch --relay` on one of your devices.' });
      }
    }
  });

  it('a device that disconnects mid-call yields device_timeout', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const token = await mintMcpToken({ sub: fx.owner.account });
    const pending = callTool(token, 'secrets_describe', { name: 'X' });
    expect((await conn.next())['type']).toBe('call');
    conn.close();
    const res = await pending;
    expect(res.json.result.structuredContent.code).toBe('device_timeout');
  });

  it('needs vault_id when the online devices hold several vaults', async () => {
    const a = await VaultFixture.create();
    const b = await VaultFixture.create('personal', a.owner.account);
    const connA = await readyRelay(a.owner, [a.vaultId]);
    const connB = await readyRelay(b.owner, [b.vaultId]);
    const token = await mintMcpToken({ sub: a.owner.account });
    const res = await callTool(token, 'secrets_list', {});
    expect(res.json.result.structuredContent.code).toBe('invalid_args');
    const pending = callTool(token, 'secrets_list', { vault_id: b.vaultId });
    const frame = await answerNext(connB, () => ({ ok: true, result: { items: [] } }));
    expect(frame['vault_id']).toBe(b.vaultId);
    expect(structured(await pending)).toEqual({ items: [] });
    connA.close();
    connB.close();
  });

  it('refuses invalid arguments before relaying, without echoing them', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const token = await mintMcpToken({ sub: fx.owner.account });
    const bad: [string, Record<string, unknown>][] = [
      ['secrets_search', { query: '' }],
      ['secrets_search', { query: 'x', extra: 'ARG_CANARY' }],
      ['secrets_list', { limit: 101 }],
      ['secrets_describe', {}],
      ['secrets_set', { name: 'ARG_CANARY' }],
      ['secrets_run', { argv: [], env: [] }],
      ['secrets_run', { argv: ['x'], env: [{ var: 'lower', name: 'ARG_CANARY' }] }],
      ['secrets_list', { vault_id: 'not-a-vault-ARG_CANARY' }],
    ];
    for (const [tool, args] of bad) {
      const res = await callTool(token, tool, args);
      expect(res.json.result.structuredContent.code, tool).toBe('invalid_args');
      expect(res.text).not.toContain('ARG_CANARY');
    }
    const unknown = await callTool(token, 'secrets_reveal', { name: 'X' });
    expect(unknown.json.error.code).toBe(-32602);
    // Nothing reached the device: the next frame it sees is the one call below.
    const pending = callTool(token, 'secrets_list', {});
    const frame = await answerNext(conn, () => ({ ok: true, result: { items: [] } }));
    expect(frame['tool']).toBe('list');
    await pending;
    conn.close();
  });

  it('refuses a device result carrying a value field (output guard) as internal', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const token = await mintMcpToken({ sub: fx.owner.account });
    const pending = callTool(token, 'secrets_describe', { name: 'X' });
    await answerNext(conn, () => ({ ok: true, result: { name: 'X', profile: {}, sensitivity: 'normal', value: 'LEAKED_VALUE' } }));
    const res = await pending;
    expect(res.json.result.structuredContent.code).toBe('internal');
    expect(res.text).not.toContain('LEAKED_VALUE');
    conn.close();
  });
});

describe('output guard', () => {
  it('allows profile field values and refuses value or secret keys anywhere else', () => {
    expect(guardResult('search', { items: [ENTRY] })).not.toBeNull();
    expect(guardResult('describe', { name: 'X', profile: ENTRY.profile, sensitivity: 'normal' })).not.toBeNull();
    expect(guardResult('describe', { name: 'X', profile: {}, sensitivity: 'normal', value: 's' })).toBeNull();
    expect(guardResult('search', { items: [{ ...ENTRY, secret: 's' }] })).toBeNull();
    expect(guardResult('set', { status: 'written', revision: 1, value: 's' })).toBeNull();
    expect(guardResult('run', { exit_code: 0, stdout: '', stderr: '', truncated: false })).not.toBeNull();
  });
});
