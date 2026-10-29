/**
 * Streamable HTTP transport of `/mcp`: MCP 2026-07-28 (stateless, POST only,
 * `server/discover`, mirrored headers) and stateless answers for 2025-11-25 clients.
 */
import { describe, expect, it } from 'vitest';
import { randomId } from '@ak-vault/protocol';
import { legacy, mcpPost, mintMcpToken, modern, modernMeta } from './helpers/mcp-client.js';

const token = () => mintMcpToken({ sub: `acct-${randomId()}` });

describe('MCP transport (2026-07-28)', () => {
  it('GET and DELETE are 405 with Allow: POST; OPTIONS is 204 without CORS headers', async () => {
    const t = await token();
    for (const method of ['GET', 'DELETE', 'PUT']) {
      const res = await mcpPost(t, null, { method });
      expect(res.status, method).toBe(405);
      expect(res.headers.get('Allow')).toBe('POST');
    }
    const options = await mcpPost(null, null, { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
    expect(options.status).toBe(204);
    for (const [name] of options.headers) expect(name.toLowerCase().startsWith('access-control-')).toBe(false);
  });

  it('server/discover lists both versions, the tools capability and server info', async () => {
    const res = await modern(await token(), 'server/discover');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('application/json');
    expect(res.headers.get('Mcp-Session-Id')).toBeNull();
    expect(res.json.id).toBe(1);
    expect(res.json.result).toMatchObject({
      resultType: 'complete',
      supportedVersions: ['2026-07-28', '2025-11-25'],
      capabilities: { tools: { listChanged: false } },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'ak-vault' } },
    });
    expect(typeof res.json.result.instructions).toBe('string');
  });

  it('tools/list returns the nine tools with closed input schemas and annotations', async () => {
    const res = await modern(await token(), 'tools/list');
    expect(res.status).toBe(200);
    expect(res.json.result).toMatchObject({ ttlMs: 300_000, cacheScope: 'private' });
    const tools = res.json.result.tools as { name: string; inputSchema: { additionalProperties: boolean; properties: Record<string, unknown> }; annotations: Record<string, unknown>; description: string }[];
    expect(tools.map((t) => t.name)).toEqual(['secrets_search', 'secrets_list', 'secrets_describe', 'secrets_set', 'secrets_delete', 'secrets_request', 'secrets_run', 'secrets_prepare_write', 'secrets_write_status']);
    for (const tool of tools) {
      expect(tool.inputSchema.additionalProperties, tool.name).toBe(false);
      expect(tool.inputSchema.properties['vault_id'], tool.name).toBeDefined();
      expect(typeof tool.annotations['readOnlyHint']).toBe('boolean');
      expect(tool.annotations['openWorldHint']).toBe(tool.name === 'secrets_run');
    }
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    for (const name of ['secrets_search', 'secrets_list', 'secrets_describe']) expect(byName[name]!.annotations['readOnlyHint']).toBe(true);
    expect(byName['secrets_set']!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: false });
    expect(byName['secrets_run']!.description).toContain('exec');
    expect(byName['secrets_request']!.description).toContain('approve');
    for (const tool of tools) if (tool.name !== 'secrets_set' && tool.name !== 'secrets_delete') expect(tool.description).toContain('never returned');
  });

  it('refuses an unsupported protocol version with -32022, the supported list and the request id', async () => {
    const t = await token();
    const res = await modern(t, 'server/discover', {}, { version: '2024-11-05' });
    expect(res.status).toBe(400);
    expect(res.json.id).toBe(1);
    expect(res.json.error).toEqual({ code: -32022, message: 'Unsupported protocol version', data: { supported: ['2026-07-28', '2025-11-25'], requested: '2024-11-05' } });
    const stringId = await mcpPost(t, { jsonrpc: '2.0', id: 'req-7', method: 'ping', params: {} }, { version: '2099-01-01' });
    expect(stringId.json).toMatchObject({ id: 'req-7', error: { code: -32022 } });
    // An unparseable body has no id to echo: `id` is null (JSON-RPC 2.0 §5).
    const unparseable = await mcpPost(t, null, { version: '2099-01-01', rawBody: '{"jsonrpc":' });
    expect(unparseable.status).toBe(400);
    expect(unparseable.json).toMatchObject({ id: null, error: { code: -32022 } });
  });

  it('refuses missing or mismatched Mcp-Method / Mcp-Name headers with 400 -32020', async () => {
    const t = await token();
    const cases = [
      await modern(t, 'tools/list', {}, { headers: { 'Mcp-Method': 'server/discover' } }),
      await mcpPost(t, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: modernMeta() } }),
      await modern(t, 'tools/call', { name: 'secrets_list', arguments: {} }, { headers: { 'Mcp-Name': 'secrets_search' } }),
      await mcpPost(t, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'secrets_list', _meta: modernMeta() } }, { headers: { 'Mcp-Method': 'tools/call' } }),
      await mcpPost(t, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: modernMeta('2025-11-25') } }, { headers: { 'Mcp-Method': 'tools/list' } }),
    ];
    for (const res of cases) {
      expect(res.status).toBe(400);
      expect(res.json.error.code).toBe(-32020);
    }
  });

  it('accepts a base64-sentinel Mcp-Name that decodes to the tool name', async () => {
    const t = await token();
    const encoded = `=?base64?${btoa('secrets_list')}?=`;
    const res = await modern(t, 'tools/call', { name: 'secrets_list', arguments: {} }, { headers: { 'Mcp-Name': encoded } });
    expect(res.status).toBe(200);
    expect(res.json.result.structuredContent.code).toBe('no_device_online');
  });

  it('refuses a request without the required _meta fields with 400 -32602', async () => {
    const t = await token();
    const res = await mcpPost(t, { jsonrpc: '2.0', id: 7, method: 'tools/list', params: {} }, { headers: { 'Mcp-Method': 'tools/list' } });
    expect(res.status).toBe(400);
    expect(res.json).toMatchObject({ id: 7, error: { code: -32602 } });
  });

  it('an unknown method is 404 -32601; initialize is not a modern method', async () => {
    const t = await token();
    for (const method of ['resources/list', 'initialize']) {
      const res = await modern(t, method);
      expect(res.status, method).toBe(404);
      expect(res.json.error.code).toBe(-32601);
    }
  });

  it('refuses batches, responses, bad JSON, a wrong content type and an Accept without event-stream', async () => {
    const t = await token();
    const batch = await mcpPost(t, [{ jsonrpc: '2.0', id: 1, method: 'ping' }]);
    expect(batch.status).toBe(400);
    expect(batch.json.error.code).toBe(-32600);
    const response = await mcpPost(t, { jsonrpc: '2.0', id: 1, result: {} });
    expect(response.json.error.code).toBe(-32600);
    const bad = await mcpPost(t, null, { rawBody: '{"jsonrpc":' });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe(-32700);
    const nullId = await mcpPost(t, { jsonrpc: '2.0', id: null, method: 'ping' });
    expect(nullId.json.error.code).toBe(-32600);
    expect((await modern(t, 'ping', {}, { headers: { 'Content-Type': 'text/plain' } })).status).toBe(415);
    expect((await modern(t, 'ping', {}, { headers: { Accept: 'application/json' } })).status).toBe(406);
    expect((await modern(t, 'ping', {}, { headers: { Accept: 'text/html' } })).status).toBe(406);
  });

  it('refuses a body over the request cap', async () => {
    const res = await mcpPost(await token(), null, { rawBody: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping', params: { pad: 'x'.repeat(300 * 1024) } }) });
    expect(res.status).toBe(413);
  });

  it('a notification is 202 with no body', async () => {
    const res = await mcpPost(await token(), { jsonrpc: '2.0', method: 'notifications/initialized' });
    expect(res.status).toBe(202);
    expect(res.text).toBe('');
  });

  it('allows a request without Origin or with an https Origin; refuses null, http and file origins with 403', async () => {
    const t = await token();
    expect((await modern(t, 'ping', {}, { headers: { Origin: 'https://claude.ai' } })).status).toBe(200);
    for (const origin of ['null', 'http://localhost:8080', 'file://', 'https://a.example/path']) {
      const res = await modern(t, 'ping', {}, { headers: { Origin: origin } });
      expect(res.status, origin).toBe(403);
    }
  });

  it('ignores a client Mcp-Session-Id and never sets one', async () => {
    const res = await modern(await token(), 'ping', {}, { headers: { 'Mcp-Session-Id': 'abc' } });
    expect(res.status).toBe(200);
    expect(res.json.result).toMatchObject({ resultType: 'complete' });
    expect(res.headers.get('Mcp-Session-Id')).toBeNull();
  });

  it('is 503 sync_disabled while the sync kill switch is off', async () => {
    const res = await modern(await token(), 'ping', {}, { env: { VAULT_SYNC_ENABLED: 'false' } });
    expect(res.status).toBe(503);
    expect(res.json.error.code).toBe('sync_disabled');
  });
});

describe('MCP transport (2025-11-25, stateless)', () => {
  it('answers initialize without a session id, with or without the version header', async () => {
    const t = await token();
    for (const version of ['2025-11-25', null]) {
      const res = await legacy(t, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'old', version: '1' } }, { version, headers: { Accept: 'application/json, text/event-stream' } });
      expect(res.status).toBe(200);
      expect(res.headers.get('Mcp-Session-Id')).toBeNull();
      expect(res.json.result).toEqual({
        protocolVersion: '2025-11-25',
        capabilities: { tools: { listChanged: false } },
        serverInfo: expect.objectContaining({ name: 'ak-vault' }),
        instructions: expect.any(String),
      });
    }
  });

  it('serves tools/list and ping without _meta or mirrored headers; tolerates a missing Accept', async () => {
    const t = await token();
    const list = await legacy(t, 'tools/list');
    expect(list.status).toBe(200);
    expect(list.json.result.resultType).toBeUndefined();
    expect(list.json.result.tools).toHaveLength(9);
    const ping = await mcpPost(t, { jsonrpc: '2.0', id: 'p', method: 'ping' }, { version: '2025-11-25', headers: { Accept: '' } });
    expect(ping.status).toBe(200);
    expect(ping.json).toEqual({ jsonrpc: '2.0', id: 'p', result: {} });
  });

  it('accepts notifications/initialized and answers an unknown method with 200 -32601 (server/discover included)', async () => {
    const t = await token();
    expect((await mcpPost(t, { jsonrpc: '2.0', method: 'notifications/initialized' }, { version: '2025-11-25' })).status).toBe(202);
    for (const method of ['server/discover', 'prompts/list']) {
      const res = await legacy(t, method);
      expect(res.status).toBe(200);
      expect(res.json.error.code).toBe(-32601);
    }
  });

  it('runs tools/call statelessly (no initialize needed)', async () => {
    const res = await legacy(await token(), 'tools/call', { name: 'secrets_search', arguments: { query: 'x' } });
    expect(res.status).toBe(200);
    expect(res.json.result.isError).toBe(true);
    expect(res.json.result.structuredContent.code).toBe('no_device_online');
  });
});
