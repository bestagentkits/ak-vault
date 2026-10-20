/**
 * No MCP path discloses a secret value or name: a sentinel written through the
 * relay and through the sealed fallback, plus device results and refusals, never
 * appears in a response body or header, in console output, or in Durable Object
 * storage (the sealed inbox holds only ciphertext).
 */
import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { randomId } from '@ak-vault/protocol';
import { relayStub } from '../src/relay/relay-rpc.js';
import { dumpDurableObject, findLeak } from './helpers/disclosure-scan.js';
import { answerNext, callTool, mintMcpToken, publishSealKey, type McpResponse } from './helpers/mcp-client.js';
import { readyRelay } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const CONSOLE = ['log', 'info', 'warn', 'error', 'debug'] as const;
let spies: MockInstance[] = [];
beforeEach(() => {
  spies = CONSOLE.map((m) => vi.spyOn(console, m));
});
afterEach(() => {
  for (const s of spies) s.mockRestore();
});

function consoleText(): string {
  return spies.flatMap((s) => s.mock.calls.map((args) => args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '))).join('\n');
}

function responseText(responses: McpResponse[]): string {
  return responses.map((r) => `${r.text}\n${[...r.headers].map(([k, v]) => `${k}: ${v}`).join('\n')}`).join('\n');
}

describe('MCP value disclosure', () => {
  it('never discloses a value or name written through the relay or the sealed fallback', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: fx.owner.account });
    const RELAY_NAME = `LEAK_RELAY_${randomId().replace(/-/g, '_').toUpperCase()}`;
    const RELAY_VALUE = `leak-relay-value-${randomId()}`;
    const SEALED_NAME = `LEAK_SEALED_${randomId().replace(/-/g, '_').toUpperCase()}`;
    const SEALED_VALUE = `leak-sealed-value-${randomId()}`;
    const responses: McpResponse[] = [];

    // Online: the write is relayed; the device's results carry no value.
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    let pending = callTool(token, 'secrets_set', { name: RELAY_NAME, value: RELAY_VALUE });
    const frame = await answerNext(conn, () => ({ ok: true, result: { status: 'written', revision: 1 } }));
    expect((frame['args'] as Record<string, unknown>)['value']).toBe(RELAY_VALUE);
    responses.push(await pending);
    // A device error and a refused (value-bearing) device result.
    pending = callTool(token, 'secrets_set', { name: RELAY_NAME, value: RELAY_VALUE });
    await answerNext(conn, () => ({ ok: false, code: 'conflict' }));
    responses.push(await pending);
    pending = callTool(token, 'secrets_describe', { name: RELAY_NAME });
    await answerNext(conn, () => ({ ok: true, result: { name: 'X', profile: {}, sensitivity: 'normal', value: RELAY_VALUE } }));
    responses.push(await pending);
    conn.close();

    // Offline: the write is sealed into the inbox.
    responses.push(await callTool(token, 'secrets_set', { name: SEALED_NAME, value: SEALED_VALUE, vault_id: fx.vaultId }));
    expect(responses.at(-1)!.json.result.structuredContent.status).toBe('queued');
    // Refusals that carry the sentinel in their arguments.
    responses.push(await callTool(token, 'secrets_set', { name: SEALED_NAME, value: SEALED_VALUE, extra: SEALED_VALUE, vault_id: fx.vaultId }));
    responses.push(await callTool(token, 'secrets_set', { name: SEALED_NAME, value: SEALED_VALUE, vault_id: randomId() }));
    responses.push(await callTool(await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:read' }), 'secrets_set', { name: SEALED_NAME, value: SEALED_VALUE }));

    const secrets = [RELAY_NAME, RELAY_VALUE, SEALED_NAME, SEALED_VALUE];
    expect(findLeak(responseText(responses), secrets)).toBeNull();
    expect(findLeak(consoleText(), [...secrets, token])).toBeNull();
    const relayDump = await dumpDurableObject(relayStub(env, fx.owner.account));
    expect(relayDump.tables).toContain('client_audit');
    expect(findLeak(relayDump.text, secrets)).toBeNull();
    const vaultDump = await dumpDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)));
    expect(findLeak(vaultDump.text, secrets)).toBeNull();
  });
});
