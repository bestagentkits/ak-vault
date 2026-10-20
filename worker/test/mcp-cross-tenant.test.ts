/**
 * Cross-tenant isolation: an MCP token reaches only its own account's relay and
 * vaults. Naming another account's vault looks exactly like naming a vault that
 * does not exist, never reaches that account's device and never seals into it.
 */
import { describe, expect, it } from 'vitest';
import { randomId } from '@ak-vault/protocol';
import { answerNext, callTool, mintMcpToken, publishSealKey, structured } from './helpers/mcp-client.js';
import { readyRelay } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

describe('MCP cross-tenant isolation', () => {
  it("another account's vault is indistinguishable from a missing one and never reaches its device", async () => {
    const a = await VaultFixture.create();
    const b = await VaultFixture.create();
    await publishSealKey(b);
    const connB = await readyRelay(b.owner, [b.vaultId]);
    const tokenA = await mintMcpToken({ sub: a.owner.account });

    const missing = await callTool(tokenA, 'secrets_describe', { name: 'X', vault_id: randomId() });
    expect(missing.json.result.structuredContent.code).toBe('invalid_args');
    for (const [tool, args] of [
      ['secrets_describe', { name: 'X' }],
      ['secrets_list', {}],
      ['secrets_run', { argv: ['env'], env: [{ var: 'K', name: 'K' }] }],
      ['secrets_set', { name: 'K', value: 'cross-tenant-value' }],
      ['secrets_delete', { name: 'K' }],
    ] as const) {
      const res = await callTool(tokenA, tool, { ...args, vault_id: b.vaultId });
      expect(res.status, tool).toBe(200);
      expect(res.json.result.structuredContent, tool).toEqual(missing.json.result.structuredContent);
      expect(res.text).not.toContain(b.vaultId);
    }
    // Without vault_id A sees no device: B's online device is not A's.
    expect((await callTool(tokenA, 'secrets_list')).json.result.structuredContent.code).toBe('no_device_online');

    // Nothing above reached B's device or B's sealed inbox.
    expect((await b.get(b.owner, '/sealed')).json.sealed).toEqual([]);
    const tokenB = await mintMcpToken({ sub: b.owner.account });
    const pending = callTool(tokenB, 'secrets_list');
    const frame = await answerNext(connB, () => ({ ok: true, result: { items: [] } }));
    expect(frame['tool']).toBe('list');
    expect(frame['vault_id']).toBe(b.vaultId);
    expect(structured(await pending)).toEqual({ items: [] });
    connB.close();
  });

  it("a token for one account cannot seal into another account's personal vault", async () => {
    const b = await VaultFixture.create();
    await publishSealKey(b);
    const tokenA = await mintMcpToken({ sub: `acct-${randomId()}` });
    const res = await callTool(tokenA, 'secrets_set', { name: 'K', value: 'v', vault_id: b.vaultId });
    expect(res.json.result.structuredContent.code).toBe('invalid_args');
    expect((await b.get(b.owner, '/sealed')).json.sealed).toEqual([]);
  });
});
