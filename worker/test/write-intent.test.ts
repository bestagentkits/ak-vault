/**
 * Human-only write requests (spec §9.9): `secrets_prepare_write` hands the AI client a
 * request ID and a form URL, the enrolled browser device claims it, writes the item as a
 * normal signed record and reports back. The Worker never sees a value; the request binds
 * account, vault, MCP grant and client, operation, target and revision, is single-use
 * under concurrency, expires, and fails closed on grant or device revocation.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { deriveSealKeyPair, openSealedOp, randomId, type SealedOpWire } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { relayStub } from '../src/relay/relay-rpc.js';
import { call, type CallResult } from './helpers/api-client.js';
import { dumpDurableObject, findLeak } from './helpers/disclosure-scan.js';
import { callTool, mintMcpToken, modern, publishSealKey, structured } from './helpers/mcp-client.js';
import { sendRevocation } from './helpers/webhook.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const BROWSER = { sessionKind: 'browser', idempotencyKey: null } as const;
const BROWSER_WRITE = { sessionKind: 'browser' } as const;

type Fixture = Awaited<ReturnType<typeof VaultFixture.create>>;

async function setup(opts: { seal?: boolean; account?: string } = {}) {
  const fx = await VaultFixture.create('personal', opts.account);
  if (opts.seal !== false) await publishSealKey(fx);
  const client = { sub: fx.owner.account, clientId: `client-${randomId()}`, grantId: `grant-${randomId()}` };
  const token = await mintMcpToken({ sub: client.sub, clientId: client.clientId, grantId: client.grantId, scope: 'vault-mcp:write' });
  return { fx, client, token };
}

async function prepare(token: string, fx: Fixture, args: Record<string, unknown> = {}) {
  const res = await callTool(token, 'secrets_prepare_write', { name: 'API_KEY', operation: 'create', vault_id: fx.vaultId, ...args });
  return { res, out: res.json.result.structuredContent as Record<string, string>, isError: res.json.result.isError as boolean };
}

function ridOf(formUrl: string): string {
  return new URL(formUrl).hash.slice('#write='.length);
}

const browser = (fx: Fixture, method: 'GET' | 'POST', rid: string, action: string, body?: unknown, device = fx.owner): Promise<CallResult> =>
  call(device, method, `/v1/write-intents/${rid}${action ? `/${action}` : ''}`, body, BROWSER);

async function pendingRequest(args: Record<string, unknown> = {}) {
  const s = await setup();
  const p = await prepare(s.token, s.fx, args);
  expect(p.isError).toBe(false);
  return { ...s, rid: ridOf(p.out['form_url']!), out: p.out };
}

const statusOf = async (token: string, rid: string) => structured(await callTool(token, 'secrets_write_status', { request_id: rid })) as { status?: string; code?: string };

afterEach(() => vi.restoreAllMocks());

describe('secrets_prepare_write', () => {
  it('returns a request ID, a fragment URL and pending_user; the tools take no value', async () => {
    const { fx, token } = await setup();
    const p = await prepare(token, fx);
    expect(p.isError).toBe(false);
    expect(Object.keys(p.out).sort()).toEqual(['expires_at', 'form_url', 'request_id', 'status']);
    expect(p.out['status']).toBe('pending_user');
    const url = new URL(p.out['form_url']!);
    expect(url.origin + url.pathname).toBe(`${new URL(p.out['form_url']!).origin}/app/`);
    expect(url.search).toBe('');
    expect(url.hash).toBe(`#write=${p.out['request_id']}`);
    const ttl = Date.parse(p.out['expires_at']!) - Date.now();
    expect(ttl).toBeGreaterThan((REMOTE_ACCESS_LIMITS.write_intent_ttl_s - 5) * 1000);
    expect(ttl).toBeLessThanOrEqual(REMOTE_ACCESS_LIMITS.write_intent_ttl_s * 1000);

    const list = await modern(token, 'tools/list');
    const tools = list.json.result.tools as { name: string; inputSchema: { properties: Record<string, unknown>; additionalProperties: boolean } }[];
    for (const name of ['secrets_prepare_write', 'secrets_write_status']) {
      const tool = tools.find((t) => t.name === name)!;
      expect(Object.keys(tool.inputSchema.properties)).not.toContain('value');
      expect(tool.inputSchema.additionalProperties).toBe(false);
    }
  });

  it('refuses a value argument, a missing operation and bad ids', async () => {
    const { fx, token } = await setup();
    for (const args of [{ value: 'x' }, { operation: 'upsert' }, { sensitivity: 'secret' }, { vault_id: 'nope' }, { name: '' }]) {
      const p = await prepare(token, fx, args);
      expect(p.out['code']).toBe('invalid_args');
    }
    const noOp = await callTool(token, 'secrets_prepare_write', { name: 'K', vault_id: fx.vaultId });
    expect(noOp.json.result.structuredContent.code).toBe('invalid_args');
  });

  it('needs vault-mcp:write, an owner or editor account and a seal key', async () => {
    const { fx } = await setup();
    const readToken = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:read' });
    const denied = await callTool(readToken, 'secrets_prepare_write', { name: 'K', operation: 'create', vault_id: fx.vaultId });
    expect(denied.status).toBe(403);

    const shared = await VaultFixture.create('shared');
    const reader = await shared.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    await publishSealKey(shared);
    const readerToken = await mintMcpToken({ sub: reader.account, scope: 'vault-mcp:write' });
    expect((await prepare(readerToken, shared)).out['code']).toBe('denied');

    const noSeal = await setup({ seal: false });
    expect((await prepare(noSeal.token, noSeal.fx)).out['code']).toBe('no_seal_key');
  });

  it('is not available to an account that is not a member of the vault', async () => {
    const { fx } = await setup();
    const stranger = await mintMcpToken({ sub: `acct-${randomId()}`, scope: 'vault-mcp:write' });
    expect((await prepare(stranger, fx)).out['code']).toBe('invalid_args');
  });

  it('caps the unfinished requests per MCP client, so one client cannot take every slot', async () => {
    const { fx, token } = await setup();
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.write_intents_open_per_client; i++) expect((await prepare(token, fx, { name: `K${i}` })).isError).toBe(false);
    expect((await prepare(token, fx)).out['code']).toBe('too_many_open');
    // Another client of the same account still gets a slot.
    const other = await mintMcpToken({ sub: fx.owner.account, clientId: `client-${randomId()}`, grantId: `grant-${randomId()}`, scope: 'vault-mcp:write' });
    expect((await prepare(other, fx)).isError).toBe(false);
  });

  it('caps the unfinished requests per account', async () => {
    const { fx } = await setup();
    let opened = 0;
    for (let c = 0; opened < REMOTE_ACCESS_LIMITS.write_intents_open_per_account; c++) {
      const token = await mintMcpToken({ sub: fx.owner.account, clientId: `client-${randomId()}`, grantId: `grant-${randomId()}`, scope: 'vault-mcp:write' });
      for (let i = 0; i < REMOTE_ACCESS_LIMITS.write_intents_open_per_client && opened < REMOTE_ACCESS_LIMITS.write_intents_open_per_account; i++, opened++) {
        expect((await prepare(token, fx, { name: `K${c}-${i}` })).isError).toBe(false);
      }
    }
    const last = await mintMcpToken({ sub: fx.owner.account, clientId: `client-${randomId()}`, grantId: `grant-${randomId()}`, scope: 'vault-mcp:write' });
    expect((await prepare(last, fx)).out['code']).toBe('too_many_open');
  });
});

describe('browser write flow', () => {
  it('create: view -> claim -> signed item write -> complete; the MCP client sees completed', async () => {
    const { fx, token, rid } = await pendingRequest({ name: 'DB_PASSWORD', sensitivity: 'high' });
    expect(await statusOf(token, rid)).toMatchObject({ status: 'pending_user' });

    const view = await browser(fx, 'GET', rid, '');
    expect(view.status).toBe(200);
    expect(view.json).toMatchObject({ request_id: rid, vault_id: fx.vaultId, operation: 'create', sensitivity: 'high', status: 'pending_user' });
    const wire = view.json.target as SealedOpWire;
    const opened = openSealedOp(deriveSealKeyPair(fx.vk.get(wire.key_epoch)!, fx.vaultId, wire.key_epoch).secretKey, wire, { vaultId: fx.vaultId });
    expect(opened.op).toEqual({ op: 'set', name: 'DB_PASSWORD', value: '', sensitivity: 'high' });

    const itemId = randomId();
    expect((await browser(fx, 'POST', rid, 'claim', { item_id: itemId, base_revision: 0 })).json).toMatchObject({ status: 'processing' });
    expect(await statusOf(token, rid)).toMatchObject({ status: 'processing' });
    expect((await fx.write(fx.owner, itemId, 0, { name: 'DB_PASSWORD', value: 'typed-by-the-user' }, BROWSER_WRITE)).status).toBe(200);
    const done = await browser(fx, 'POST', rid, 'complete');
    expect(done.status).toBe(200);
    expect(done.json.status).toBe('completed');
    expect(await statusOf(token, rid)).toMatchObject({ status: 'completed' });
    // Terminal: nothing moves it again.
    expect((await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 })).status).toBe(409);
    expect((await browser(fx, 'POST', rid, 'cancel')).status).toBe(409);
  });

  it('replace: binds the live revision; a stale base is a conflict', async () => {
    const s = await setup();
    const { fx, token } = s;
    const itemId = randomId();
    expect((await fx.write(fx.owner, itemId, 0, { name: 'K', value: 'v1' })).status).toBe(200);
    expect((await fx.write(fx.owner, itemId, 1, { name: 'K', value: 'v2' })).status).toBe(200);

    const stale = ridOf((await prepare(token, fx, { name: 'K', operation: 'replace' })).out['form_url']!);
    const bad = await browser(fx, 'POST', stale, 'claim', { item_id: itemId, base_revision: 1 });
    expect(bad.status).toBe(409);
    expect(bad.json.error.status).toBe('conflict');
    expect(await statusOf(token, stale)).toMatchObject({ status: 'conflict' });

    const ok = ridOf((await prepare(token, fx, { name: 'K', operation: 'replace' })).out['form_url']!);
    expect((await browser(fx, 'POST', ok, 'claim', { item_id: itemId, base_revision: 2 })).status).toBe(200);
    expect((await fx.write(fx.owner, itemId, 2, { name: 'K', value: 'v3' }, BROWSER_WRITE)).status).toBe(200);
    expect(await statusOf(token, ok)).toMatchObject({ status: 'completed' });
  });

  it('create refuses an item that already exists; replace refuses a missing or deleted one', async () => {
    const { fx, token } = await setup();
    const existing = randomId();
    expect((await fx.write(fx.owner, existing, 0, { name: 'K', value: 'v' })).status).toBe(200);
    const create = ridOf((await prepare(token, fx, { name: 'K', operation: 'create' })).out['form_url']!);
    expect((await browser(fx, 'POST', create, 'claim', { item_id: existing, base_revision: 1 })).status).toBe(409);
    expect(await statusOf(token, create)).toMatchObject({ status: 'conflict' });

    const replace = ridOf((await prepare(token, fx, { name: 'NEW', operation: 'replace' })).out['form_url']!);
    expect((await browser(fx, 'POST', replace, 'claim', { item_id: randomId(), base_revision: 0 })).status).toBe(409);
    expect(await statusOf(token, replace)).toMatchObject({ status: 'conflict' });

    expect((await fx.write(fx.owner, existing, 1, null)).status).toBe(200);
    const deleted = ridOf((await prepare(token, fx, { name: 'K', operation: 'replace' })).out['form_url']!);
    expect((await browser(fx, 'POST', deleted, 'claim', { item_id: existing, base_revision: 2 })).status).toBe(409);
  });

  it('exactly one of many concurrent claims wins', async () => {
    const { fx, token, rid } = await pendingRequest();
    const results = await Promise.all(Array.from({ length: 6 }, () => browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409)).toHaveLength(5);
    expect(await statusOf(token, rid)).toMatchObject({ status: 'processing' });
  });

  it('two requests cannot be written by one record: the second claim of the same item and revision is refused', async () => {
    const s = await setup();
    const { fx, token } = s;
    const itemId = randomId();
    expect((await fx.write(fx.owner, itemId, 0, { name: 'K', value: 'v1' })).status).toBe(200);
    const first = ridOf((await prepare(token, fx, { name: 'K', operation: 'replace' })).out['form_url']!);
    const second = ridOf((await prepare(token, fx, { name: 'K', operation: 'replace' })).out['form_url']!);
    expect((await browser(fx, 'POST', first, 'claim', { item_id: itemId, base_revision: 1 })).status).toBe(200);
    const refused = await browser(fx, 'POST', second, 'claim', { item_id: itemId, base_revision: 1 });
    expect(refused.status).toBe(409);
    expect(await statusOf(token, second)).toMatchObject({ status: 'conflict' });
    expect((await fx.write(fx.owner, itemId, 1, { name: 'K', value: 'v2' }, BROWSER_WRITE)).status).toBe(200);
    expect(await statusOf(token, first)).toMatchObject({ status: 'completed' });
    expect(await statusOf(token, second)).toMatchObject({ status: 'conflict' });
  });

  it('a claim and a cancel racing leave one outcome', async () => {
    const { fx, token, rid } = await pendingRequest();
    const [claim, cancel] = await Promise.all([browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 }), browser(fx, 'POST', rid, 'cancel')]);
    expect([claim.status, cancel.status].sort()).toEqual([200, 409]);
    expect((await statusOf(token, rid)).status).toBe(claim.status === 200 ? 'processing' : 'cancelled');
  });

  it('cancel and fail end the request', async () => {
    const { fx, token, rid } = await pendingRequest();
    expect((await browser(fx, 'POST', rid, 'cancel')).json.status).toBe('cancelled');
    expect(await statusOf(token, rid)).toMatchObject({ status: 'cancelled' });
    expect((await browser(fx, 'GET', rid, '')).status).toBe(409);

    const second = await pendingRequest();
    expect((await browser(second.fx, 'POST', second.rid, 'claim', { item_id: randomId(), base_revision: 0 })).status).toBe(200);
    expect((await browser(second.fx, 'POST', second.rid, 'fail', { reason: 'failed' })).json.status).toBe('failed');
    expect(await statusOf(second.token, second.rid)).toMatchObject({ status: 'failed' });
  });

  it('reconciles with the vault: a landed write completes it even if the browser never reported', async () => {
    const { fx, token, rid } = await pendingRequest();
    const itemId = randomId();
    await browser(fx, 'POST', rid, 'claim', { item_id: itemId, base_revision: 0 });
    expect((await fx.write(fx.owner, itemId, 0, { name: 'API_KEY', value: 'v' }, BROWSER_WRITE)).status).toBe(200);
    expect(await statusOf(token, rid)).toMatchObject({ status: 'completed' });
    // The browser reporting failure afterwards cannot undo what the vault shows.
    expect((await browser(fx, 'POST', rid, 'fail', { reason: 'failed' })).json.status).toBe('completed');
  });

  it('a claimed request whose write never lands fails after the processing window', async () => {
    const { fx, token, rid } = await pendingRequest();
    await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 });
    expect(await statusOf(token, rid)).toMatchObject({ status: 'processing' });
    const stub = relayStub(env, fx.owner.account);
    await runInDurableObject(stub, (_i: unknown, state: DurableObjectState) => {
      state.storage.sql.exec('UPDATE write_intent SET claimed_at = ?', Date.now() - (REMOTE_ACCESS_LIMITS.write_intent_processing_s + 1) * 1000);
    });
    expect(await statusOf(token, rid)).toMatchObject({ status: 'failed' });
  });

  it('another device writing the item first makes it a conflict', async () => {
    const { fx, token, rid } = await pendingRequest();
    const other = await fx.addDevice();
    const itemId = randomId();
    await browser(fx, 'POST', rid, 'claim', { item_id: itemId, base_revision: 0 });
    expect((await fx.write(other, itemId, 0, { name: 'API_KEY', value: 'x' })).status).toBe(200);
    expect(await statusOf(token, rid)).toMatchObject({ status: 'conflict' });
  });

  it('expires after its TTL', async () => {
    const { fx, token, rid } = await pendingRequest();
    await runInDurableObject(relayStub(env, fx.owner.account), (_i: unknown, state: DurableObjectState) => {
      state.storage.sql.exec('UPDATE write_intent SET expires_at = ?', Date.now() - 1);
    });
    const view = await browser(fx, 'GET', rid, '');
    expect(view.status).toBe(409);
    expect(view.json.error.status).toBe('expired');
    expect((await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 })).status).toBe(409);
    expect(await statusOf(token, rid)).toMatchObject({ status: 'expired' });
  });

  it('purges requests past retention', async () => {
    const { fx, token, rid } = await pendingRequest();
    await browser(fx, 'POST', rid, 'cancel');
    const stub = relayStub(env, fx.owner.account);
    await runInDurableObject(stub, async (instance: { alarm(): Promise<void> }, state: DurableObjectState) => {
      state.storage.sql.exec('UPDATE write_intent SET ended_at = ?', Date.now() - (REMOTE_ACCESS_LIMITS.write_intent_retention_s + 1) * 1000);
      await instance.alarm();
      expect(state.storage.sql.exec('SELECT COUNT(*) AS n FROM write_intent').one()['n']).toBe(0);
    });
    expect(await statusOf(token, rid)).toMatchObject({ code: 'not_found' });
  });
});

describe('isolation and authorization', () => {
  it('status is bound to the grant and client that asked', async () => {
    const { fx, client, rid } = await pendingRequest();
    const otherClient = await mintMcpToken({ sub: client.sub, clientId: 'other-client', grantId: client.grantId, scope: 'vault-mcp:write' });
    const otherGrant = await mintMcpToken({ sub: client.sub, clientId: client.clientId, grantId: 'other-grant', scope: 'vault-mcp:write' });
    const otherUser = await mintMcpToken({ sub: `acct-${randomId()}`, clientId: client.clientId, grantId: client.grantId, scope: 'vault-mcp:write' });
    for (const token of [otherClient, otherGrant, otherUser]) expect((await statusOf(token, rid)).code).toBe('not_found');
    expect(fx.vaultId).toBeTruthy();
  });

  it("another account's browser cannot see or finish the request", async () => {
    const { rid } = await pendingRequest();
    const intruder = await VaultFixture.create();
    for (const [method, action, body] of [['GET', '', undefined], ['POST', 'claim', { item_id: randomId(), base_revision: 0 }], ['POST', 'cancel', undefined]] as const) {
      expect((await browser(intruder, method, rid, action, body)).status).toBe(404);
    }
  });

  it("a device of the same account that is not a member of the request's vault is refused", async () => {
    const { fx, rid } = await pendingRequest();
    const otherVault = await VaultFixture.create('personal', fx.owner.account);
    const res = await browser(otherVault, 'GET', rid, '');
    expect(res.status).toBe(403);
  });

  it('a removed device is refused', async () => {
    const { fx, rid } = await pendingRequest();
    const device = await fx.addDevice();
    expect((await browser(fx, 'GET', rid, '', undefined, device)).status).toBe(200);
    expect((await fx.removeDevice(device)).status).toBe(201);
    expect((await browser(fx, 'GET', rid, '', undefined, device)).status).toBe(403);
  });

  it('only a browser session, with a device key and a fresh proof, may call', async () => {
    const { fx, rid } = await pendingRequest();
    const path = `/v1/write-intents/${rid}`;
    for (const sessionKind of [undefined, 'email_otp', 'machine', 'api_key_device']) {
      const res = await call(fx.owner, 'GET', path, undefined, { ...(sessionKind ? { sessionKind } : {}), idempotencyKey: null });
      expect(res.status).toBe(403);
    }
    expect((await call(null, 'GET', path)).status).toBe(401);
    expect((await call(fx.owner, 'GET', path, undefined, { ...BROWSER, proof: null })).status).toBe(401);
    expect((await call(fx.owner, 'GET', path, undefined, { ...BROWSER, proofUrl: `https://vault.agentkit.best/v1/write-intents/${randomId()}` })).status).toBe(401);
    expect((await call(fx.owner, 'GET', path, undefined, { ...BROWSER, proofSecret: new Uint8Array(32).fill(7) })).status).toBe(401);
    const claimBody = { item_id: randomId(), base_revision: 0 };
    expect((await call(fx.owner, 'POST', `${path}/claim`, claimBody, { ...BROWSER, proofBody: new Uint8Array([1]) })).status).toBe(401);
    // Still pending: none of the refused calls moved it.
    expect((await browser(fx, 'GET', rid, '')).status).toBe(200);
  });

  it('a proof is single-use', async () => {
    const { fx, rid } = await pendingRequest();
    const first = await browser(fx, 'GET', rid, '');
    expect(first.status).toBe(200);
    const replay = await call(fx.owner, 'GET', `/v1/write-intents/${rid}`, undefined, { ...BROWSER, token: first.token, proof: first.proof });
    expect(replay.status).toBe(401);
  });

  it('rejects malformed ids, unknown actions, methods and bodies', async () => {
    const { fx, rid } = await pendingRequest();
    expect((await call(fx.owner, 'GET', '/v1/write-intents/not-an-id', undefined, BROWSER)).status).toBe(400);
    expect((await call(fx.owner, 'POST', `/v1/write-intents/${rid}/purge`, undefined, BROWSER)).status).toBe(404);
    expect((await call(fx.owner, 'POST', `/v1/write-intents/${rid}`, undefined, BROWSER)).status).toBe(404);
    expect((await browser(fx, 'POST', rid, 'claim', { item_id: 'x', base_revision: 0 })).status).toBe(400);
    expect((await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: -1 })).status).toBe(400);
    expect((await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0, value: 'x' })).status).toBe(400);
    expect((await browser(fx, 'POST', rid, 'fail', { reason: 'other' })).status).toBe(400);
    expect((await browser(fx, 'POST', rid, 'cancel', { x: 1 })).status).toBe(400);
  });

  it('only the claiming device completes or fails a claimed request', async () => {
    const { fx, rid } = await pendingRequest();
    const other = await fx.addDevice();
    await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 });
    expect((await browser(fx, 'POST', rid, 'complete', undefined, other)).status).toBe(403);
    expect((await browser(fx, 'POST', rid, 'fail', { reason: 'failed' }, other)).status).toBe(403);
  });

  it('a revoked MCP grant fails closed and cancels the request', async () => {
    const { fx, client, token, rid } = await pendingRequest();
    expect((await sendRevocation({ revoke_sids: [client.grantId] })).status).toBe(200);
    const res = await browser(fx, 'POST', rid, 'claim', { item_id: randomId(), base_revision: 0 });
    expect(res.status).toBe(401);
    // The revoked grant cannot poll, so read the account object's own state.
    const row = await runInDurableObject(relayStub(env, fx.owner.account), (_i: unknown, state: DurableObjectState) => state.storage.sql.exec('SELECT status FROM write_intent').one()['status']);
    expect(row).toBe('cancelled');
    expect((await callTool(token, 'secrets_write_status', { request_id: rid })).status).toBe(401);
  });

  it('a revoked browser device fails closed', async () => {
    const { fx, rid } = await pendingRequest();
    expect((await sendRevocation({ revoke_sids: [fx.owner.sid] })).status).toBe(200);
    expect((await browser(fx, 'GET', rid, '')).status).toBe(401);
  });

  it('is a 404 while remote access is off', async () => {
    const { fx, rid } = await pendingRequest();
    const res = await call(fx.owner, 'GET', `/v1/write-intents/${rid}`, undefined, { ...BROWSER, env: { VAULT_REMOTE_ACCESS_ENABLED: 'false' } });
    expect(res.status).toBe(404);
  });

  it('limits browser calls per device', async () => {
    const { fx, rid } = await pendingRequest();
    let last = 0;
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.write_intent_calls_per_minute_per_device + 1; i++) last = (await browser(fx, 'GET', rid, '')).status;
    expect(last).toBe(429);
  });
});

describe('plaintext boundary', () => {
  it('neither the name nor the value reaches MCP results, logs or any stored table in the clear', async () => {
    const NAME = 'SENTINEL_NAME_5f1d9c';
    const VALUE = 'SENTINEL_VALUE_a83b27e9c41d';
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));
    vi.spyOn(console, 'warn').mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' ')));

    const { fx, token } = await setup();
    const p = await prepare(token, fx, { name: NAME });
    const rid = ridOf(p.out['form_url']!);
    const itemId = randomId();
    await browser(fx, 'POST', rid, 'claim', { item_id: itemId, base_revision: 0 });
    expect((await fx.write(fx.owner, itemId, 0, { name: NAME, value: VALUE }, BROWSER_WRITE)).status).toBe(200);
    await browser(fx, 'POST', rid, 'complete');
    const status = await callTool(token, 'secrets_write_status', { request_id: rid });

    const responses = JSON.stringify([p.res.json, status.json]);
    expect(findLeak(responses, [NAME, VALUE])).toBeNull();
    expect(findLeak(logs.join('\n'), [NAME, VALUE, rid])).toBeNull();
    const relayDump = await dumpDurableObject(relayStub(env, fx.owner.account));
    expect(relayDump.tables).toContain('write_intent');
    expect(findLeak(relayDump.text, [NAME, VALUE])).toBeNull();
    const vaultDump = await dumpDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)));
    expect(findLeak(vaultDump.text, [NAME, VALUE])).toBeNull();
  });
});
