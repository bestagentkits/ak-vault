/**
 * Device relay after `hello`: `reauth`, token expiry, call dispatch with
 * per-call revocation and membership checks, results, rate budgets and audit.
 */
import { env } from 'cloudflare:workers';
import { runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { randomId, signResult, type JsonObject, type McpScope } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { AUDIT_MAX_ROWS, AUDIT_MAX_SUCCESS_ROWS, AUDIT_PRUNE_EVERY, ensureAuditSchema } from '../src/relay/account-relay-durable-object.js';
import { relayStub, type RelayCall } from '../src/relay/relay-rpc.js';
import { clientLogTag } from '../src/http/operational-logger.js';
import { createDevice } from './helpers/api-client.js';
import { openRelay, readyRelay, relayProof, relayToken, type RelayConnection } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { sendRevocation } from './helpers/webhook.js';

const ALL_SCOPES: McpScope[] = ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use'];

function listCall(overrides: Partial<RelayCall> = {}): RelayCall {
  return { tool: 'list', args: {}, caller: { clientId: 'client-1', grantId: 'grant-1', scopes: ALL_SCOPES }, deadlineMs: 5_000, ...overrides };
}

/** Wait for the next `call` frame on `conn`. */
async function nextCall(conn: RelayConnection): Promise<JsonObject> {
  const frame = await conn.next();
  expect(frame['type']).toBe('call');
  return frame;
}

describe('relay reauth', () => {
  it('a fresh token for the same sub and did is answered with ready and the new exp', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const exp = Math.floor(Date.now() / 1000) + 600;
    await conn.reauth(await relayToken(fx.owner, { claims: { exp } }));
    expect(await conn.next()).toEqual({ v: 1, type: 'ready', exp });
    conn.close();
  });

  it('closes 4401 for a token of another device or account, a bad proof or a replayed proof', async () => {
    const fx = await VaultFixture.create();
    const other = createDevice(fx.owner.account);
    const cases: ((c: RelayConnection) => Promise<void>)[] = [
      async (c) => c.reauth(await relayToken(fx.owner, { claims: { did: other.keys.record.device_id } })),
      async (c) => c.reauth(await relayToken(fx.owner, { claims: { sub: `acct-${randomId()}` } })),
      async (c) => c.reauth(await relayToken(fx.owner, { claims: { session_kind: undefined } })),
      async (c) => c.reauth('not.a.jwt', 'x'),
      async (c) => {
        const token = await relayToken(fx.owner);
        await c.reauth(token, relayProof(other, token));
      },
    ];
    for (const run of cases) {
      const conn = await readyRelay(fx.owner, [fx.vaultId]);
      await run(conn);
      expect((await conn.closedWith()).code).toBe(4401);
    }

    // A proof already burned at the upgrade cannot be reused for reauth.
    const token = await relayToken(fx.owner);
    const proof = relayProof(fx.owner, token);
    const conn = await readyRelay(fx.owner, [fx.vaultId], undefined, { token, proof });
    await conn.reauth(token, proof);
    expect((await conn.closedWith()).code).toBe(4401);
  });

  it('closes 4403 for a browser or single-scope token and 4401 for a revoked one', async () => {
    const fx = await VaultFixture.create();
    const browser = await readyRelay(fx.owner, [fx.vaultId]);
    await browser.reauth(await relayToken(fx.owner, { sessionKind: 'browser' }));
    expect((await browser.closedWith()).code).toBe(4403);

    const readOnly = await readyRelay(fx.owner, [fx.vaultId]);
    await readOnly.reauth(await relayToken(fx.owner, { scope: 'vault:read' }));
    expect((await readOnly.closedWith()).code).toBe(4403);

    const sid = `sid-${randomId()}`;
    const revoked = await readyRelay(fx.owner, [fx.vaultId]);
    expect((await sendRevocation({ revoke_sids: [sid] })).status).toBe(200);
    await revoked.reauth(await relayToken(fx.owner, { claims: { sid } }));
    expect((await revoked.closedWith()).code).toBe(4401);
  });

  it('more than relay_reauth_per_token_lifetime reauths in one token lifetime close 4429', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.relay_reauth_per_token_lifetime; i++) {
      await conn.reauth(await relayToken(fx.owner));
      expect((await conn.next())['type']).toBe('ready');
    }
    await conn.reauth(await relayToken(fx.owner));
    expect((await conn.closedWith()).code).toBe(4429);
  });

  it('reauth drops a vault the device left and closes 4403 when none remains', async () => {
    const fx = await VaultFixture.create();
    const second = await VaultFixture.create('personal', fx.owner.account);
    const device = await fx.addDevice();
    const { event, wraps } = second.enrollEvent(device);
    expect((await second.append(event, wraps)).status).toBe(201);
    const conn = await readyRelay(device, [fx.vaultId, second.vaultId]);
    expect((await fx.removeDevice(device)).status).toBe(201);
    await conn.reauth(await relayToken(device));
    expect((await conn.next())['type']).toBe('ready');
    expect(await relayStub(env, device.account).knownVaults()).toEqual([second.vaultId]);
    expect((await second.removeDevice(device)).status).toBe(201);
    await conn.reauth(await relayToken(device));
    expect((await conn.closedWith()).code).toBe(4403);
  });

  it('the alarm closes a connection whose token expired without reauth with 4401', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const stub = relayStub(env, fx.owner.account);
    await expireTokenInForce(fx.owner.account);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await conn.closedWith()).code).toBe(4401);
  });

  it('a reauth after the token in force expired closes 4401 even before the alarm fires', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    await expireTokenInForce(fx.owner.account);
    await conn.reauth(await relayToken(fx.owner));
    expect((await conn.closedWith()).code).toBe(4401);
  });
});

/** Mark every open relay connection of `account` as holding an expired token, without running the alarm. */
async function expireTokenInForce(account: string): Promise<void> {
  await runInDurableObject(relayStub(env, account), async (_instance, state) => {
    for (const ws of state.getWebSockets()) ws.serializeAttachment({ ...(ws.deserializeAttachment() as object), exp: Math.floor(Date.now() / 1000) - 1 });
  });
}

describe('relay dispatch', () => {
  it('relays a call to the device and returns its verified result', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const pending = relayStub(env, fx.owner.account).dispatch(listCall({ vaultId: fx.vaultId }));
    const callFrame = await nextCall(conn);
    expect(callFrame).toMatchObject({
      v: 1,
      vault_id: fx.vaultId,
      tool: 'list',
      args: {},
      caller: { client_id: 'client-1', grant_id: 'grant-1', scopes: ALL_SCOPES },
      deadline_ms: 5_000,
    });
    conn.result({ call_id: callFrame['call_id'] as string, ok: true, result: { items: [] } });
    expect(await pending).toEqual({ kind: 'result', ok: true, result: { items: [] }, deviceId: fx.owner.keys.record.device_id });
    conn.close();
  });

  it('picks the only announced vault when none is named, and refuses to guess between several', async () => {
    const fx = await VaultFixture.create();
    const second = await VaultFixture.create('personal', fx.owner.account);
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const pending = relayStub(env, fx.owner.account).dispatch(listCall());
    const callFrame = await nextCall(conn);
    expect(callFrame['vault_id']).toBe(fx.vaultId);
    conn.result({ call_id: callFrame['call_id'] as string, ok: false, error: { code: 'denied' } });
    expect(await pending).toEqual({ kind: 'result', ok: false, code: 'denied', deviceId: fx.owner.keys.record.device_id });

    const device = second.newDevice();
    const { event, wraps } = second.enrollEvent(device);
    expect((await second.append(event, wraps)).status).toBe(201);
    const two = await readyRelay(device, [second.vaultId]);
    expect(await relayStub(env, fx.owner.account).dispatch(listCall())).toEqual({ kind: 'invalid_args' });
    conn.close();
    two.close();
  });

  it('answers no_device_online without an announced device, and for a tool the device did not list', async () => {
    const fx = await VaultFixture.create();
    const stub = relayStub(env, fx.owner.account);
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    const unannounced = await openRelay(fx.owner);
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    unannounced.close();
    const conn = await readyRelay(fx.owner, [fx.vaultId], ['search']);
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    expect(await stub.dispatch(listCall({ vaultId: randomId() }))).toEqual({ kind: 'no_device_online' });
    conn.close();
  });

  it('does not relay across accounts', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    expect(await relayStub(env, `acct-${randomId()}`).dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    conn.close();
  });

  it('refuses a call the caller scopes do not cover and invalid arguments before relaying', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const stub = relayStub(env, fx.owner.account);
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId, caller: { clientId: 'c', grantId: 'g', scopes: ['vault-mcp:write'] } }))).toEqual({ kind: 'denied' });
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId, tool: 'set', args: { name: 'A' }, caller: { clientId: 'c', grantId: 'g', scopes: ALL_SCOPES } }))).toEqual({ kind: 'invalid_args' });
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId, args: { nope: 1 } }))).toEqual({ kind: 'invalid_args' });
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId, deadlineMs: 0 }))).toEqual({ kind: 'invalid_args' });
    conn.close();
  });

  it('caps deadline_ms at relay_call_deadline_ms', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const pending = relayStub(env, fx.owner.account).dispatch(listCall({ vaultId: fx.vaultId, deadlineMs: 10 * REMOTE_ACCESS_LIMITS.relay_call_deadline_ms }));
    const callFrame = await nextCall(conn);
    expect(callFrame['deadline_ms']).toBe(REMOTE_ACCESS_LIMITS.relay_call_deadline_ms);
    conn.result({ call_id: callFrame['call_id'] as string, ok: true, result: { items: [] } });
    expect((await pending).kind).toBe('result');
    conn.close();
  });

  it('a set or delete never goes to a reader device', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const conn = await readyRelay(reader, [fx.vaultId]);
    const stub = relayStub(env, reader.account);
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId, tool: 'set', args: { name: 'A', value: 'v' } }))).toEqual({ kind: 'no_device_online' });
    const pending = stub.dispatch(listCall({ vaultId: fx.vaultId }));
    const callFrame = await nextCall(conn);
    conn.result({ call_id: callFrame['call_id'] as string, ok: true, result: { items: [] } });
    expect((await pending).kind).toBe('result');
    conn.close();
  });

  it('checks revocation before each call: a revoked connection closes 4401 and gets no call', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    expect((await sendRevocation({ revoke_sids: [fx.owner.sid] })).status).toBe(200);
    expect(await relayStub(env, fx.owner.account).dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    expect((await conn.closedWith()).code).toBe(4401);
  });

  it('neither relays to nor announces a connection whose token expired before the alarm fired', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const stub = relayStub(env, fx.owner.account);
    expect(await stub.knownVaults()).toEqual([fx.vaultId]);
    await expireTokenInForce(fx.owner.account);
    expect(await stub.knownVaults()).toEqual([]);
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    expect(await stub.dispatch(listCall())).toEqual({ kind: 'no_device_online' });
    conn.close();
  });

  it('checks membership before each call: a removed device closes 4403 when no vault remains', async () => {
    const fx = await VaultFixture.create();
    const device = await fx.addDevice();
    const conn = await readyRelay(device, [fx.vaultId]);
    expect((await fx.removeDevice(device)).status).toBe(201);
    expect(await relayStub(env, device.account).dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'no_device_online' });
    expect((await conn.closedWith()).code).toBe(4403);
  });

  it('prefers the newest device and falls back to another when the newest is removed', async () => {
    const fx = await VaultFixture.create();
    const older = await readyRelay(fx.owner, [fx.vaultId]);
    const device = await fx.addDevice();
    const newer = await readyRelay(device, [fx.vaultId]);
    const stub = relayStub(env, fx.owner.account);
    let pending = stub.dispatch(listCall({ vaultId: fx.vaultId }));
    let callFrame = await nextCall(newer);
    newer.result({ call_id: callFrame['call_id'] as string, ok: true, result: { items: [] } });
    expect(await pending).toMatchObject({ kind: 'result', deviceId: device.keys.record.device_id });

    expect((await fx.removeDevice(device)).status).toBe(201);
    pending = stub.dispatch(listCall({ vaultId: fx.vaultId }));
    callFrame = await nextCall(older);
    older.result({ call_id: callFrame['call_id'] as string, ok: true, result: { items: [] } });
    expect(await pending).toMatchObject({ kind: 'result', deviceId: fx.owner.keys.record.device_id });
    expect((await newer.closedWith()).code).toBe(4403);
    older.close();
  });

  it('times out when the device does not answer, answers with a bad signature, or disconnects', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const stub = relayStub(env, fx.owner.account);
    const started = Date.now();
    const silent = stub.dispatch(listCall({ vaultId: fx.vaultId, deadlineMs: 50 }));
    await nextCall(conn);
    expect(await silent).toEqual({ kind: 'timeout' });
    expect(Date.now() - started).toBeGreaterThanOrEqual(50);

    const forged = stub.dispatch(listCall({ vaultId: fx.vaultId, deadlineMs: 50 }));
    const callFrame = await nextCall(conn);
    const stranger = createDevice(fx.owner.account);
    conn.send(signResult({ call_id: callFrame['call_id'] as string, ok: true, result: { items: [] } }, stranger.keys.signSecret) as unknown as JsonObject);
    expect(await forged).toEqual({ kind: 'timeout' });

    const dropped = stub.dispatch(listCall({ vaultId: fx.vaultId }));
    await nextCall(conn);
    conn.close();
    expect(await dropped).toEqual({ kind: 'timeout' });
  });

  it('reports an ok result that fails the tool result schema as internal', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const pending = relayStub(env, fx.owner.account).dispatch(listCall({ vaultId: fx.vaultId }));
    const callFrame = await nextCall(conn);
    conn.result({ call_id: callFrame['call_id'] as string, ok: true, result: { status: 'written' } });
    expect(await pending).toEqual({ kind: 'result', ok: false, code: 'internal', deviceId: fx.owner.keys.record.device_id });
    conn.close();
  });

  it('answers device_busy past relay_calls_inflight_per_device outstanding calls', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    const stub = relayStub(env, fx.owner.account);
    const inflight = [];
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.relay_calls_inflight_per_device; i++) inflight.push(stub.dispatch(listCall({ vaultId: fx.vaultId })));
    const frames = [];
    for (let i = 0; i < inflight.length; i++) frames.push(await nextCall(conn));
    expect(await stub.dispatch(listCall({ vaultId: fx.vaultId }))).toEqual({ kind: 'device_busy' });
    for (const f of frames) conn.result({ call_id: f['call_id'] as string, ok: true, result: { items: [] } });
    for (const p of inflight) expect((await p).kind).toBe('result');
    conn.close();
  });

  it('closes 4429 after more than relay_calls_inflight_per_device unsolicited results', async () => {
    const fx = await VaultFixture.create();
    const conn = await readyRelay(fx.owner, [fx.vaultId]);
    for (let i = 0; i <= REMOTE_ACCESS_LIMITS.relay_calls_inflight_per_device; i++) {
      conn.result({ call_id: randomId(), ok: true, result: { items: [] } });
    }
    expect((await conn.closedWith()).code).toBe(4429);
  });

  it('a result from a replaced connection does not answer the call', async () => {
    const fx = await VaultFixture.create();
    const first = await readyRelay(fx.owner, [fx.vaultId]);
    const pending = relayStub(env, fx.owner.account).dispatch(listCall({ vaultId: fx.vaultId }));
    await nextCall(first);
    await readyRelay(fx.owner, [fx.vaultId]);
    expect((await first.closedWith()).code).toBe(4409);
    expect(await pending).toEqual({ kind: 'timeout' });
  });
});

describe('relay rate budgets and audit', () => {
  it('spends per-client, per-run and per-account budgets per minute, and a refusal spends nothing', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    const t0 = 60_000 * 1_000_000;
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.mcp_run_calls_per_minute_per_client; i++) expect(await stub.takeRate('client-a', 'run', t0)).toEqual({ ok: true });
    const refused = await stub.takeRate('client-a', 'run', t0 + 1_500);
    expect(refused.ok).toBe(false);
    expect(refused.retryAfterS).toBe(59);
    // Other tools and other clients keep their own budgets.
    expect((await stub.takeRate('client-a', 'list', t0)).ok).toBe(true);
    expect((await stub.takeRate('client-b', 'run', t0)).ok).toBe(true);
    // A new minute starts fresh.
    expect((await stub.takeRate('client-a', 'run', t0 + 60_000)).ok).toBe(true);

    const perClient = REMOTE_ACCESS_LIMITS.mcp_calls_per_minute_per_client;
    const t1 = t0 + 120_000;
    for (let i = 0; i < perClient; i++) expect((await stub.takeRate('client-c', 'list', t1)).ok).toBe(true);
    expect((await stub.takeRate('client-c', 'list', t1)).ok).toBe(false);

    const t2 = t0 + 180_000;
    const perAccount = REMOTE_ACCESS_LIMITS.mcp_calls_per_minute_per_account;
    for (let i = 0; i < perAccount; i++) expect((await stub.takeRate(`client-${i % 10}`, 'list', t2)).ok).toBe(true);
    expect((await stub.takeRate('client-new', 'list', t2)).ok).toBe(false);
    expect(await stub.takeRate('bad\nclient', 'list', t0 + 240_000)).toEqual({ ok: false });
  });

  it('records hashed audit rows and drops rows older than 30 days', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    const clientHash = clientLogTag('client-1');
    const old = Date.now() - 31 * 24 * 60 * 60 * 1000;
    expect(await stub.recordAudit({ clientHash, tool: 'list', outcome: 'ok', ms: 12 }, old)).toBe(true);
    expect(await stub.recordAudit({ clientHash, tool: 'set', outcome: 'no_device_online', ms: 3 })).toBe(true);
    expect(await stub.recordAudit({ clientHash: 'client-1', tool: 'list', outcome: 'ok', ms: 1 })).toBe(false);
    expect(await stub.recordAudit({ clientHash, tool: 'list', outcome: 'Has Spaces', ms: 1 })).toBe(false);
    const rows = await runInDurableObject(stub, async (_instance, state) => state.storage.sql.exec('SELECT client_hash, tool, outcome, ms FROM client_audit').toArray());
    expect(rows).toEqual([{ client_hash: clientHash, tool: 'set', outcome: 'no_device_online', ms: 3 }]);
  });

  /** Insert `n` audit rows straight into the table, `ms` counting up from `from`, one `ts` tick apart. */
  async function seedAudit(stub: ReturnType<typeof relayStub>, n: number, outcome: string, success: 0 | 1, from = 0, ts0 = Date.now() - 60_000): Promise<void> {
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.transactionSync(() => {
        for (let i = 0; i < n; i++) {
          state.storage.sql.exec('INSERT INTO client_audit (ts, client_hash, tool, outcome, ms, success) VALUES (?, ?, ?, ?, ?, ?)', ts0 + from + i, 'a'.repeat(16), 'list', outcome, from + i, success);
        }
      });
    });
  }

  const auditCounts = (stub: ReturnType<typeof relayStub>) =>
    runInDurableObject(stub, async (_instance, state) => {
      const rows = state.storage.sql.exec<{ success: number; n: number; lo: number; hi: number }>('SELECT success, COUNT(*) AS n, MIN(ms) AS lo, MAX(ms) AS hi FROM client_audit GROUP BY success').toArray();
      return Object.fromEntries(rows.map((r) => [r.success, r]));
    });

  it('a flood of failing calls keeps the earlier success rows and only the newest failures', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    const clientHash = clientLogTag('client-1');
    expect(await stub.recordAudit({ clientHash, tool: 'set', outcome: 'ok', ms: 7 })).toBe(true);
    expect(await stub.recordAudit({ clientHash, tool: 'set', outcome: 'queued', ms: 8 })).toBe(true);
    await seedAudit(stub, AUDIT_MAX_ROWS + 50, 'invalid_args', 0);
    // The two successes above count toward the interval, so this insert is the 256th and prunes.
    const flood = AUDIT_PRUNE_EVERY - 2;
    for (let i = 0; i < flood; i++) expect(await stub.recordAudit({ clientHash, tool: 'list', outcome: 'no_device_online', ms: 1_000_000 + i })).toBe(true);
    const counts = await auditCounts(stub);
    expect(counts[1]).toMatchObject({ n: 2, lo: 7, hi: 8 });
    expect(counts[0]!.n).toBe(AUDIT_MAX_ROWS);
    expect(counts[0]!.hi).toBe(1_000_000 + flood - 1);
  });

  it('a flood of successful calls keeps the newest failure rows', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    const clientHash = clientLogTag('client-1');
    await seedAudit(stub, 3, 'denied', 0);
    await seedAudit(stub, AUDIT_MAX_SUCCESS_ROWS, 'ok', 1);
    // Failures are untouched by the success count, however large it is.
    for (let i = 0; i < AUDIT_PRUNE_EVERY; i++) expect(await stub.recordAudit({ clientHash, tool: 'list', outcome: 'ok', ms: 900_000 + i })).toBe(true);
    const counts = await auditCounts(stub);
    expect(counts[0]).toMatchObject({ n: 3, lo: 0, hi: 2 });
    expect(counts[1]!.n).toBe(AUDIT_MAX_SUCCESS_ROWS);
    expect(counts[1]!.hi).toBe(900_000 + AUDIT_PRUNE_EVERY - 1);
    expect(counts[1]!.lo).toBe(AUDIT_PRUNE_EVERY);
  });

  it('prunes only at the insert interval, not on every insert', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    const clientHash = clientLogTag('client-1');
    await seedAudit(stub, AUDIT_MAX_ROWS + 10, 'not_found', 0);
    for (let i = 0; i < AUDIT_PRUNE_EVERY - 1; i++) expect(await stub.recordAudit({ clientHash, tool: 'list', outcome: 'ok', ms: i })).toBe(true);
    expect((await auditCounts(stub))[0]!.n).toBe(AUDIT_MAX_ROWS + 10);
    expect(await stub.recordAudit({ clientHash, tool: 'list', outcome: 'ok', ms: 999 })).toBe(true);
    expect((await auditCounts(stub))[0]!.n).toBe(AUDIT_MAX_ROWS);
  });

  it('the startup prune trims a class that is over its cap and leaves a small table alone', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    const startupPrune = () => runInDurableObject(stub, async (instance) => (instance as unknown as { pruneAuditIfOverCap(): void }).pruneAuditIfOverCap());
    await seedAudit(stub, 100, 'ok', 1);
    await startupPrune();
    expect((await auditCounts(stub))[1]!.n).toBe(100);
    await seedAudit(stub, AUDIT_MAX_ROWS + 50, 'not_found', 0, 1_000);
    await startupPrune();
    const counts = await auditCounts(stub);
    expect(counts[0]!.n).toBe(AUDIT_MAX_ROWS);
    expect(counts[0]!.hi).toBe(1_000 + AUDIT_MAX_ROWS + 49);
    expect(counts[1]!.n).toBe(100);
  });

  it('the startup prune of a table under every cap reads only the two ends of the table', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    await seedAudit(stub, 2_000, 'ok', 1);
    const rowsRead = await runInDurableObject(stub, async (instance) => {
      const relay = instance as unknown as { sql: SqlStorage; pruneAuditIfOverCap(): void };
      const real = relay.sql;
      const cursors: SqlStorageCursor<Record<string, SqlStorageValue>>[] = [];
      relay.sql = { exec: (query: string, ...bindings: unknown[]) => { const cursor = real.exec(query, ...bindings); cursors.push(cursor); return cursor; } } as SqlStorage;
      try { relay.pruneAuditIfOverCap(); } finally { relay.sql = real; }
      return cursors.reduce((sum, cursor) => sum + cursor.rowsRead, 0);
    });
    expect(rowsRead).toBeLessThanOrEqual(2);
    expect((await auditCounts(stub))[1]!.n).toBe(2_000);
  });

  it('the startup prune of an empty table is a no-op', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    await runInDurableObject(stub, async (instance) => (instance as unknown as { pruneAuditIfOverCap(): void }).pruneAuditIfOverCap());
    expect(await auditCounts(stub)).toEqual({});
  });

  it('adds and backfills the class column on an audit table written before it existed', async () => {
    const stub = relayStub(env, `acct-${randomId()}`);
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec('DROP TABLE client_audit');
      sql.exec('CREATE TABLE client_audit (ts INTEGER NOT NULL, client_hash TEXT NOT NULL, tool TEXT NOT NULL, outcome TEXT NOT NULL, ms INTEGER NOT NULL)');
      for (const [i, outcome] of ['ok', 'queued', 'denied', 'no_device_online'].entries()) {
        sql.exec('INSERT INTO client_audit (ts, client_hash, tool, outcome, ms) VALUES (?, ?, ?, ?, ?)', Date.now(), 'a'.repeat(16), 'list', outcome, i);
      }
      ensureAuditSchema(state.storage);
      ensureAuditSchema(state.storage); // idempotent
      const rows = sql.exec<{ outcome: string; success: number }>('SELECT outcome, success FROM client_audit ORDER BY ms').toArray();
      expect(rows).toEqual([
        { outcome: 'ok', success: 1 },
        { outcome: 'queued', success: 1 },
        { outcome: 'denied', success: 0 },
        { outcome: 'no_device_online', success: 0 },
      ]);
      const indexes = sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'client_audit'").toArray().map((r) => r.name);
      expect(indexes).toEqual(expect.arrayContaining(['client_audit_ts', 'client_audit_class_ts']));
    });
  });
});