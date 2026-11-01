/**
 * Sealed-operation inbox: the server stores opaque sealed ops queued by the MCP
 * handler (RPC only) and serves them to writer devices of the origin account.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { cjson, deriveSealKeyPair, parseSealedOp, randomId, sealOp, type JsonObject, type SealedOpWire } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { applyVaultSchema } from '../src/vault/vault-schema.js';
import { sendRevocation } from './helpers/webhook.js';
import { call as rawCall, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const TTL_MS = REMOTE_ACCESS_LIMITS.sealed_ttl_s * 1000;

function sealFor(fx: VaultFixture, opts: { account?: string; ts?: number; keyEpoch?: number; vaultId?: string; grantId?: string } = {}): SealedOpWire {
  const keyEpoch = opts.keyEpoch ?? fx.keyEpoch;
  const { publicKey } = deriveSealKeyPair(fx.vk.get(keyEpoch)!, fx.vaultId, keyEpoch);
  return sealOp(publicKey, {
    vaultId: opts.vaultId ?? fx.vaultId,
    keyEpoch,
    origin: { kind: 'mcp', account: opts.account ?? fx.owner.account, client_id: 'client-1', grant_id: opts.grantId ?? 'grant-1' },
    ts: opts.ts ?? Date.now(),
    op: { op: 'set', name: 'API_TOKEN', value: 'secret-value' },
  });
}

function enqueue(fx: VaultFixture, wire: unknown, nowMs?: number, tokenIat = 0) {
  const stub = env.VAULT.get(env.VAULT.idFromName(fx.vaultId));
  return nowMs === undefined ? stub.enqueueSealed(wire, tokenIat) : stub.enqueueSealed(wire, tokenIat, nowMs);
}

function call(fx: VaultFixture, device: TestDevice, method: string, sub: string, body?: unknown, opts: CallOptions = {}) {
  return rawCall(device, method, `/v1/vaults/${fx.vaultId}${sub}`, body, opts);
}

function ack(fx: VaultFixture, device: TestDevice, sealedId: string, outcome: unknown = 'applied', opts: CallOptions = {}) {
  return call(fx, device, 'POST', `/sealed/${sealedId}/ack`, { outcome }, opts);
}

describe('sealed inbox', () => {
  it('queues an op, serves it verbatim to the origin account and drops it on ack', async () => {
    const fx = await VaultFixture.create();
    const wire = sealFor(fx);
    expect(await enqueue(fx, wire)).toBe('queued');
    const page = await fx.get(fx.owner, '/sealed');
    expect(page.status).toBe(200);
    expect(page.json.next).toBeNull();
    expect(page.json.sealed).toHaveLength(1);
    expect(cjson(page.json.sealed[0].op as JsonObject)).toBe(cjson(wire as unknown as JsonObject));
    expect(parseSealedOp(page.json.sealed[0].op)).toEqual(wire);

    const done = await ack(fx, fx.owner, wire.sealed_id);
    expect(done.status).toBe(200);
    expect(done.json).toEqual({});
    expect((await fx.get(fx.owner, '/sealed')).json.sealed).toEqual([]);
    expect((await ack(fx, fx.owner, wire.sealed_id)).status).toBe(404);
    expect((await ack(fx, fx.owner, randomId(), 'refused')).status).toBe(404);
  });

  it('refuses a duplicate sealed_id, pending or already acknowledged', async () => {
    const fx = await VaultFixture.create();
    const wire = sealFor(fx);
    expect(await enqueue(fx, wire)).toBe('queued');
    expect(await enqueue(fx, wire)).toBe('refused');
    expect((await ack(fx, fx.owner, wire.sealed_id, 'refused')).status).toBe(200);
    expect(await enqueue(fx, wire)).toBe('refused');
  });

  it('serves an op only to the origin account and never to another member or vault', async () => {
    const fx = await VaultFixture.create('shared');
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const forOwner = sealFor(fx);
    const forEditor = sealFor(fx, { account: editor.account });
    expect(await enqueue(fx, forOwner)).toBe('queued');
    expect(await enqueue(fx, forEditor)).toBe('queued');
    expect((await fx.get(fx.owner, '/sealed')).json.sealed.map((s: { op: SealedOpWire }) => s.op.sealed_id)).toEqual([forOwner.sealed_id]);
    expect((await fx.get(editor, '/sealed')).json.sealed.map((s: { op: SealedOpWire }) => s.op.sealed_id)).toEqual([forEditor.sealed_id]);
    expect((await ack(fx, editor, forOwner.sealed_id)).status).toBe(404);
    expect((await fx.get(fx.owner, '/sealed')).json.sealed).toHaveLength(1);

    const other = await VaultFixture.create();
    expect(await enqueue(other, forOwner)).toBe('refused');
    expect((await call(fx, other.owner, 'GET', '/sealed')).status).toBe(403);
  });

  it('only owner and editor human devices drain the queue', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const machine = await fx.addDevice({ kind: 'machine' });
    const wire = sealFor(fx);
    expect(await enqueue(fx, wire)).toBe('queued');
    expect((await fx.get(reader, '/sealed')).status).toBe(403);
    expect((await fx.get(machine, '/sealed')).status).toBe(403);
    expect((await ack(fx, machine, wire.sealed_id)).status).toBe(403);
    expect((await fx.get(fx.owner, '/sealed', { scope: 'vault:write' })).status).toBe(403);
    expect((await ack(fx, fx.owner, wire.sealed_id, 'applied', { scope: 'vault:read' })).status).toBe(403);
  });

  it('refuses ops for a reader or non-member origin, another vault, a past epoch, a pending rekey or a bad wire', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    expect(await enqueue(fx, sealFor(fx, { account: reader.account }))).toBe('refused');
    expect(await enqueue(fx, sealFor(fx, { account: `acct-${randomId()}` }))).toBe('refused');
    expect(await enqueue(fx, sealFor(fx, { vaultId: randomId() }))).toBe('refused');
    expect(await enqueue(fx, { ...sealFor(fx), ct: 'not base64!' })).toBe('refused');
    expect(await enqueue(fx, 'garbage')).toBe('refused');
    const epochOne = sealFor(fx);
    expect((await fx.rekey()).status).toBe(201);
    expect(await enqueue(fx, epochOne)).toBe('refused');
    expect(await enqueue(fx, sealFor(fx))).toBe('queued');

    const device = await fx.addDevice();
    expect((await fx.removeDevice(device)).status).toBe(201);
    expect(await enqueue(fx, sealFor(fx))).toBe('refused');
    expect(await env.VAULT.get(env.VAULT.idFromName(randomId())).enqueueSealed(sealFor(fx), 0)).toBe('refused');
  });

  it('refuses a ts too far ahead or older than sealed_ttl_s, and drops an op when it expires', async () => {
    const fx = await VaultFixture.create();
    const now = Date.now();
    expect(await enqueue(fx, sealFor(fx, { ts: now + 301_000 }), now)).toBe('refused');
    expect(await enqueue(fx, sealFor(fx, { ts: now - TTL_MS }), now)).toBe('refused');
    expect(await enqueue(fx, sealFor(fx, { ts: now + 60_000 }), now)).toBe('queued');

    // The GET path reads the real clock, so the margin must outlast a loaded machine's
    // enqueue plus listing; the wait then runs past the exact expiry instant.
    const expiryMargin = 3_000;
    const expiresAt = Date.now() + expiryMargin;
    const expiring = sealFor(fx, { ts: expiresAt - TTL_MS });
    expect(await enqueue(fx, expiring)).toBe('queued');
    expect((await fx.get(fx.owner, '/sealed')).json.sealed).toHaveLength(2);
    await new Promise((r) => setTimeout(r, Math.max(0, expiresAt - Date.now()) + 200));
    const page = await fx.get(fx.owner, '/sealed');
    expect(page.json.sealed.map((s: { op: SealedOpWire }) => s.op.sealed_id)).not.toContain(expiring.sealed_id);
    expect(page.json.sealed).toHaveLength(1);
    expect((await ack(fx, fx.owner, expiring.sealed_id)).status).toBe(404);
  });

  it('answers sealed_queue_full at sealed_queue_max held ops, acknowledged ones included, until they expire', async () => {
    const fx = await VaultFixture.create();
    const now = Date.now();
    // The first op expires 60 s from now; the rest live for the full TTL.
    const first = sealFor(fx, { ts: now - TTL_MS + 60_000 });
    expect(await enqueue(fx, first, now)).toBe('queued');
    for (let i = 1; i < REMOTE_ACCESS_LIMITS.sealed_queue_max; i++) expect(await enqueue(fx, sealFor(fx, { ts: now }), now)).toBe('queued');
    expect(await enqueue(fx, sealFor(fx, { ts: now }), now)).toBe('sealed_queue_full');

    // Acknowledging keeps the ID for replay refusal, so the slot stays taken.
    expect((await ack(fx, fx.owner, first.sealed_id)).status).toBe(200);
    expect(await enqueue(fx, sealFor(fx, { ts: now }), now)).toBe('sealed_queue_full');
    expect(await enqueue(fx, first, now)).toBe('refused');

    // Once the acknowledged op expires its slot frees up.
    const later = now + 60_001;
    expect(await enqueue(fx, sealFor(fx, { ts: later }), later)).toBe('queued');
    expect(await enqueue(fx, sealFor(fx, { ts: later }), later)).toBe('sealed_queue_full');
  });

  it('pages in seq order with after and limit, and validates the query', async () => {
    const fx = await VaultFixture.create();
    const wires = [sealFor(fx), sealFor(fx), sealFor(fx)];
    for (const w of wires) expect(await enqueue(fx, w)).toBe('queued');
    const first = await fx.get(fx.owner, '/sealed?limit=2');
    expect(first.json.sealed.map((s: { op: SealedOpWire }) => s.op.sealed_id)).toEqual([wires[0]!.sealed_id, wires[1]!.sealed_id]);
    expect(first.json.next).toBe(first.json.sealed[1].seq);
    const second = await fx.get(fx.owner, `/sealed?after=${first.json.next}&limit=2`);
    expect(second.json.sealed.map((s: { op: SealedOpWire }) => s.op.sealed_id)).toEqual([wires[2]!.sealed_id]);
    expect(second.json.next).toBeNull();

    for (const q of ['?limit=0', `?limit=${REMOTE_ACCESS_LIMITS.sealed_page_max + 1}`, '?after=-1', '?other=1', '?limit=1&limit=2']) {
      expect((await fx.get(fx.owner, `/sealed${q}`)).status).toBe(400);
    }
  });

  it('ack needs a known outcome and an Idempotency-Key', async () => {
    const fx = await VaultFixture.create();
    const wire = sealFor(fx);
    expect(await enqueue(fx, wire)).toBe('queued');
    expect((await ack(fx, fx.owner, wire.sealed_id, 'maybe')).status).toBe(400);
    expect((await call(fx, fx.owner, 'POST', `/sealed/${wire.sealed_id}/ack`, { outcome: 'applied', extra: 1 })).status).toBe(400);
    expect((await ack(fx, fx.owner, wire.sealed_id, 'applied', { idempotencyKey: null })).status).toBe(400);
    expect((await call(fx, fx.owner, 'POST', `/sealed/not-an-id/ack`, { outcome: 'applied' })).status).toBe(400);
    const key = randomId();
    expect((await ack(fx, fx.owner, wire.sealed_id, 'applied', { idempotencyKey: key })).status).toBe(200);
    // A retry with the same key replays the first answer instead of 404.
    expect((await ack(fx, fx.owner, wire.sealed_id, 'applied', { idempotencyKey: key })).status).toBe(200);
  });

  it('no route enqueues: POST /sealed is not found', async () => {
    const fx = await VaultFixture.create();
    expect((await call(fx, fx.owner, 'POST', '/sealed', sealFor(fx))).status).toBe(404);
    expect((await call(fx, fx.owner, 'PUT', '/sealed', sealFor(fx))).status).toBe(404);
  });

  describe('grant revocation', () => {
    const ids = async (fx: VaultFixture) => (await fx.get(fx.owner, '/sealed')).json.sealed.map((s: { op: SealedOpWire }) => s.op.sealed_id);

    it('never serves operations queued under a revoked grant, and keeps their IDs against replay', async () => {
      const fx = await VaultFixture.create();
      const revoked = sealFor(fx, { grantId: 'grant-revoked' });
      const live = sealFor(fx, { grantId: 'grant-live' });
      expect(await enqueue(fx, revoked)).toBe('queued');
      expect(await enqueue(fx, live)).toBe('queued');
      expect(await ids(fx)).toEqual([revoked.sealed_id, live.sealed_id]);

      expect((await sendRevocation({ revoke_sids: ['grant-revoked'] })).status).toBe(200);
      expect(await ids(fx)).toEqual([live.sealed_id]);
      expect((await ack(fx, fx.owner, revoked.sealed_id)).status).toBe(404);
      expect(await enqueue(fx, revoked)).toBe('refused');
      expect((await ack(fx, fx.owner, live.sealed_id)).status).toBe(200);

      const row = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) =>
        state.storage.sql.exec('SELECT wire, outcome FROM sealed_ops WHERE sealed_id = ?', revoked.sealed_id).one(),
      );
      expect(row).toEqual({ wire: null, outcome: 'cancelled' });
    });

    it('cancels only operations queued by tokens older than the account minimum iat', async () => {
      const fx = await VaultFixture.create();
      const old = sealFor(fx);
      const fresh = sealFor(fx);
      expect(await enqueue(fx, old, undefined, 1_000)).toBe('queued');
      expect(await enqueue(fx, fresh, undefined, 5_000)).toBe('queued');
      expect((await sendRevocation({ min_iat: [{ sub: fx.owner.account, iat: 3_000 }] })).status).toBe(200);
      expect(await ids(fx)).toEqual([fresh.sealed_id]);
    });

    it('adds the grant columns to a queue created without them', async () => {
      const fx = await VaultFixture.create();
      const names = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
        const sql = state.storage.sql;
        sql.exec('ALTER TABLE sealed_ops DROP COLUMN grant_id');
        sql.exec('ALTER TABLE sealed_ops DROP COLUMN token_iat');
        applyVaultSchema(sql);
        applyVaultSchema(sql);
        return sql.exec<{ name: string }>("SELECT name FROM pragma_table_info('sealed_ops')").toArray().map((c) => c.name);
      });
      expect(names).toEqual(expect.arrayContaining(['grant_id', 'token_iat']));
    });

    it('fails closed when the revocation registry cannot answer', async () => {
      const fx = await VaultFixture.create();
      expect(await enqueue(fx, sealFor(fx))).toBe('queued');
      const registry = env.REVOCATIONS;
      (env as { REVOCATIONS: unknown }).REVOCATIONS = { idFromName: () => ({}), get: () => ({ isRevoked: () => Promise.resolve(false), isGrantRevoked: () => Promise.reject(new Error('down')) }) };
      try {
        expect((await fx.get(fx.owner, '/sealed')).status).toBe(503);
      } finally {
        (env as { REVOCATIONS: unknown }).REVOCATIONS = registry;
      }
      expect(await ids(fx)).toHaveLength(1);
    });

    it('backfills the grant of a pending row queued before the columns existed', async () => {
      const fx = await VaultFixture.create();
      const old = sealFor(fx, { grantId: 'grant-old' });
      expect(await enqueue(fx, old)).toBe('queued');
      await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
        const sql = state.storage.sql;
        sql.exec('ALTER TABLE sealed_ops DROP COLUMN grant_id');
        sql.exec('ALTER TABLE sealed_ops DROP COLUMN token_iat');
        applyVaultSchema(sql);
      });
      expect(await ids(fx)).toEqual([old.sealed_id]);
      expect((await sendRevocation({ revoke_sids: ['grant-old'] })).status).toBe(200);
      expect(await ids(fx)).toEqual([]);
      expect((await ack(fx, fx.owner, old.sealed_id)).status).toBe(404);
    });

    it('backfills a row stored without its grant after the columns existed, below the oldest possible token iat', async () => {
      const fx = await VaultFixture.create();
      const op = sealFor(fx, { grantId: 'grant-rolled-back' });
      expect(await enqueue(fx, op)).toBe('queued');
      const row = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
        const sql = state.storage.sql;
        // As written by a revision that did not know the columns (a rollback, then a roll forward).
        sql.exec('UPDATE sealed_ops SET grant_id = NULL, token_iat = NULL WHERE sealed_id = ?', op.sealed_id);
        applyVaultSchema(sql);
        return sql.exec<{ grant_id: string; token_iat: number; created_at: number }>('SELECT grant_id, token_iat, created_at FROM sealed_ops WHERE sealed_id = ?', op.sealed_id).one();
      });
      expect(row.grant_id).toBe('grant-rolled-back');
      // A token lives at most 600 s and is accepted 60 s past exp; the bound must sit below that.
      expect(row.token_iat).toBeLessThanOrEqual(Math.floor(row.created_at / 1000) - 660);
      expect((await sendRevocation({ min_iat: [{ sub: fx.owner.account, iat: Math.floor(row.created_at / 1000) - 650 }] })).status).toBe(200);
      expect(await ids(fx)).toEqual([]);
    });
  });
});
