/**
 * Sealed-operation inbox: the server stores opaque sealed ops queued by the MCP
 * handler (RPC only) and serves them to writer devices of the origin account.
 */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { cjson, deriveSealKeyPair, parseSealedOp, randomId, sealOp, type JsonObject, type SealedOpWire } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { call as rawCall, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const TTL_MS = REMOTE_ACCESS_LIMITS.sealed_ttl_s * 1000;

function sealFor(fx: VaultFixture, opts: { account?: string; ts?: number; keyEpoch?: number; vaultId?: string } = {}): SealedOpWire {
  const keyEpoch = opts.keyEpoch ?? fx.keyEpoch;
  const { publicKey } = deriveSealKeyPair(fx.vk.get(keyEpoch)!, fx.vaultId, keyEpoch);
  return sealOp(publicKey, {
    vaultId: opts.vaultId ?? fx.vaultId,
    keyEpoch,
    origin: { kind: 'mcp', account: opts.account ?? fx.owner.account, client_id: 'client-1', grant_id: 'grant-1' },
    ts: opts.ts ?? Date.now(),
    op: { op: 'set', name: 'API_TOKEN', value: 'secret-value' },
  });
}

function enqueue(fx: VaultFixture, wire: unknown, nowMs?: number) {
  const stub = env.VAULT.get(env.VAULT.idFromName(fx.vaultId));
  return nowMs === undefined ? stub.enqueueSealed(wire) : stub.enqueueSealed(wire, nowMs);
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
    expect(await env.VAULT.get(env.VAULT.idFromName(randomId())).enqueueSealed(sealFor(fx))).toBe('refused');
  });

  it('refuses a ts too far ahead or older than sealed_ttl_s, and drops an op when it expires', async () => {
    const fx = await VaultFixture.create();
    const now = Date.now();
    expect(await enqueue(fx, sealFor(fx, { ts: now + 301_000 }), now)).toBe('refused');
    expect(await enqueue(fx, sealFor(fx, { ts: now - TTL_MS }), now)).toBe('refused');
    expect(await enqueue(fx, sealFor(fx, { ts: now + 60_000 }), now)).toBe('queued');

    const expiring = sealFor(fx, { ts: Date.now() - TTL_MS + 200 });
    expect(await enqueue(fx, expiring)).toBe('queued');
    expect((await fx.get(fx.owner, '/sealed')).json.sealed).toHaveLength(2);
    await new Promise((r) => setTimeout(r, 400));
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
});
