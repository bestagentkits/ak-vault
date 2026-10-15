/**
 * Red-team concurrency and interrupted operations against the real Durable
 * Object: many writers racing on one base revision, idempotent retries sent in
 * parallel, and a rekey whose answer is lost and is then retried, re-built from
 * stale state, or raced by a second owner device.
 */
import { randomId, verifyMembershipChain, type JsonObject, type MembershipEvent } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call, type CallResult } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const v = (value: string) => ({ name: 'SYNTHETIC_SECRET', value });

/** Every change-log position the server reports for the vault, in order. */
async function logPositions(fx: VaultFixture): Promise<number[]> {
  const res = await fx.get(fx.owner, '/changes?cursor=0&limit=500');
  return (res.json.changes as { log_seq: number }[]).map((c) => c.log_seq);
}

const contiguous = (seqs: number[]) => seqs.every((s, i) => s === i + 1);

describe('red team: racing writers', () => {
  it('six parallel writes on one base revision: one wins, five are preserved as distinct branches', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, v('base'))).status).toBe(200);
    const results = await Promise.all([0, 1, 2, 3, 4, 5].map((i) => fx.write(i % 2 ? laptop : fx.owner, id, 1, v(`racer-${i}`))));
    expect(results.map((r) => r.status).sort()).toEqual([200, 409, 409, 409, 409, 409]);
    const conflictIds = results.filter((r) => r.status === 409).map((r) => r.json.error.conflict_id as string);
    expect(new Set(conflictIds).size).toBe(5);
    const item = await fx.get(fx.owner, `/items/${id}`);
    expect(item.json.revision).toBe(2);
    expect((item.json.conflicts as { conflict_id: string }[]).map((c) => c.conflict_id).sort()).toEqual([...conflictIds].sort());
    const seqs = await logPositions(fx);
    expect(seqs).toHaveLength(7);
    expect(contiguous(seqs)).toBe(true);
  });

  it('the same idempotency key and body sent four times at once applies once', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    const key = randomId();
    const record = fx.record(fx.owner, id, 0, v('once'));
    const results = await Promise.all([0, 1, 2, 3].map(() => fx.put(fx.owner, record, { idempotencyKey: key })));
    expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200]);
    for (const r of results) expect(r.json).toEqual(results[0]!.json);
    expect(results.filter((r) => r.headers.get('Idempotent-Replayed') === 'true')).toHaveLength(3);
    expect(await logPositions(fx)).toEqual([1]);
  });

  it('the same idempotency key with two different bodies at once: one applies, the other is 422', async () => {
    const fx = await VaultFixture.create();
    const key = randomId();
    const [a, b] = await Promise.all([fx.write(fx.owner, randomId(), 0, v('a'), { idempotencyKey: key }), fx.write(fx.owner, randomId(), 0, v('b'), { idempotencyKey: key })]);
    expect([a.status, b.status].sort()).toEqual([200, 422]);
    expect((a.status === 422 ? a : b).json.error.code).toBe('idempotency_mismatch');
    expect(await logPositions(fx)).toEqual([1]);
  });
});

describe('red team: interrupted rekey', () => {
  async function serverEvents(fx: VaultFixture): Promise<MembershipEvent[]> {
    return (await fx.get(fx.owner, '/membership')).json.events as MembershipEvent[];
  }

  it('a rekey whose answer was lost is replayed on retry, and a rekey rebuilt from the stale state is refused', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    const { event, wraps } = fx.rekeyEvent();
    const body = { event: event as unknown as JsonObject, wraps: wraps as unknown as JsonObject[] };
    const key = randomId();
    const path = `/v1/vaults/${fx.vaultId}/membership`;

    // The request lands but the client never sees the answer.
    const lost = await call(fx.owner, 'POST', path, body, { idempotencyKey: key });
    expect(lost.status).toBe(201);
    const retry = await call(fx.owner, 'POST', path, body, { idempotencyKey: key });
    expect(retry.status).toBe(201);
    expect(retry.json).toEqual(lost.json);
    expect(retry.headers.get('Idempotent-Replayed')).toBe('true');

    // A client that lost its state rebuilds a different rekey on the pre-rekey chain.
    const rebuilt = fx.rekeyEvent();
    const stale = await call(fx.owner, 'POST', path, { event: rebuilt.event as unknown as JsonObject, wraps: rebuilt.wraps as unknown as JsonObject[] });
    expect([stale.status, stale.json.error.code]).toEqual([400, 'bad_request']);

    const events = await serverEvents(fx);
    expect(events.filter((e) => e.type === 'rekey')).toHaveLength(1);
    expect(events.at(-1)).toEqual(event);
    expect(verifyMembershipChain(events).rekey_required).toBe(false);
  });

  it('two owner devices racing different rekeys: exactly one lands and the chain stays verifiable', async () => {
    const fx = await VaultFixture.create();
    const phone = await fx.addDevice();
    const laptop = await fx.addDevice();
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    const fromOwner = fx.rekeyEvent(fx.owner);
    const fromPhone = fx.rekeyEvent(phone);
    const send = (by: typeof phone, r: typeof fromOwner): Promise<CallResult> =>
      call(by, 'POST', `/v1/vaults/${fx.vaultId}/membership`, { event: r.event as unknown as JsonObject, wraps: r.wraps as unknown as JsonObject[] });
    const [a, b] = await Promise.all([send(fx.owner, fromOwner), send(phone, fromPhone)]);
    expect([a.status, b.status].filter((s) => s === 201)).toHaveLength(1);
    const loser = a.status === 201 ? b : a;
    expect([loser.status, loser.json.error.code]).toEqual([400, 'bad_request']);

    const events = await serverEvents(fx);
    expect(events.filter((e) => e.type === 'rekey')).toHaveLength(1);
    const state = verifyMembershipChain(events);
    expect(state.rekey_required).toBe(false);
    expect(state.key_epoch).toBe(2);
  });
});
