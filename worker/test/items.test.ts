/** CAS writes, preserved conflicts, resolution, tombstones, replay and idempotency (spec §5). */
import { openItem, randomId, type SignedRecord } from '@ak-vault/protocol';
import { beforeEach, describe, expect, it } from 'vitest';
import { call, type TestDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

let fx: VaultFixture;
let laptop: TestDevice;
const v = (value: string) => ({ name: 'API_TOKEN', value });

beforeEach(async () => {
  fx = await VaultFixture.create();
  laptop = await fx.addDevice();
});

describe('compare-and-swap', () => {
  it('sequential writes advance the revision and pull returns decryptable records', async () => {
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, v('one'))).json.revision).toBe(1);
    expect((await fx.write(laptop, id, 1, v('two'))).json.revision).toBe(2);
    const item = await fx.get(laptop, `/items/${id}`);
    expect(item.json).toMatchObject({ revision: 2, tombstone: false, conflicts: [] });
    const rec = item.json.record as SignedRecord;
    const payload = openItem({ vk: fx.vk.get(1)!, vault_id: fx.vaultId, item_id: id, base_revision: rec.base_revision, key_epoch: rec.key_epoch, author: rec.author, tombstone: false, env: rec.env });
    expect(payload).toMatchObject({ value: 'two' });
  });

  it('concurrent writers: one wins, the other gets 409 with a preserved branch returned on pull', async () => {
    const id = randomId();
    await fx.write(fx.owner, id, 0, v('base'));
    const [a, b] = await Promise.all([fx.write(fx.owner, id, 1, v('from-owner')), fx.write(laptop, id, 1, v('from-laptop'))]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 409]);
    const loser = a.status === 409 ? a : b;
    expect(loser.json.error.code).toBe('conflict');
    const conflictId = loser.json.error.conflict_id as string;
    expect(conflictId).toMatch(/^[A-Za-z0-9_-]{22}$/);

    const changes = await fx.get(laptop, '/changes');
    const branch = changes.json.changes.find((c: { kind: string }) => c.kind === 'conflict');
    expect(branch).toMatchObject({ item_id: id, conflict_id: conflictId, resolved_revision: null });
    expect(branch.record.base_revision).toBe(1);
    expect((await fx.get(laptop, `/items/${id}`)).json.conflicts).toHaveLength(1);

    // Resolve explicitly by writing a record that names the branch.
    const resolved = await fx.put(laptop, fx.record(laptop, id, 2, v('merged'), { resolves: [conflictId] }));
    expect(resolved.status).toBe(200);
    expect(resolved.json.revision).toBe(3);
    expect((await fx.get(laptop, `/items/${id}`)).json.conflicts).toHaveLength(0);
    const after = await fx.get(laptop, '/changes');
    expect(after.json.changes.find((c: { kind: string }) => c.kind === 'conflict').resolved_revision).toBe(3);
  });

  it('resolves naming an unknown branch is bad_request', async () => {
    const id = randomId();
    await fx.write(fx.owner, id, 0, v('x'));
    expect((await fx.put(fx.owner, fx.record(fx.owner, id, 1, v('y'), { resolves: [randomId()] }))).status).toBe(400);
  });

  it('a replayed record is refused and not preserved', async () => {
    const id = randomId();
    const rec = fx.record(fx.owner, id, 0, v('x'));
    expect((await fx.put(fx.owner, rec)).status).toBe(200);
    const replay = await fx.put(fx.owner, rec);
    expect(replay.status).toBe(409);
    expect(replay.json.error.conflict_id).toBeUndefined();
    expect((await fx.get(fx.owner, `/items/${id}`)).json.conflicts).toHaveLength(0);
  });
});

describe('tombstones', () => {
  it('a stale offline device cannot resurrect a deleted secret; re-create needs the tombstone revision', async () => {
    const id = randomId();
    await fx.write(fx.owner, id, 0, v('secret'));
    const offline = fx.record(laptop, id, 1, v('stale-edit'));
    const del = await fx.write(fx.owner, id, 1, null);
    expect(del.json).toMatchObject({ revision: 2, tombstone: true });
    const before = (await fx.get(fx.owner, '/changes')).json.head.log_seq;

    const resurrect = await fx.put(laptop, offline);
    expect(resurrect.status).toBe(409);
    expect(resurrect.json.error.code).toBe('tombstoned');
    const fresh = await fx.write(laptop, id, 0, v('recreate-from-zero'));
    expect(fresh.json.error.code).toBe('tombstoned');
    expect((await fx.get(fx.owner, '/changes')).json.head.log_seq).toBe(before);

    expect((await fx.write(laptop, id, 2, v('recreated'))).json.revision).toBe(3);
  });

  it('deleting a missing or already deleted item is bad_request', async () => {
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, null)).status).toBe(400);
    await fx.write(fx.owner, id, 0, v('x'));
    await fx.write(fx.owner, id, 1, null);
    expect((await fx.write(fx.owner, id, 2, null)).status).toBe(400);
  });
});

describe('idempotency and record binding', () => {
  it('same key + same body returns the stored response; a different body is 422', async () => {
    const id = randomId();
    const key = randomId();
    const rec = fx.record(fx.owner, id, 0, v('x'));
    const first = await fx.put(fx.owner, rec, { idempotencyKey: key });
    const again = await fx.put(fx.owner, rec, { idempotencyKey: key });
    expect(again.status).toBe(first.status);
    expect(again.json).toEqual(first.json);
    const other = await fx.put(fx.owner, fx.record(fx.owner, id, 1, v('y')), { idempotencyKey: key });
    expect(other.status).toBe(422);
    expect(other.json.error.code).toBe('idempotency_mismatch');
  });

  it('a retried conflicting write returns the same conflict_id instead of a second branch', async () => {
    const id = randomId();
    await fx.write(fx.owner, id, 0, v('a'));
    await fx.write(fx.owner, id, 1, v('b'));
    const key = randomId();
    const stale = fx.record(laptop, id, 1, v('c'));
    const first = await fx.put(laptop, stale, { idempotencyKey: key });
    const retry = await fx.put(laptop, stale, { idempotencyKey: key });
    expect(first.status).toBe(409);
    expect(retry.json.error.conflict_id).toBe(first.json.error.conflict_id);
    expect((await fx.get(fx.owner, `/items/${id}`)).json.conflicts).toHaveLength(1);
  });

  it('rejects a record bound to another item, signed by another device, or a malformed path id', async () => {
    const other = fx.record(fx.owner, randomId(), 0, v('x'));
    const wrongPath = await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/items/${randomId()}`, other);
    expect(wrongPath.status).toBe(400);
    const notMine = await fx.put(fx.owner, fx.record(laptop, randomId(), 0, v('x')));
    expect(notMine.status).toBe(403);
    expect((await fx.get(fx.owner, `/items/${randomId()}`)).status).toBe(404);
    expect((await fx.get(fx.owner, '/items/not-an-id')).status).toBe(400);
  });

  it('pages the change log by cursor', async () => {
    for (let i = 0; i < 3; i++) await fx.write(fx.owner, randomId(), 0, v(`v${i}`));
    const p1 = await fx.get(fx.owner, '/changes?limit=2');
    expect(p1.json.changes).toHaveLength(2);
    expect(p1.json.has_more).toBe(true);
    const p2 = await fx.get(fx.owner, `/changes?cursor=${p1.json.next_cursor}&limit=2`);
    expect(p2.json.changes).toHaveLength(1);
    expect(p2.json.has_more).toBe(false);
    expect((await fx.get(fx.owner, '/changes?limit=501')).status).toBe(400);
  });
});
