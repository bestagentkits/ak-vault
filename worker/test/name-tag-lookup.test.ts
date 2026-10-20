/** Name tags: writers attach them to item PUTs; `GET /lookup` matches them without any server key. */
import { describe, expect, it } from 'vitest';
import { b64encode, nameIndexKey, nameTag, randomBytes, randomId, type SignedRecord } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { call as rawCall, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

function tagOf(fx: VaultFixture, name: string, keyEpoch = fx.keyEpoch): string {
  return nameTag(nameIndexKey(fx.vk.get(keyEpoch)!, fx.vaultId, keyEpoch), name);
}

function putTagged(fx: VaultFixture, device: TestDevice, record: SignedRecord, nameTagValue: unknown, opts: CallOptions = {}) {
  const body = nameTagValue === undefined ? { record } : { record, name_tag: nameTagValue };
  return rawCall(device, 'PUT', `/v1/vaults/${fx.vaultId}/items/${record.item_id}`, body, opts);
}

function lookup(fx: VaultFixture, device: TestDevice, pairs: [string, number][] | string, opts: CallOptions = {}) {
  const query = typeof pairs === 'string' ? pairs : pairs.map(([tag, epoch]) => `tag=${tag}&key_epoch=${epoch}`).join('&');
  return rawCall(device, 'GET', `/v1/vaults/${fx.vaultId}/lookup?${query}`, undefined, opts);
}

describe('name tags', () => {
  it('stores the tag of an applied write and finds the item by it', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    const tag = tagOf(fx, 'API_TOKEN');
    const res = await putTagged(fx, fx.owner, fx.record(fx.owner, id, 0, { name: 'API_TOKEN', value: 'one' }), { key_epoch: 1, tag });
    expect(res.status).toBe(200);
    const found = await lookup(fx, fx.owner, [[tag, 1]]);
    expect(found.status).toBe(200);
    expect(found.json).toEqual({ hits: [{ item_id: id, revision: 1, key_epoch: 1, tag }] });
    expect((await lookup(fx, fx.owner, [[tagOf(fx, 'OTHER'), 1]])).json).toEqual({ hits: [] });
  });

  it('follows the head: a later write without a tag clears it, a new tag replaces it', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    const first = tagOf(fx, 'A');
    const second = tagOf(fx, 'B');
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 0, { name: 'A', value: '1' }), { key_epoch: 1, tag: first })).status).toBe(200);
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 1, { name: 'B', value: '2' }), { key_epoch: 1, tag: second })).status).toBe(200);
    expect((await lookup(fx, fx.owner, [[first, 1]])).json.hits).toEqual([]);
    expect((await lookup(fx, fx.owner, [[second, 1]])).json.hits).toEqual([{ item_id: id, revision: 2, key_epoch: 1, tag: second }]);
    expect((await fx.write(fx.owner, id, 2, { name: 'B', value: '3' })).status).toBe(200);
    expect((await lookup(fx, fx.owner, [[second, 1]])).json.hits).toEqual([]);
  });

  it('a losing concurrent write does not move the tag', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    const winner = tagOf(fx, 'WIN');
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 0, { name: 'WIN', value: '1' }), { key_epoch: 1, tag: winner })).status).toBe(200);
    const loser = await putTagged(fx, fx.owner, fx.record(fx.owner, id, 0, { name: 'LOSE', value: '2' }), { key_epoch: 1, tag: tagOf(fx, 'LOSE') });
    expect(loser.status).toBe(409);
    expect((await lookup(fx, fx.owner, [[winner, 1]])).json.hits).toHaveLength(1);
    expect((await lookup(fx, fx.owner, [[tagOf(fx, 'LOSE'), 1]])).json.hits).toEqual([]);
  });

  it('returns each matching item once, in item_id order, across several pairs and epochs', async () => {
    const fx = await VaultFixture.create();
    const tag = tagOf(fx, 'SHARED');
    const ids = [randomId(), randomId(), randomId()];
    for (const id of ids) expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 0, { name: 'SHARED', value: id }), { key_epoch: 1, tag })).status).toBe(200);
    expect((await fx.rekey()).status).toBe(201);
    const tag2 = tagOf(fx, 'SHARED', 2);
    const late = randomId();
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, late, 0, { name: 'SHARED', value: 'x' }), { key_epoch: 2, tag: tag2 })).status).toBe(200);
    const res = await lookup(fx, fx.owner, [
      [tag, 1],
      [tag, 1],
      [tag2, 2],
    ]);
    expect(res.json.hits.map((h: { item_id: string }) => h.item_id)).toEqual([...ids, late].sort());
  });

  it('refuses a tag on a tombstone, for another epoch, of the wrong size, or with extra keys', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, { name: 'A', value: '1' })).status).toBe(200);
    const tag = tagOf(fx, 'A');
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 1, null), { key_epoch: 1, tag })).status).toBe(400);
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 1, { name: 'A', value: '2' }), { key_epoch: 2, tag })).status).toBe(400);
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 1, { name: 'A', value: '2' }), { key_epoch: 1, tag: b64encode(randomBytes(15)) })).status).toBe(400);
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 1, { name: 'A', value: '2' }), { key_epoch: 1, tag, extra: 1 })).status).toBe(400);
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 1, { name: 'A', value: '2' }), 'tag')).status).toBe(400);
    const record = fx.record(fx.owner, id, 1, { name: 'A', value: '2' });
    expect((await rawCall(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/items/${id}`, { record, name_tag: { key_epoch: 1, tag }, more: 1 })).status).toBe(400);
    // The wrapper without a tag is a plain write that clears any tag.
    expect((await putTagged(fx, fx.owner, record, undefined)).status).toBe(200);
  });

  it('validates the lookup query', async () => {
    const fx = await VaultFixture.create();
    const tag = tagOf(fx, 'A');
    const tooMany = Array.from({ length: REMOTE_ACCESS_LIMITS.lookup_tags_max + 1 }, () => [tag, 1] as [string, number]);
    for (const q of ['', `tag=${tag}`, `key_epoch=1`, `tag=${tag}&key_epoch=0`, `tag=${tag}&key_epoch=2`, `tag=short&key_epoch=1`, `tag=${tag}&key_epoch=1&x=1`, `tag=${tag}&key_epoch=1.0`]) {
      expect((await lookup(fx, fx.owner, q)).status).toBe(400);
    }
    expect((await lookup(fx, fx.owner, tooMany)).status).toBe(400);
    const max = tooMany.slice(1);
    expect((await lookup(fx, fx.owner, max)).status).toBe(200);
  });

  it('any device of the vault may look up; outsiders and other vaults see nothing', async () => {
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const machine = await fx.addDevice({ kind: 'machine' });
    const id = randomId();
    const tag = tagOf(fx, 'A');
    expect((await putTagged(fx, fx.owner, fx.record(fx.owner, id, 0, { name: 'A', value: '1' }), { key_epoch: 1, tag })).status).toBe(200);
    for (const device of [reader, machine]) expect((await lookup(fx, device, [[tag, 1]])).json.hits).toHaveLength(1);
    expect((await putTagged(fx, reader, fx.record(reader, randomId(), 0, { name: 'A', value: '1' }), { key_epoch: 1, tag })).status).toBe(403);

    const other = await VaultFixture.create();
    expect((await lookup(fx, other.owner, [[tag, 1]])).status).toBe(403);
    expect((await rawCall(other.owner, 'GET', `/v1/vaults/${other.vaultId}/lookup?tag=${tag}&key_epoch=1`)).json).toEqual({ hits: [] });
    expect((await lookup(fx, fx.owner, [[tag, 1]], { scope: 'vault:write' })).status).toBe(403);
  });
});
