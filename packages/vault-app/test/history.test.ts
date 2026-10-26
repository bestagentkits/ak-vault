/**
 * The pure history projection: ordering, status, author standing, content
 * availability, retention bound. Records are real (sealed and signed by the
 * protocol library); membership is the minimum the projection reads.
 */
import { describe, expect, it } from 'vitest';
import { applyRecord, b64encode, createDeviceKeys, randomBytes, randomId, sealItem, signRecord, type ItemState, type MembershipState, type SignedRecord } from '@ak-vault/protocol';
import { buildItemHistory, type LoggedRecord } from '../src/sync/history.js';
import { openRecord } from '../src/sync/vault-sync.js';

const vaultId = randomId();
const itemId = randomId();
const owner = createDeviceKeys({ account: 'acct-a', role: 'owner', kind: 'human' });
const gone = createDeviceKeys({ account: 'acct-a', role: 'editor', kind: 'human' });
const keys = new Map<number, Uint8Array>([[1, randomBytes(32)], [2, randomBytes(32)]]);

function write(author: typeof owner, base: number, value: string, opts: { epoch?: number; tombstone?: boolean; resolves?: string[] } = {}): SignedRecord {
  const epoch = opts.epoch ?? 1;
  const ctx = { vault_id: vaultId, item_id: itemId, base_revision: base, key_epoch: epoch, author: author.record.device_id, tombstone: opts.tombstone === true };
  const payload = opts.tombstone ? { deleted: true as const } : { name: 'n', value, meta: {}, sensitivity: 'normal' as const };
  return signRecord({ ...ctx, ts: 1_700_000_000_000 + base, resolves: opts.resolves ?? [], env: sealItem({ ...ctx, vk: keys.get(epoch)!, payload }) }, author.signSecret);
}

/** Apply records the way the server does and keep the log entries. */
function replay(records: SignedRecord[]): { state: ItemState; log: LoggedRecord[] } {
  let state: ItemState | undefined;
  const log: LoggedRecord[] = [];
  records.forEach((record, i) => {
    const applied = applyRecord(state, record, { conflictId: b64encode(new Uint8Array(16).fill(i + 1)) });
    state = applied.state;
    log.push({ logSeq: i + 1, conflictId: applied.outcome.status === 'conflict' ? applied.outcome.conflict_id : null, record });
  });
  return { state: state!, log };
}

const membership = { devices: [owner.record], removals: [{ device_id: gone.record.device_id }] } as unknown as MembershipState;
const build = (r: ReturnType<typeof replay>, vaultKeys = keys, limit?: number) =>
  buildItemHistory({ itemId, name: 'n', itemState: r.state, log: r.log, state: membership, vaultKeys, selfDeviceId: owner.record.device_id, open: openRecord, ...(limit ? { limit } : {}) });

describe('buildItemHistory', () => {
  it('lists revisions newest first with status, author standing and no value', () => {
    const r = replay([write(owner, 0, 'SENTINEL-A'), write(gone, 1, 'SENTINEL-B'), write(owner, 2, 'SENTINEL-C')]);
    const h = build(r);
    expect(h.entries.map((e) => [e.revision, e.status, e.authorStanding])).toEqual([[3, 'current', 'this_browser'], [2, 'superseded', 'removed_device'], [1, 'superseded', 'this_browser']]);
    // A value the removed device wrote is never promoted back; the one before it is restorable.
    expect(h.entries.map((e) => e.restorable)).toEqual([false, false, true]);
    expect(JSON.stringify(h)).not.toContain('SENTINEL');
    expect(h.entries[0]!.author).toBe(owner.record.device_id.slice(0, 8));
  });

  it('marks content unavailable when the key epoch was never given, and offers no restore for it', () => {
    const r = replay([write(owner, 0, 'a', { epoch: 1 }), write(owner, 1, 'b', { epoch: 2 })]);
    const h = build(r, new Map([[2, keys.get(2)!]]));
    expect(h.entries.map((e) => [e.revision, e.keyEpoch, e.content, e.restorable])).toEqual([[2, 2, 'readable', false], [1, 1, 'unavailable', false]]);
  });

  it('shows a tombstone with no content and offers no restore of a value from before the deletion', () => {
    const r = replay([write(owner, 0, 'a'), write(owner, 1, '', { tombstone: true }), write(owner, 2, 'again')]);
    const h = build(r);
    expect(h.entries.map((e) => [e.revision, e.tombstone, e.content, e.restorable])).toEqual([[3, false, 'readable', false], [2, true, 'none', false], [1, false, 'readable', false]]);
  });

  it('offers no restore of a value a removed device could hold, and none of a pre-removal epoch', () => {
    const r = replay([write(owner, 0, 'a', { epoch: 1 }), write(owner, 1, 'b', { epoch: 2 }), write(owner, 2, 'c', { epoch: 2 })]);
    const removed = { devices: [owner.record], removals: [{ device_id: gone.record.device_id, key_epoch: 1 }] } as unknown as MembershipState;
    const h = buildItemHistory({ itemId, name: 'n', itemState: r.state, log: r.log, state: removed, vaultKeys: keys, selfDeviceId: owner.record.device_id, open: openRecord });
    expect(h.entries.map((e) => [e.revision, e.restorable])).toEqual([[3, false], [2, true], [1, false]]);
  });

  it('is not resolvable while an open branch is a deletion or unreadable', () => {
    const del = replay([write(owner, 0, 'a'), write(owner, 1, 'head'), write(owner, 1, '', { tombstone: true })]);
    expect(build(del).resolvable).toBe(false);
    const epoch2 = replay([write(owner, 0, 'a'), write(owner, 1, 'head'), write(owner, 1, 'branch', { epoch: 2 })]);
    expect(build(epoch2, new Map([[1, keys.get(1)!]])).resolvable).toBe(false);
  });

  it('offers no restore on a deleted item', () => {
    const r = replay([write(owner, 0, 'a'), write(owner, 1, '', { tombstone: true })]);
    expect(build(r).entries.every((e) => !e.restorable)).toBe(true);
  });

  it('tracks a conflict branch from open to resolved at the revision that resolved it', () => {
    const base = [write(owner, 0, 'a'), write(owner, 1, 'head'), write(gone, 1, 'branch')];
    const open = replay(base);
    const branchId = open.log[2]!.conflictId!;
    const h1 = build(open);
    expect(h1.openConflicts).toBe(1);
    expect(h1.entries[0]).toMatchObject({ kind: 'conflict', status: 'open', adoptable: false, revision: null, baseRevision: 1, authorStanding: 'removed_device' });
    expect(h1.resolvable).toBe(true);
    const resolved = replay([...base, write(owner, 2, 'head', { resolves: [branchId] })]);
    const h2 = build(resolved);
    expect(h2.openConflicts).toBe(0);
    expect(h2.entries.find((e) => e.kind === 'conflict')).toMatchObject({ status: 'resolved', resolvedAtRevision: 3, adoptable: false });
    expect(h2.entries[0]).toMatchObject({ revision: 3, resolves: 1, status: 'current' });
  });

  it('bounds the list to the newest entries and reports how many are omitted', () => {
    const records: SignedRecord[] = [];
    for (let i = 0; i < 12; i++) records.push(write(owner, i, `v${i}`));
    const h = build(replay(records), keys, 5);
    expect(h.entries.map((e) => e.revision)).toEqual([12, 11, 10, 9, 8]);
    expect(h.omitted).toBe(7);
  });
});
