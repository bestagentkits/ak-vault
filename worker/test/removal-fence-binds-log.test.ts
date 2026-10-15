/**
 * The removal fence binds the change-log contents (spec §5): every removal signs the
 * change-log head at its fence, the Worker refuses a removal whose head differs from the
 * stored log, and a device that first reads the log after the removal detects a record
 * substituted, dropped or given another conflict_id at or below the fence.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { b64encode, randomBytes, randomId, verifyChangeLog, type SignedRecord } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { VaultDurableObject } from '../src/vault/vault-durable-object.js';
import type { TestDevice } from './helpers/api-client.js';
import { signerOf, VaultFixture, type ChangeFeedEntry } from './helpers/vault-fixture.js';

const v = (value: string) => ({ name: 'API_KEY', value });
const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

interface LogEntry {
  log_seq: number;
  conflict_id: string | null;
  record: unknown;
}

/** The whole change log as served to `device` (one page; these logs are short). */
async function readLog(fx: VaultFixture, device: TestDevice): Promise<{ entries: LogEntry[]; served: ChangeFeedEntry[]; head: { log_seq: number; log_head: string } }> {
  const res = await fx.get(device, '/changes?cursor=0');
  expect(res.status).toBe(200);
  expect(res.json.has_more).toBe(false);
  const served = res.json.changes as ChangeFeedEntry[];
  return { entries: served.map(({ log_seq, conflict_id, record }) => ({ log_seq, conflict_id, record })), served, head: res.json.head };
}

/**
 * A vault where `laptop` wrote two records and a conflict branch, the owner wrote one,
 * and the owner then removed `laptop` (fence = 4) and rekeyed.
 */
async function vaultWithRemoval() {
  const fx = await VaultFixture.create();
  const laptop = await fx.addDevice();
  const shared = randomId();
  expect((await fx.write(laptop, shared, 0, v('one'))).status).toBe(200);
  expect((await fx.write(fx.owner, randomId(), 0, v('two'))).status).toBe(200);
  const branch = await fx.write(laptop, shared, 0, v('three'));
  expect(branch.status).toBe(409);
  expect((await fx.write(laptop, randomId(), 0, v('four'))).status).toBe(200);
  expect((await fx.removeDevice(laptop)).status).toBe(201);
  expect((await fx.rekey()).status).toBe(201);
  return { fx, laptop, shared };
}

describe('change-log heads', () => {
  it('the feed publishes the head chain a client computes, and the removal signs the head at its fence', async () => {
    const { fx } = await vaultWithRemoval();
    const heads = await fx.verifiedLogHeads();
    const { served, head } = await readLog(fx, fx.owner);
    expect(served.map((e) => e.log_head)).toEqual(heads.slice(1));
    expect(served.filter((e) => e.conflict_id !== null).map((e) => e.log_seq)).toEqual([3]);
    expect(head).toMatchObject({ log_seq: 4, log_head: heads[4] });
    expect(fx.state.removals).toEqual([expect.objectContaining({ log_fence: 4, log_head: heads[4] })]);
  });

  it('an empty log has head "" and a removal at fence 0 signs ""', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.get(fx.owner, '/changes')).json.head).toMatchObject({ log_seq: 0, log_head: '' });
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect(fx.state.removals).toEqual([expect.objectContaining({ log_fence: 0, log_head: '' })]);
  });

  it('refuses a removal whose signed head does not describe the stored log', async () => {
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    expect((await fx.write(laptop, randomId(), 0, v('one'))).status).toBe(200);
    const remove = (log_head: string) =>
      fx.append(fx.buildEvent('device_remove', { device_id: laptop.keys.record.device_id, reason: 'lost', log_fence: 1, log_head }, signerOf(fx.owner)));
    const wrongHead = await remove(b64encode(randomBytes(32)));
    expect(wrongHead.status).toBe(400);
    expect(wrongHead.json.error.code).toBe('bad_request');
    expect((await remove('')).json.error.code).toBe('bad_request');
    expect((await fx.get(fx.owner, '/membership')).json.membership.seq).toBe(1);
    expect((await remove((await fx.verifiedLogHeads())[1]!)).status).toBe(201);
  });
});

describe('a device that first reads the log after a removal', () => {
  it('verifies the honest log against the signed fence', async () => {
    const { fx } = await vaultWithRemoval();
    const fresh = await fx.addDevice();
    const { entries } = await readLog(fx, fresh);
    const { head } = verifyChangeLog(entries, fx.state, { complete: true });
    expect(head).toEqual({ log_seq: 4, log_head: fx.state.removals[0]!.log_head });
  });

  it('detects a record the removed device signed after its removal, placed at or below the fence', async () => {
    const { fx, laptop, shared } = await vaultWithRemoval();
    const fresh = await fx.addDevice();
    const { entries } = await readLog(fx, fresh);
    // The removed device still holds its key and VK[1]; a colluding server serves its new record in place of an honest one.
    const late: SignedRecord = fx.record(laptop, shared, 0, v('late'), { keyEpoch: 1 });
    for (const position of [1, 2, 4]) {
      const forged = entries.map((e) => (e.log_seq === position ? { ...e, conflict_id: null, record: late } : e));
      expect(() => verifyChangeLog(forged, fx.state, { complete: true })).toThrowError(expect.objectContaining({ code: 'rollback' }));
    }
    // The Worker itself refuses that record: its author is no longer a current device.
    expect((await fx.put(fx.owner, late)).json.error.code).toBe('forbidden');
  });

  it('detects a dropped conflict branch, a changed conflict_id and a log truncated below the fence', async () => {
    const { fx } = await vaultWithRemoval();
    const fresh = await fx.addDevice();
    const { entries } = await readLog(fx, fresh);
    const dropped = entries.filter((e) => e.log_seq !== 3).map((e, i) => ({ ...e, log_seq: i + 1 }));
    const relabelled = entries.map((e) => (e.log_seq === 3 ? { ...e, conflict_id: randomId() } : e));
    for (const forged of [dropped, relabelled, entries.slice(0, 3)]) {
      expect(() => verifyChangeLog(forged, fx.state, { complete: true })).toThrowError(expect.objectContaining({ code: 'rollback' }));
    }
  });
});

describe('vaults that stored records before change-log heads existed', () => {
  it('get their heads computed in log order when the Durable Object starts', async () => {
    const { fx } = await vaultWithRemoval();
    const before = (await readLog(fx, fx.owner)).served.map((e) => e.log_head);
    await runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      state.storage.sql.exec('DELETE FROM log_heads WHERE log_seq > 1');
    });
    // A missing head fails closed instead of serving a log with gaps.
    expect((await fx.get(fx.owner, '/changes')).json.error.code).toBe('internal');
    await runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      new VaultDurableObject(state, env); // a fresh instance over the same storage, as after a deploy
    });
    expect((await readLog(fx, fx.owner)).served.map((e) => e.log_head)).toEqual(before);
  });
});
