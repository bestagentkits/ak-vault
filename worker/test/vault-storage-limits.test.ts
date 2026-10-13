/**
 * Storage bounds of a vault Durable Object: requests for a vault that does not
 * exist write nothing, and the append-only change log is capped by record count
 * and total record bytes (published limits).
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { randomId } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { LIMITS } from '../src/limits.js';
import { RECORD_USAGE_KEY } from '../src/vault/item-store.js';
import { call } from './helpers/api-client.js';
import { dumpDurableObject } from './helpers/disclosure-scan.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

describe('non-existent vaults', () => {
  it('every op on a random vault id is 404 and leaves the Durable Object storage empty', async () => {
    const somebody = await VaultFixture.create();
    const vid = randomId();
    const paths: [string, string, unknown?][] = [
      ['GET', `/v1/vaults/${vid}/membership`],
      ['GET', `/v1/vaults/${vid}/recovery`],
      ['POST', `/v1/vaults/${vid}/audit`, { start_seq: 0, prev: '', entries: [] }],
      ['PUT', `/v1/vaults/${vid}/items/${randomId()}`, somebody.record(somebody.owner, randomId(), 0, { name: 'n', value: 'v' })],
    ];
    for (const [method, path, body] of paths) {
      const res = await call(somebody.owner, method, path, body);
      expect(res.status).toBe(404);
      expect(res.json.error.code).toBe('not_found');
    }
    const dump = await dumpDurableObject(stubFor(vid));
    expect(dump.tables).toEqual([]);
    expect(dump.text).toBe('');
  });

  it('genesis still creates the vault', async () => {
    const fx = await VaultFixture.create();
    const dump = await dumpDurableObject(stubFor(fx.vaultId));
    expect(dump.tables).toContain('membership_events');
    expect(dump.tables).toContain('rate_counters');
  });
});

describe('record caps', () => {
  const setUsage = (fx: VaultFixture, usage: { records: number; bytes: number } | null) =>
    runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      if (usage === null) state.storage.sql.exec('DELETE FROM meta WHERE k = ?', RECORD_USAGE_KEY);
      else state.storage.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v', RECORD_USAGE_KEY, JSON.stringify(usage));
    });
  const readUsage = (fx: VaultFixture) =>
    runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      const sql = state.storage.sql;
      const stored = JSON.parse(sql.exec<{ v: string }>('SELECT v FROM meta WHERE k = ?', RECORD_USAGE_KEY).one().v) as { records: number; bytes: number };
      const actual = sql.exec<{ n: number; b: number }>('SELECT COUNT(*) AS n, SUM(length(CAST(record_json AS BLOB))) AS b FROM records').one();
      return { stored, actual: { records: actual.n, bytes: actual.b } };
    });
  const v = { name: 'n', value: 'v' };

  it('limits are published', () => {
    expect(LIMITS.records_per_vault).toBeGreaterThan(LIMITS.items_per_vault);
    expect(LIMITS.record_bytes_per_vault).toBeGreaterThan(LIMITS.envelope_max_bytes);
  });

  it('tracks exact record count and bytes, seeding from the table when the counter is missing', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, v)).status).toBe(200);
    expect((await fx.write(fx.owner, id, 0, v)).status).toBe(409); // preserved conflict branch counts too
    let usage = await readUsage(fx);
    expect(usage.stored).toEqual(usage.actual);
    expect(usage.stored.records).toBe(2);
    await setUsage(fx, null);
    expect((await fx.write(fx.owner, id, 1, v)).status).toBe(200);
    usage = await readUsage(fx);
    expect(usage.stored).toEqual(usage.actual);
    expect(usage.stored.records).toBe(3);
  });

  it('refuses a write once the record count or byte cap would be exceeded (403 quota_exceeded), conflicts included', async () => {
    const fx = await VaultFixture.create();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, v)).status).toBe(200);

    await setUsage(fx, { records: LIMITS.records_per_vault, bytes: 0 });
    const byCount = await fx.write(fx.owner, id, 1, v);
    expect(byCount.status).toBe(403);
    expect(byCount.json.error.code).toBe('quota_exceeded');
    expect((await fx.write(fx.owner, id, 0, v)).status).toBe(403); // would-be conflict branch

    await setUsage(fx, { records: 1, bytes: LIMITS.record_bytes_per_vault - 16 });
    const byBytes = await fx.write(fx.owner, randomId(), 0, v);
    expect(byBytes.status).toBe(403);
    expect(byBytes.json.error.code).toBe('quota_exceeded');

    await setUsage(fx, { records: 1, bytes: 100 });
    expect((await fx.write(fx.owner, id, 1, v)).status).toBe(200);
    expect((await fx.get(fx.owner, `/items/${id}`)).json.revision).toBe(2);
  });
});
