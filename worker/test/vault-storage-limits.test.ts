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
import { call, type CallOptions } from './helpers/api-client.js';
import { VaultDurableObject } from '../src/vault/vault-durable-object.js';
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

  it('a rejected genesis leaves the Durable Object storage empty', async () => {
    const intruder = await VaultFixture.create();
    const victim = VaultFixture.local();
    const cases: [VaultFixture['owner'], string, unknown, CallOptions][] = [
      // Malformed genesis body.
      [intruder.owner, `/v1/vaults/${randomId()}`, { event: {} }, {}],
      // A valid genesis replayed by another account (sub/author mismatch).
      [intruder.owner, `/v1/vaults/${victim.vaultId}`, victim.genesisBody(), {}],
      // The right author with a proof signed by another key.
      [victim.owner, `/v1/vaults/${victim.vaultId}`, victim.genesisBody(), { proofSecret: intruder.owner.keys.signSecret }],
      // A read-only token.
      [victim.owner, `/v1/vaults/${victim.vaultId}`, victim.genesisBody(), { scope: 'vault:read' }],
    ];
    for (const [device, path, body, opts] of cases) {
      const res = await call(device, 'PUT', path, body, opts);
      expect(res.status).toBeGreaterThanOrEqual(400);
      const vid = path.split('/')[3]!;
      const dump = await dumpDurableObject(stubFor(vid));
      expect(dump.tables).toEqual([]);
    }
    // The genuine genesis still succeeds afterwards.
    expect((await victim.putGenesis()).status).toBe(201);
  });

  it('an existing vault keeps working when its Durable Object is reloaded', async () => {
    const fx = await VaultFixture.create();
    await runInDurableObject(stubFor(fx.vaultId), async (_instance, state) => {
      // A fresh instance over the same storage, as after a deploy or eviction.
      const reloaded = new VaultDurableObject(state, env);
      expect((reloaded as unknown as { schemaReady: boolean }).schemaReady).toBe(true);
    });
    const res = await call(fx.owner, 'GET', `/v1/vaults/${fx.vaultId}/membership`);
    expect(res.status).toBe(200);
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

describe('signed wrap sets', () => {
  it('refuse a device-adding event once stored wraps would pass wraps_per_vault, and the chain does not advance', async () => {
    const fx = await VaultFixture.create();
    await runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      const stored = state.storage.sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM wrap_sets').one().n;
      // Synthetic filler rows on a sequence no event uses, just to reach the cap.
      for (let i = stored; i < LIMITS.wraps_per_vault; i++) {
        state.storage.sql.exec('INSERT INTO wrap_sets (membership_seq, rcpt, key_epoch, wrap_json) VALUES (?, ?, ?, ?)', 1_000_000, `filler-${i}`, 1, '{}');
      }
    });
    const { event, wraps } = fx.enrollEvent(fx.newDevice());
    const res = await fx.append(event, wraps);
    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe('quota_exceeded');
    expect((await fx.get(fx.owner, '/membership')).json.membership.seq).toBe(0);
  });
});

describe('vaults created before the current protocol revision', () => {
  it('are refused on every request instead of half-working', async () => {
    const fx = await VaultFixture.create();
    await runInDurableObject(stubFor(fx.vaultId), (instance: VaultDurableObject, state: DurableObjectState) => {
      const sql = state.storage.sql;
      const current = JSON.parse(sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = 'membership_state'").one().v) as Record<string, unknown>;
      delete current['removals'];
      sql.exec("UPDATE meta SET v = ? WHERE k = 'membership_state'", JSON.stringify(current));
      (instance as unknown as { membership: { invalidate(): void } }).membership.invalidate();
    });
    for (const res of [await fx.get(fx.owner, '/membership'), await fx.write(fx.owner, randomId(), 0, { name: 'n', value: 'v' })]) {
      expect(res.status).toBe(400);
      expect(res.json.error.code).toBe('unsupported_version');
    }
  });
});
