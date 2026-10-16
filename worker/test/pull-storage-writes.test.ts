/**
 * A verified pull writes one row (the device's proof-jti row) and nothing else; the
 * rate window lives in memory. Single-use proofs still hold across a Durable Object
 * reload and across an upgrade from the per-jti table.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { decodeProof } from '@ak-vault/protocol';
import { describe, expect, it } from 'vitest';
import { call } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { ProofReplayStore } from '../src/vault/proof-replay-store.js';
import { VaultDurableObject } from '../src/vault/vault-durable-object.js';

const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));
const membershipPath = (fx: VaultFixture) => `/v1/vaults/${fx.vaultId}/membership`;

/** Rows written by every statement the vault object runs while `fn` runs. */
async function rowsWrittenDuring(fx: VaultFixture, fn: () => Promise<void>): Promise<number> {
  const cursors: SqlStorageCursor<Record<string, SqlStorageValue>>[] = [];
  await runInDurableObject(stubFor(fx.vaultId), (_i: unknown, state: DurableObjectState) => {
    const sql = state.storage.sql as unknown as { exec: SqlStorage['exec']; __orig?: SqlStorage['exec'] };
    sql.__orig = sql.exec;
    sql.exec = ((...args: Parameters<SqlStorage['exec']>) => {
      const c = sql.__orig!.apply(state.storage.sql, args);
      cursors.push(c);
      return c;
    }) as SqlStorage['exec'];
  });
  try {
    await fn();
  } finally {
    await runInDurableObject(stubFor(fx.vaultId), (_i: unknown, state: DurableObjectState) => {
      const sql = state.storage.sql as unknown as { exec: SqlStorage['exec']; __orig?: SqlStorage['exec'] };
      sql.exec = sql.__orig!;
    });
  }
  return cursors.reduce((n, c) => n + c.rowsWritten, 0);
}

describe('pull storage writes', () => {
  it('a steady-state pull writes one row', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.get(fx.owner, '/membership')).status).toBe(200); // loads the device row
    const rows = await rowsWrittenDuring(fx, async () => {
      expect((await fx.get(fx.owner, '/membership')).status).toBe(200);
    });
    expect(rows).toBe(1);
  });

  it('refuses a replayed proof after the in-memory state is lost', async () => {
    const fx = await VaultFixture.create();
    const first = await fx.get(fx.owner, '/membership');
    expect(first.status).toBe(200);
    await runInDurableObject(stubFor(fx.vaultId), (instance: VaultDurableObject, state: DurableObjectState) => {
      // As after eviction: same storage, empty memory.
      (instance as unknown as { replay: ProofReplayStore }).replay = new ProofReplayStore(state.storage.sql);
    });
    const replay = await call(fx.owner, 'GET', membershipPath(fx), undefined, { token: first.token, proof: first.proof });
    expect(replay.status).toBe(401);
    expect((await fx.get(fx.owner, '/membership')).status).toBe(200);
  });

  it('refuses a proof burned in the legacy per-jti table until it expires', async () => {
    const fx = await VaultFixture.create();
    const first = await fx.get(fx.owner, '/membership');
    expect(first.status).toBe(200);
    const jti = await runInDurableObject(stubFor(fx.vaultId), (instance: VaultDurableObject, state: DurableObjectState) => {
      const sql = state.storage.sql;
      const seenJti = decodeProof(first.proof!).proof.jti;
      sql.exec('CREATE TABLE IF NOT EXISTS proof_jti (did TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (did, jti))');
      sql.exec('DELETE FROM proof_seen');
      sql.exec('INSERT INTO proof_jti VALUES (?, ?, ?)', fx.owner.keys.record.device_id, seenJti, Date.now() + 60_000);
      (instance as unknown as { replay: ProofReplayStore }).replay = new ProofReplayStore(sql);
      return seenJti;
    });
    expect(jti).toBeTruthy();
    const replay = await call(fx.owner, 'GET', membershipPath(fx), undefined, { token: first.token, proof: first.proof });
    expect(replay.status).toBe(401);
  });

  it('expired jtis are pruned from the device row', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.get(fx.owner, '/membership')).status).toBe(200);
    const stored = await runInDurableObject(stubFor(fx.vaultId), (_i: unknown, state: DurableObjectState) =>
      state.storage.sql.exec<{ jtis: string }>('SELECT jtis FROM proof_seen').toArray().map((r) => (JSON.parse(r.jtis) as unknown[]).length),
    );
    expect(stored.length).toBeGreaterThan(0);
    expect(Math.max(...stored)).toBeLessThanOrEqual(3);
  });
});
