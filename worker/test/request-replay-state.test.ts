/**
 * Rate windows and burned proof `jti`s live in vault-object memory: a steady-state pull
 * writes no SQLite rows, and single use of a proof survives a restart (clean: reloaded;
 * unclean: proofs from before the restart plus the clock skew are refused).
 */
import { randomId } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { replayStateFor } from '../src/vault/request-replay-state.js';
import type { VaultDurableObject } from '../src/vault/vault-durable-object.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const stubOf = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));
const sqlOf = (instance: unknown) => (instance as { sql: SqlStorage }).sql;

afterEach(() => {
  vi.useRealTimers();
});

async function restart(vaultId: string): Promise<void> {
  await stubOf(vaultId)
    .operatorRestart()
    .catch(() => undefined);
}

/** Count rows written through the vault object's SQL handle while `run` executes. */
async function rowsWrittenDuring(vaultId: string, run: () => Promise<void>): Promise<number> {
  const cursors: SqlStorageCursor<Record<string, SqlStorageValue>>[] = [];
  await runInDurableObject(stubOf(vaultId), (instance: VaultDurableObject) => {
    const sql = sqlOf(instance);
    const exec = sql.exec.bind(sql);
    (sql as { exec: typeof sql.exec }).exec = ((query: string, ...bindings: unknown[]) => {
      const cursor = exec(query, ...bindings);
      cursors.push(cursor);
      return cursor;
    }) as typeof sql.exec;
  });
  await run();
  return runInDurableObject(stubOf(vaultId), (instance: VaultDurableObject) => {
    delete (sqlOf(instance) as { exec?: unknown }).exec;
    return cursors.reduce((sum, c) => sum + c.rowsWritten, 0);
  });
}

describe('request replay state', () => {
  it('a steady-state pull writes no rows', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
    const rows = await rowsWrittenDuring(fx.vaultId, async () => {
      for (let i = 0; i < 20; i++) expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
    });
    expect(rows).toBe(0);
  });

  it('the row count sees writes (control)', async () => {
    const fx = await VaultFixture.create();
    const rows = await rowsWrittenDuring(fx.vaultId, async () => {
      expect((await fx.write(fx.owner, randomId(), 0, { name: 'SYNTH', value: 'synthetic' })).status).toBe(200);
    });
    expect(rows).toBeGreaterThan(0);
  });

  it('a replayed proof is refused', async () => {
    const fx = await VaultFixture.create();
    const first = await fx.get(fx.owner, '/changes');
    expect(first.status).toBe(200);
    expect((await fx.get(fx.owner, '/changes', { token: first.token, proof: first.proof })).status).toBe(401);
  });

  it('after a clean stop the burned jtis are reloaded and fresh proofs are served at once', async () => {
    const fx = await VaultFixture.create();
    const first = await fx.get(fx.owner, '/changes');
    expect(first.status).toBe(200);
    await runInDurableObject(stubOf(fx.vaultId), (instance: VaultDurableObject) => {
      replayStateFor(sqlOf(instance), Date.now()).flush(Date.now());
    });
    await restart(fx.vaultId);
    expect((await fx.get(fx.owner, '/changes', { token: first.token, proof: first.proof })).status).toBe(401);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
  });

  it('after an unclean stop proofs from before it plus the skew are refused, later ones served', async () => {
    const fx = await VaultFixture.create();
    const first = await fx.get(fx.owner, '/changes');
    expect(first.status).toBe(200);
    await restart(fx.vaultId);
    expect((await fx.get(fx.owner, '/changes', { token: first.token, proof: first.proof })).status).toBe(401);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(401);
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 61_000 });
    expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
  });

  it('an unreadable session marker fails closed', async () => {
    const fx = await VaultFixture.create();
    await runInDurableObject(stubOf(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      state.storage.sql.exec("UPDATE meta SET v = 'not json' WHERE k = 'request_replay_state'");
    });
    await restart(fx.vaultId);
    const res = await fx.get(fx.owner, '/changes');
    expect(res.status).toBe(500);
    expect(res.json.error.code).toBe('internal');
  });
});
