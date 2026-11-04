/**
 * Conditional pull: `GET /changes?if_head=<tag>` at the head answers `304` with no body,
 * and any change to the head (a record, a membership event) answers in full again.
 */
import { changesHeadTag, randomId, type ChangesHead } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { VaultDurableObject } from '../src/vault/vault-durable-object.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const stubOf = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

async function head(fx: VaultFixture): Promise<ChangesHead> {
  const res = await fx.get(fx.owner, '/changes?cursor=0');
  expect(res.status).toBe(200);
  return res.json.head as ChangesHead;
}

/** Rows read through the vault object's SQL handle while `run` executes. */
async function rowsReadDuring(vaultId: string, run: () => Promise<void>): Promise<number> {
  const cursors: SqlStorageCursor<Record<string, SqlStorageValue>>[] = [];
  await runInDurableObject(stubOf(vaultId), (instance: VaultDurableObject) => {
    const sql = (instance as unknown as { sql: SqlStorage }).sql;
    const exec = sql.exec.bind(sql);
    (sql as { exec: typeof sql.exec }).exec = ((query: string, ...bindings: unknown[]) => {
      const cursor = exec(query, ...bindings);
      cursors.push(cursor);
      return cursor;
    }) as typeof sql.exec;
  });
  await run();
  return runInDurableObject(stubOf(vaultId), (instance: VaultDurableObject) => {
    delete ((instance as unknown as { sql: SqlStorage }).sql as { exec?: unknown }).exec;
    return cursors.reduce((sum, c) => sum + c.rowsRead, 0);
  });
}

describe('conditional pull', () => {
  it('answers 304 with no body while the head is unchanged, and reads no rows', async () => {
    const fx = await VaultFixture.create();
    const h = await head(fx);
    const path = `/changes?cursor=${h.log_seq}&if_head=${changesHeadTag(h)}`;
    expect((await fx.get(fx.owner, path)).status).toBe(304);
    const rows = await rowsReadDuring(fx.vaultId, async () => {
      for (let i = 0; i < 5; i++) {
        const res = await fx.get(fx.owner, path);
        expect(res.status).toBe(304);
        expect(res.json).toBeNull();
      }
    });
    expect(rows).toBe(0);
  });

  it('answers in full after a record is written', async () => {
    const fx = await VaultFixture.create();
    const h = await head(fx);
    expect((await fx.write(fx.owner, randomId(), 0, { name: 'SYNTH', value: 'synthetic' })).status).toBe(200);
    const res = await fx.get(fx.owner, `/changes?cursor=${h.log_seq}&if_head=${changesHeadTag(h)}`);
    expect(res.status).toBe(200);
    expect(res.json.changes).toHaveLength(1);
    expect(res.json.head.log_seq).toBe(h.log_seq + 1);
  });

  it('answers in full after a membership event', async () => {
    const fx = await VaultFixture.create();
    const h = await head(fx);
    await fx.addDevice();
    const res = await fx.get(fx.owner, `/changes?cursor=${h.log_seq}&if_head=${changesHeadTag(h)}`);
    expect(res.status).toBe(200);
    expect(res.json.head.membership_seq).toBeGreaterThan(h.membership_seq);
  });

  it('answers in full for another tag or a cursor behind the head', async () => {
    const fx = await VaultFixture.create();
    expect((await fx.write(fx.owner, randomId(), 0, { name: 'SYNTH', value: 'synthetic' })).status).toBe(200);
    const h = await head(fx);
    const tag = changesHeadTag(h);
    expect((await fx.get(fx.owner, `/changes?cursor=${h.log_seq}&if_head=${changesHeadTag({ ...h, key_epoch: h.key_epoch + 1 })}`)).status).toBe(200);
    const behind = await fx.get(fx.owner, `/changes?cursor=0&if_head=${tag}`);
    expect(behind.status).toBe(200);
    expect(behind.json.changes).toHaveLength(1);
  });

  it('ignores an if_head that is not a current tag', async () => {
    const fx = await VaultFixture.create();
    const h = await head(fx);
    expect((await fx.get(fx.owner, `/changes?cursor=${h.log_seq}&if_head=not-a-tag`)).status).toBe(200);
    expect((await fx.get(fx.owner, `/changes?cursor=${h.log_seq}&if_head=`)).status).toBe(200);
  });

  it('still authenticates: a conditional pull without a valid proof is refused', async () => {
    const fx = await VaultFixture.create();
    const h = await head(fx);
    const path = `/changes?cursor=${h.log_seq}&if_head=${changesHeadTag(h)}`;
    const first = await fx.get(fx.owner, path);
    expect(first.status).toBe(304);
    expect((await fx.get(fx.owner, path, { token: first.token, proof: first.proof })).status).toBe(401);
  });
});
