/**
 * Operator point-in-time restore route: off unless its secret is set, HMAC over a
 * context-separated request carried in the body, origin and time bound, exact
 * request shapes, one vault object only, and compare-and-swap restores.
 *
 * Point-in-time recovery itself is not available in local workerd, so the route
 * tests check that the platform refusal surfaces as a fixed message, and the
 * restore logic is tested against an in-memory fake of the storage PITR API.
 * The real restore is rehearsed on staging (docs/operations/rehearsal-2026-10.md).
 */
import { b64encode, concatBytes, randomBytes, randomId, utf8Encode } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env.js';
import type { VaultDurableObject } from '../src/vault/vault-durable-object.js';
import { OPERATOR_SIGN_CONTEXT } from '../src/routes/operator-restore.js';
import { bookmarkForTime, PITR_WINDOW_MS, scheduleRestore, type PointInTimeStorage } from '../src/vault/point-in-time-restore.js';
import { BASE, fetchRaw } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const SECRET = 'test-only-operator-secret-0123456789abcdef';
const WITH_SECRET: Partial<Env> = { VAULT_OPERATOR_SECRET: SECRET };
const PLATFORM_TEXT = 'storage-layer detail that must never be echoed';

async function sign(secret: string, request: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', utf8Encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, concatBytes(utf8Encode(`${OPERATOR_SIGN_CONTEXT}\n`), utf8Encode(request)));
  return b64encode(new Uint8Array(mac));
}

interface SendOptions {
  env?: Partial<Env>;
  secret?: string;
  sig?: string;
  method?: string;
  raw?: string;
}

async function send(fields: Record<string, unknown>, opts: SendOptions = {}) {
  const request = JSON.stringify({ v: 1, origin: BASE, ts: Math.floor(Date.now() / 1000), ...fields });
  const body = opts.raw ?? JSON.stringify({ request, sig: opts.sig ?? (await sign(opts.secret ?? SECRET, request)) });
  const res = await fetchRaw('/internal/v1/operator', { method: opts.method ?? 'POST', body: opts.method === 'GET' ? null : body }, opts.env ?? WITH_SECRET);
  const text = await res.text();
  return { status: res.status, text, json: text ? (JSON.parse(text) as { error?: { code: string; message: string }; [k: string]: unknown }) : null };
}

const bookmarkOf = (vaultId: string, at_ms: number | null = null) => ({ action: 'bookmark', vault_id: vaultId, at_ms });

describe('operator restore route: authentication and shape', () => {
  it('answers 404 when the secret is unset or too short, like an unknown path', async () => {
    const fx = await VaultFixture.create();
    expect((await send(bookmarkOf(fx.vaultId), { env: {} })).status).toBe(404);
    expect((await send(bookmarkOf(fx.vaultId), { env: { VAULT_OPERATOR_SECRET: 'short' }, secret: 'short' })).status).toBe(404);
    expect((await fetchRaw('/internal/v1/operator-x', { method: 'POST' }, WITH_SECRET)).status).toBe(404);
  });

  it('refuses a wrong secret, a malformed or missing signature, and non-POST', async () => {
    const fx = await VaultFixture.create();
    expect((await send(bookmarkOf(fx.vaultId), { secret: 'another-operator-secret-0123456789abcdef' })).status).toBe(401);
    expect((await send(bookmarkOf(fx.vaultId), { sig: 'AAAA' })).status).toBe(401);
    expect((await send(bookmarkOf(fx.vaultId), { sig: '***' })).status).toBe(401);
    expect((await send(bookmarkOf(fx.vaultId), { raw: JSON.stringify({ request: '{}', sig: 1 }) })).status).toBe(401);
    expect((await send(bookmarkOf(fx.vaultId), { method: 'GET' })).status).toBe(404);
  });

  it('binds the origin and a ±60 s timestamp into the signed request', async () => {
    const fx = await VaultFixture.create();
    expect((await send({ ...bookmarkOf(fx.vaultId), origin: 'https://vault-staging.agentkit.best' })).status).toBe(401);
    expect((await send({ ...bookmarkOf(fx.vaultId), ts: Math.floor(Date.now() / 1000) - 61 })).status).toBe(401);
    expect((await send({ ...bookmarkOf(fx.vaultId), ts: Math.floor(Date.now() / 1000) + 61 })).status).toBe(401);
    expect((await send({ ...bookmarkOf(fx.vaultId), ts: '1' })).status).toBe(401);
  });

  it('refuses unknown versions, actions, extra or missing fields and malformed values', async () => {
    const fx = await VaultFixture.create();
    expect((await send({ ...bookmarkOf(fx.vaultId), v: 2 })).status).toBe(400);
    expect((await send({ ...bookmarkOf(fx.vaultId), action: 'export' })).status).toBe(400);
    expect((await send({ ...bookmarkOf(fx.vaultId), extra: true })).status).toBe(400);
    expect((await send({ action: 'bookmark', vault_id: fx.vaultId })).status).toBe(400);
    expect((await send(bookmarkOf(fx.vaultId, 1.5))).status).toBe(400);
    expect((await send({ action: 'restore', vault_id: fx.vaultId, bookmark: 'a b', expected_current: 'b' })).status).toBe(400);
    expect((await send({ action: 'restore', vault_id: fx.vaultId, bookmark: 'a' })).status).toBe(400);
    expect((await send(bookmarkOf(fx.vaultId), { raw: 'not json' })).status).toBe(400);
    expect((await send(bookmarkOf(fx.vaultId), { raw: JSON.stringify({ request: '{}', sig: 'x', more: 1 }) })).status).toBe(400);
  });

  it('refuses a vault_id that is not a 16-byte ID (the route only has the VAULT binding; this checks input validation)', async () => {
    expect((await send(bookmarkOf('global'))).status).toBe(400);
  });

  it('serves an object without a vault, so a restore to before genesis can be undone', async () => {
    const missing = b64encode(randomBytes(16));
    const res = await send(bookmarkOf(missing));
    expect(res.status).toBe(200);
    expect(res.json?.['vault_exists']).toBe(false);
    // Reading a bookmark creates no vault tables.
    await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(missing)), (_instance: unknown, state: DurableObjectState) => {
      expect(state.storage.sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'").toArray()).toHaveLength(0);
    });
  });

  it('works with the sync kill switch off', async () => {
    const fx = await VaultFixture.create();
    const res = await send(bookmarkOf(fx.vaultId), { env: { ...WITH_SECRET, VAULT_SYNC_ENABLED: 'false' } });
    expect(res.status).toBe(200);
    expect(res.json?.['vault_exists']).toBe(true);
  });

  it('returns the current bookmark, refuses a future time, and refuses a stale restore without touching the vault', async () => {
    // Local workerd keeps no point-in-time history: its bookmarks are placeholders
    // that advance on every call, so only the refusal paths are observable here.
    const fx = await VaultFixture.create();
    const id = randomId();
    expect((await fx.write(fx.owner, id, 0, { name: 'SYNTH_OPERATOR', value: 'synthetic' })).status).toBe(200);
    const read = await send(bookmarkOf(fx.vaultId));
    expect(read.status).toBe(200);
    const bookmark = read.json?.['bookmark'];
    expect(typeof bookmark === 'string' && /^[A-Za-z0-9_.:-]{1,256}$/.test(bookmark)).toBe(true);
    expect((await send(bookmarkOf(fx.vaultId, Date.now() + 60_000))).status).toBe(400);

    const stale = await send({ action: 'restore', vault_id: fx.vaultId, bookmark: '0', expected_current: bookmark });
    expect(stale.status).toBe(409);
    expect(stale.json?.error?.code).toBe('conflict');
    expect((await fx.get(fx.owner, `/items/${id}`)).status).toBe(200);
    expect(await fx.logHead()).toBe(1);
  });
});

describe('operator restore: pending restore and restart', () => {
  const stubOf = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

  it('refuses every sync and operator request while a restore is pending', async () => {
    const fx = await VaultFixture.create();
    await runInDurableObject(stubOf(fx.vaultId), (instance: VaultDurableObject) => {
      (instance as unknown as { restorePending: boolean }).restorePending = true;
    });
    const read = await fx.get(fx.owner, '/membership');
    expect(read.status).toBe(503);
    expect(read.json.error).toEqual({ code: 'internal', message: 'vault restore in progress' });
    const write = await fx.write(fx.owner, randomId(), 0, { name: 'SYNTH_PENDING', value: 'synthetic' });
    expect(write.status).toBe(503);
  });

  it('an operator request finishes a pending restore first: restart, then answer', async () => {
    const fx = await VaultFixture.create();
    const before = await stubOf(fx.vaultId).operatorInstance();
    await runInDurableObject(stubOf(fx.vaultId), (instance: VaultDurableObject) => {
      (instance as unknown as { restorePending: boolean }).restorePending = true;
    });
    expect((await fx.get(fx.owner, '/membership')).status).toBe(503);
    const res = await send(bookmarkOf(fx.vaultId));
    expect(res.status).toBe(200);
    expect(res.json?.['vault_exists']).toBe(true);
    const after = await stubOf(fx.vaultId).operatorInstance();
    expect(after.instance).not.toBe(before.instance);
    expect(after.restorePending).toBe(false);
    expect((await fx.get(fx.owner, '/membership')).status).toBe(200);
  });

  it('a restart starts a new instance that is no longer pending, and the vault serves again', async () => {
    const fx = await VaultFixture.create();
    const before = await stubOf(fx.vaultId).operatorInstance();
    await runInDurableObject(stubOf(fx.vaultId), (instance: VaultDurableObject) => {
      (instance as unknown as { restorePending: boolean }).restorePending = true;
    });
    await stubOf(fx.vaultId)
      .operatorRestart()
      .catch(() => undefined);
    const after = await stubOf(fx.vaultId).operatorInstance();
    expect(after.instance).not.toBe(before.instance);
    expect(after.restorePending).toBe(false);
    expect((await fx.get(fx.owner, '/membership')).status).toBe(200);
  });
});

/** In-memory model of the PITR API: bookmarks are ordered, every restore moves history forward. */
class FakePitr implements PointInTimeStorage {
  position = 10;
  restoredTo: string | null = null;
  failWith: Error | null = null;
  pendingLog: boolean[] = [];
  markPending = (): void => {
    this.pendingLog.push(true);
  };
  bookmark(n: number): string {
    return `0000${n.toString(16).padStart(8, '0')}`;
  }
  async getCurrentBookmark(): Promise<string> {
    if (this.failWith) throw this.failWith;
    return this.bookmark(this.position);
  }
  async getBookmarkForTime(): Promise<string> {
    if (this.failWith) throw this.failWith;
    return this.bookmark(this.position - 5);
  }
  async onNextSessionRestoreBookmark(target: string): Promise<string> {
    if (this.failWith) throw this.failWith;
    this.restoredTo = target;
    const undo = this.bookmark(this.position);
    this.position += 1;
    return undo;
  }
}

describe('point-in-time restore logic', () => {
  it('schedules a restore at the expected point and returns the undo bookmark', async () => {
    const pitr = new FakePitr();
    const undo = await scheduleRestore(pitr, pitr.bookmark(4), pitr.bookmark(10), pitr.markPending);
    expect(pitr.pendingLog).toEqual([true]);
    expect(undo).toBe(pitr.bookmark(10));
    expect(pitr.restoredTo).toBe(pitr.bookmark(4));
  });

  it('refuses a stale expected point, so a replayed restore does nothing', async () => {
    const pitr = new FakePitr();
    await scheduleRestore(pitr, pitr.bookmark(4), pitr.bookmark(10), pitr.markPending);
    pitr.restoredTo = null;
    await expect(scheduleRestore(pitr, pitr.bookmark(4), pitr.bookmark(10), pitr.markPending)).rejects.toMatchObject({ code: 'conflict', status: 409 });
    expect(pitr.restoredTo).toBeNull();
  });

  it('maps platform errors to a fixed message that echoes nothing', async () => {
    const pitr = new FakePitr();
    pitr.failWith = new Error(PLATFORM_TEXT);
    const err = await scheduleRestore(pitr, pitr.bookmark(4), pitr.bookmark(10), pitr.markPending).catch((e: unknown) => e);
    expect(err).toMatchObject({ code: 'bad_request', message: 'point-in-time recovery refused the request' });
    expect(String((err as Error).message)).not.toContain(PLATFORM_TEXT);
  });

  it('refuses a platform value that is not a bookmark', async () => {
    const pitr = new FakePitr();
    pitr.getCurrentBookmark = async () => 'not a bookmark';
    await expect(scheduleRestore(pitr, '0001', '0002', pitr.markPending)).rejects.toMatchObject({ code: 'internal' });
    expect(pitr.pendingLog).toEqual([]);
  });

  it('stays pending once the platform call started, even when it fails', async () => {
    const refused = new FakePitr();
    refused.onNextSessionRestoreBookmark = async () => {
      throw new Error(PLATFORM_TEXT);
    };
    await expect(scheduleRestore(refused, refused.bookmark(4), refused.bookmark(10), refused.markPending)).rejects.toMatchObject({ code: 'bad_request' });
    expect(refused.pendingLog).toEqual([true]);

    const malformed = new FakePitr();
    malformed.onNextSessionRestoreBookmark = async () => 'not a bookmark';
    await expect(scheduleRestore(malformed, malformed.bookmark(4), malformed.bookmark(10), malformed.markPending)).rejects.toMatchObject({ code: 'internal' });
    expect(malformed.pendingLog).toEqual([true]);
  });

  it('accepts time lookups only inside the 30-day window and not in the future', async () => {
    const pitr = new FakePitr();
    const now = Date.now();
    expect(await bookmarkForTime(pitr, now - 60_000, now)).toBe(pitr.bookmark(5));
    await expect(bookmarkForTime(pitr, now + 1, now)).rejects.toMatchObject({ code: 'bad_request' });
    await expect(bookmarkForTime(pitr, now - PITR_WINDOW_MS - 1, now)).rejects.toMatchObject({ code: 'bad_request' });
  });
});
