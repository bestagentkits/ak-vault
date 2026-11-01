/**
 * The recovery-identity path (a not-yet-enrolled owner-account device reading
 * `GET /recovery` or `GET /membership` with `AKV-Device-Key`) spends a per-account
 * budget in the vault, so minting tokens for fresh device IDs does not buy fresh
 * budgets. Enrolled devices and other accounts keep their own budgets.
 */
import { randomBytes, randomId } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LIMITS } from '../src/limits.js';
import { createDevice, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { putTestBundle, sealTestBundle } from './helpers/recovery-bundle.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const BUDGET = LIMITS.recovery_identity_requests_per_window;
const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));
const keyHeader = (device: TestDevice): CallOptions => ({ headers: { 'AKV-Device-Key': device.keys.record.sign_pub } });

/** Freeze the clock 10 s into a window so a burst cannot straddle a boundary. */
function freezeIntoWindow(): void {
  vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
}

async function vaultWithBundle(): Promise<VaultFixture> {
  const fx = await VaultFixture.create();
  const put = await putTestBundle(fx, fx.owner, sealTestBundle(fx, 1));
  if (put.status !== 200) throw new Error(`bundle upload failed: ${put.status}`);
  return fx;
}

/** One recovery-identity read by a device ID never seen before; alternates bundle and membership reads. */
function freshRead(fx: VaultFixture, i: number, opts: CallOptions = {}) {
  const fresh = createDevice(fx.owner.account, 'owner');
  return fx.get(fresh, i % 2 === 0 ? '/recovery' : '/membership', { ...keyHeader(fresh), ...opts });
}

const accountRows = (fx: VaultFixture) =>
  runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) =>
    state.storage.sql.exec('SELECT account, count FROM recovery_identity_rate_counters').toArray(),
  );

afterEach(() => {
  vi.useRealTimers();
});

describe('recovery-identity rate limit per account', () => {
  it('fresh device IDs share one account budget, then 429 with Retry-After until the window ends', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    for (let i = 0; i < BUDGET; i++) expect((await freshRead(fx, i)).status).toBe(200);
    for (const path of ['/recovery', '/membership']) {
      const fresh = createDevice(fx.owner.account, 'owner');
      const limited = await fx.get(fresh, path, keyHeader(fresh));
      expect(limited.status).toBe(429);
      expect(limited.json).toEqual({ error: { code: 'rate_limited', message: 'too many requests' } });
      expect(limited.headers.get('Retry-After')).toBe('50');
    }

    vi.setSystemTime(Date.now() + 50_000);
    expect((await freshRead(fx, 0)).status).toBe(200);
  });

  it('refused proofs do not spend the account budget, and a spent budget refuses before the proof check', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    for (let i = 0; i < BUDGET + 10; i++) {
      const res = await freshRead(fx, i, { proofSecret: randomBytes(32) });
      expect(res.status).toBe(401);
      expect(res.json.error.code).toBe('invalid_signature');
    }
    // A missing key header, or a key whose kid is not the token did, spends nothing either.
    const fresh = createDevice(fx.owner.account, 'owner');
    expect((await fx.get(fresh, '/recovery')).status).toBe(401);
    expect((await fx.get(fresh, '/recovery', keyHeader(createDevice(fx.owner.account, 'owner')))).status).toBe(401);
    expect(await accountRows(fx)).toEqual([]);
    for (let i = 0; i < BUDGET; i++) expect((await freshRead(fx, i)).status).toBe(200);
    // Once spent, even a bad proof is answered 429 without verification.
    expect((await freshRead(fx, 0, { proofSecret: randomBytes(32) })).status).toBe(429);
    expect(await accountRows(fx)).toEqual([{ account: fx.owner.account, count: BUDGET }]);
  });

  it('leaves enrolled devices and other accounts in the vault unaffected', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    const laptop = await fx.addDevice();
    for (let i = 0; i < BUDGET; i++) expect((await freshRead(fx, i)).status).toBe(200);
    expect((await freshRead(fx, 0)).status).toBe(429);

    // Enrolled owner devices keep their normal path, with or without the key header.
    expect((await fx.get(fx.owner, '/recovery')).status).toBe(200);
    expect((await fx.get(laptop, '/membership')).status).toBe(200);
    expect((await fx.get(laptop, '/membership', keyHeader(laptop))).status).toBe(200);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(200);

    // Another account is refused for what it is, not rate limited by the owner's budget.
    const stranger = createDevice(`acct-${randomId()}`, 'owner');
    const refused = await fx.get(stranger, '/recovery', keyHeader(stranger));
    expect(refused.status).toBe(403);
    expect(refused.json.error.code).toBe('forbidden');
  });

  it("another account's vault keeps its own budget", async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    for (let i = 0; i < BUDGET; i++) expect((await freshRead(fx, i)).status).toBe(200);
    expect((await freshRead(fx, 0)).status).toBe(429);
    const other = await vaultWithBundle();
    for (let i = 0; i < BUDGET; i++) expect((await freshRead(other, i)).status).toBe(200);
  });

  it('another account or a removed device ID spends nothing', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    const stranger = createDevice(`acct-${randomId()}`, 'owner');
    expect((await fx.get(stranger, '/recovery', keyHeader(stranger))).status).toBe(403);
    const laptop = await fx.addDevice();
    expect((await fx.removeDevice(laptop)).status).toBe(201);
    expect((await fx.get(laptop, '/recovery', keyHeader(laptop))).status).toBe(403);
    expect(await accountRows(fx)).toEqual([]);
  });

  it('a non-email_otp session is refused before it can spend the account budget', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    for (let i = 0; i < BUDGET + 5; i++) expect((await freshRead(fx, i, { sessionKind: 'api_key_device' })).status).toBe(403);
    expect(await accountRows(fx)).toEqual([]);
    expect((await freshRead(fx, 0)).status).toBe(200);
  });

  it('counts per account in the vault, whatever device ID the token names', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    for (let i = 0; i < 3; i++) expect((await freshRead(fx, i)).status).toBe(200);
    expect(await accountRows(fx)).toEqual([{ account: fx.owner.account, count: 3 }]);
  });

  it('prunes account rows of earlier windows like the per-device counters', async () => {
    freezeIntoWindow();
    const fx = await vaultWithBundle();
    const stale = Math.floor(Date.now() / 60_000) * 60_000 - 120_000;
    await runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      state.storage.sql.exec('INSERT INTO recovery_identity_rate_counters (account, window_start, count) VALUES (?, ?, ?)', 'acct-stale', stale, 7);
    });
    expect((await freshRead(fx, 0)).status).toBe(200);
    expect(await accountRows(fx)).toEqual([{ account: fx.owner.account, count: 1 }]);
  });

  it('fails closed when the limiter storage errors', async () => {
    const fx = await vaultWithBundle();
    await runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) => {
      state.storage.sql.exec('DROP TABLE recovery_identity_rate_counters');
    });
    const res = await freshRead(fx, 0);
    expect(res.status).toBe(500);
    expect(res.json.error.code).toBe('internal');
    expect(res.json.bundle).toBeUndefined();
    // The enrolled path does not touch the per-account table.
    expect((await fx.get(fx.owner, '/recovery')).status).toBe(200);
  });
});
