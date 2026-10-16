/** Per-device fixed-window rate limit inside the vault Durable Object. */
import { randomBytes, randomId } from '@ak-vault/protocol';
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { VaultFixture } from './helpers/vault-fixture.js';

const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));

afterEach(() => {
  vi.useRealTimers();
});

describe('rate limit', () => {
  it('allows the window budget, then 429 with Retry-After for that device only', async () => {
    // Freeze the clock 10 s into a window so the test cannot straddle a boundary.
    vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    // Genesis and the enrollment above already used 2 of the owner's 120 requests.
    for (let i = 0; i < 118; i++) {
      const res = await fx.get(fx.owner, '/membership');
      expect(res.status).toBe(200);
    }
    const limited = await fx.get(fx.owner, '/membership');
    expect(limited.status).toBe(429);
    expect(limited.json.error.code).toBe('rate_limited');
    expect(limited.headers.get('Retry-After')).toBe('50');
    expect((await fx.get(laptop, '/membership')).status).toBe(200);

    vi.setSystemTime(Date.now() + 50_000);
    expect((await fx.get(fx.owner, '/membership')).status).toBe(200);
  });

  it('requests refused at authorization spend a separate budget, so a stolen token cannot exhaust the device', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
    const fx = await VaultFixture.create();
    const laptop = await fx.addDevice();
    // The thief holds a valid token for the owner device but signs proofs with a key of its own.
    const thief = { proofSecret: randomBytes(32) };
    for (let i = 0; i < 120; i++) {
      const res = await fx.get(fx.owner, '/changes', thief);
      expect(res.status).toBe(401);
      expect(res.json.error.code).toBe('invalid_signature');
    }
    const limited = await fx.get(fx.owner, '/changes', thief);
    expect(limited.status).toBe(429);
    expect(limited.json.error.code).toBe('rate_limited');
    expect(limited.headers.get('Retry-After')).toBe('50');

    // The refused budget is per device: another device's refusals still answer with their real error.
    expect((await fx.get(laptop, '/changes', thief)).status).toBe(401);

    // The device itself still has its whole budget: genesis and the enrollment used 2 of 120.
    for (let i = 0; i < 118; i++) expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(429);

    // Both windows reset together.
    vi.setSystemTime(Date.now() + 50_000);
    expect((await fx.get(fx.owner, '/changes', thief)).status).toBe(401);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
  });

  it('a device over its own budget is refused before authorization and charges nothing more', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
    const fx = await VaultFixture.create();
    for (let i = 0; i < 119; i++) expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
    // Anyone presenting the token now gets 429 without a proof check, and the refused budget is untouched.
    expect((await fx.get(fx.owner, '/changes', { proofSecret: randomBytes(32) })).status).toBe(429);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(429);
    const refusedRows = await runInDurableObject(stubFor(fx.vaultId), (_instance: unknown, state: DurableObjectState) =>
      state.storage.sql.exec('SELECT 1 FROM refused_rate_counters').toArray().length,
    );
    expect(refusedRows).toBe(0);
  });

  it('a mutation without a valid Idempotency-Key is charged to the refused budget', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
    const fx = await VaultFixture.create();
    const v = { name: 'n', value: 'v' };
    for (let i = 0; i < 120; i++) expect((await fx.write(fx.owner, randomId(), 0, v, { idempotencyKey: 'k'.repeat(200) })).status).toBe(400);
    expect((await fx.write(fx.owner, randomId(), 0, v, { idempotencyKey: 'k'.repeat(200) })).status).toBe(429);
    expect((await fx.write(fx.owner, randomId(), 0, v)).status).toBe(200);
  });

  it('a device refused for its role spends its refused budget, not its authorized one', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Math.floor(Date.now() / 60_000) * 60_000 + 10_000 });
    const fx = await VaultFixture.create('shared');
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    for (let i = 0; i < 120; i++) expect((await fx.get(reader, '/recovery')).status).toBe(403);
    expect((await fx.get(reader, '/recovery')).status).toBe(429);
    expect((await fx.get(reader, '/membership')).status).toBe(200);
  });
});
