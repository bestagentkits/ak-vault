/** Per-device fixed-window rate limit inside the vault Durable Object. */
import { randomBytes, randomId } from '@ak-vault/protocol';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { VaultFixture } from './helpers/vault-fixture.js';

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

    // The device itself still has its whole budget: genesis used 1 of 120.
    for (let i = 0; i < 119; i++) expect((await fx.get(fx.owner, '/changes')).status).toBe(200);
    expect((await fx.get(fx.owner, '/changes')).status).toBe(429);
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
