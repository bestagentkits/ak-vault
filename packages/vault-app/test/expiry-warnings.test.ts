// @vitest-environment happy-dom
/**
 * Expiry warnings from a secret profile's `expires_at`: expired and expiring
 * soon. They come only from the profile this device verified, sit beside the
 * rotation health without replacing it, and change no grant.
 */
import { describe, expect, it } from 'vitest';
import { randomId, type JsonObject } from '@ak-vault/protocol';
import { DAY_MS, EXPIRING_SOON_DAYS, parseExpiresMs, rotationInfo, type RotationInput } from '../src/sync/rotation.js';
import type { ItemView } from '../src/sync/vault-sync.js';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, type Page } from './helpers/dashboard-page.js';

const NOW = 1_800_000_000_000;
const base: RotationInput = { createdMs: NOW - 10 * DAY_MS, rotatedMs: null, rotateTtlDays: null, flaggedMs: null, flaggedEpoch: null, keyEpoch: 1, workflow: null, expiresMs: null };

/** `expires_at` in the strict profile form (whole seconds, `Z`). */
function iso(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

describe('parseExpiresMs', () => {
  it('reads the strict profile form', () => {
    expect(parseExpiresMs('2027-01-31T12:00:00Z')).toBe(Date.UTC(2027, 0, 31, 12));
  });

  it('ignores anything the profile rule would not accept', () => {
    for (const bad of [
      undefined, null, 1_800_000_000_000, ['2027-01-31T12:00:00Z'], '',
      '2027-01-31', '2027-01-31T12:00:00', '2027-01-31T12:00:00.000Z', '2027-01-31T12:00:00+00:00',
      ' 2027-01-31T12:00:00Z', '2027-02-30T00:00:00Z', '2027-13-01T00:00:00Z', '2027-01-31T24:00:00Z', '0000-01-01T00:00:00Z',
    ]) {
      expect(parseExpiresMs(bad), String(bad)).toBeNull();
    }
  });
});

describe('expiry in rotationInfo', () => {
  it('is expired at or after expires_at', () => {
    expect(rotationInfo({ ...base, expiresMs: NOW - 3 * DAY_MS }, NOW)).toMatchObject({ expiry: 'expired', expiresMs: NOW - 3 * DAY_MS, daysUntilExpiry: -3 });
    expect(rotationInfo({ ...base, expiresMs: NOW }, NOW).expiry).toBe('expired');
  });

  it(`is expiring soon within ${EXPIRING_SOON_DAYS} days`, () => {
    expect(rotationInfo({ ...base, expiresMs: NOW + 1 }, NOW).expiry).toBe('expiring_soon');
    expect(rotationInfo({ ...base, expiresMs: NOW + 3 * DAY_MS }, NOW)).toMatchObject({ expiry: 'expiring_soon', daysUntilExpiry: 3 });
    expect(rotationInfo({ ...base, expiresMs: NOW + EXPIRING_SOON_DAYS * DAY_MS }, NOW).expiry).toBe('expiring_soon');
  });

  it('is ok when far in the future', () => {
    expect(rotationInfo({ ...base, expiresMs: NOW + EXPIRING_SOON_DAYS * DAY_MS + 1 }, NOW).expiry).toBe('ok');
    expect(rotationInfo({ ...base, expiresMs: NOW + 365 * DAY_MS }, NOW)).toMatchObject({ expiry: 'ok', daysUntilExpiry: 365 });
  });

  it('is absent without expires_at', () => {
    expect(rotationInfo(base, NOW)).toMatchObject({ expiry: null, expiresMs: null, daysUntilExpiry: null });
  });

  it('leaves rotation health untouched, so neither hides the other', () => {
    const flagged = { ...base, rotateTtlDays: 365, flaggedMs: NOW - DAY_MS, flaggedEpoch: 2, keyEpoch: 2 };
    expect(rotationInfo({ ...flagged, expiresMs: NOW - DAY_MS }, NOW)).toMatchObject({ health: 'needs_rotate', expiry: 'expired' });
    expect(rotationInfo({ ...base, rotateTtlDays: 5, expiresMs: NOW + DAY_MS }, NOW)).toMatchObject({ health: 'overdue', expiry: 'expiring_soon' });
    expect(rotationInfo({ ...base, rotateTtlDays: 365, expiresMs: NOW - DAY_MS }, NOW)).toMatchObject({ health: 'ok', expiry: 'expired' });
  });
});

function vaultScreen(page: Page) {
  const s = page.controller.current();
  if (s.kind !== 'vault') throw new Error(`not a vault screen: ${s.kind}`);
  return s;
}

function row(page: Page, name: string): HTMLElement {
  const li = allByTestId(page.root, 'item').find((el) => byTestId(el, 'item-name').textContent === name);
  if (!li) throw new Error('missing row');
  return li;
}

function itemNamed(page: Page, name: string): ItemView {
  const found = vaultScreen(page).items.find((i) => i.name === name);
  if (!found) throw new Error('missing item');
  return found;
}

describe('dashboard expiry warnings', () => {
  it('warns on expired and expiring-soon items from the verified profile and stays silent otherwise', async () => {
    const world = new FakeWorld();
    const owner = world.owner.record.device_id;
    const at = Date.now();
    const meta = (profile?: JsonObject): JsonObject => ({ schema: 'agentkit.secret/v1', created_ms: at - DAY_MS, ...(profile ? { profile } : {}) });
    const field = (value: string, by = owner): JsonObject => ({ value, by, at, src: 'local' });
    world.ownerSet('expired', 'a', meta({ expires_at: field(iso(at - 2 * DAY_MS)) }), at);
    world.ownerSet('soon', 'a', meta({ expires_at: field(iso(at + 3 * DAY_MS)) }), at);
    world.ownerSet('far', 'a', meta({ expires_at: field(iso(at + 365 * DAY_MS)) }), at);
    world.ownerSet('none', 'a', meta(), at);
    // Not a valid profile at all: the whole profile is ignored.
    world.ownerSet('malformed', 'a', meta({ expires_at: field('2020-01-01') }), at);
    // Claims another device wrote it: the provenance check drops the field.
    world.ownerSet('forged', 'a', meta({ expires_at: field(iso(at - 2 * DAY_MS), randomId()) }), at);
    const { page } = await new Browser(world).enroll();

    const badge = (name: string) => row(page, name).querySelector('[data-testid="expiry-health"]')?.textContent ?? null;
    expect(Object.fromEntries(['expired', 'soon', 'far', 'none', 'malformed', 'forged'].map((n) => [n, badge(n)]))).toEqual({
      expired: 'expired', soon: 'expires soon', far: null, none: null, malformed: null, forged: null,
    });
    expect(byTestId(row(page, 'expired'), 'expiry-due').textContent).toMatch(/^expired \d{4}-\d{2}-\d{2} \([23] days ago\)$/);
    expect(byTestId(row(page, 'soon'), 'expiry-due').textContent).toMatch(/^expires \d{4}-\d{2}-\d{2} \(in [23] days\)$/);
    expect(byTestId(row(page, 'far'), 'expiry-due').textContent).toMatch(/^expires /);
    for (const n of ['none', 'malformed', 'forged']) {
      expect(row(page, n).querySelector('[data-testid="expiry-due"]'), n).toBeNull();
      expect(itemNamed(page, n).expiresMs, n).toBeNull();
    }
    // The rotation health is still shown next to it, unchanged.
    expect(byTestId(row(page, 'expired'), 'rotation-health').textContent).toBe('rotation unknown');
    expect(byTestId(page.root, 'expiry-expired').textContent).toBe('1 expired');
    expect(byTestId(page.root, 'expiry-expiring_soon').textContent).toBe('1 expires soon');

    // Informational only: an expired item keeps every action and accepts a write.
    expect(vaultScreen(page).canWrite).toBe(true);
    for (const id of ['delete', 'rotate', 'history']) expect((byTestId(row(page, 'expired'), id) as HTMLButtonElement).disabled, id).toBe(false);
    expect(await page.controller.set('expired', 'b')).toBe(true);
  });

  it('ignores expires_at from a profile this device could not verify', async () => {
    const world = new FakeWorld();
    const owner = world.owner.record.device_id;
    const at = Date.now();
    const meta: JsonObject = { schema: 'agentkit.secret/v1', profile: { expires_at: { value: iso(at - 2 * DAY_MS), by: owner, at, src: 'local' } } };
    const id = world.ownerSet('unverified', 'a', meta, at);
    world.rekey();
    expect(world.ownerWrite(id, 'unverified', 'b', { base: 1, ts: at + 1, meta }).status).toBe(200);
    const b = new Browser(world);
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    // This browser never holds epoch 1, so the base of the head is unverifiable.
    world.approve(joinCode, offer.nonceI, { omitEpochs: [1] });
    await page.controller.checkApproval();
    const item = itemNamed(page, 'unverified');
    // The field is still listed (marked `sync`), but it raises no warning.
    expect(item.profile.map((p) => p.key)).toEqual(['expires_at']);
    expect(item.expiresMs).toBeNull();
    expect(page.root.querySelector('[data-testid="expiry-health"]')).toBeNull();
    expect(byTestId(page.root, 'expiry-expired').textContent).toBe('0 expired');
  });
});
