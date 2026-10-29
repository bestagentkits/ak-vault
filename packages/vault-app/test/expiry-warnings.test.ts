// @vitest-environment happy-dom
/**
 * Expiry warnings from a secret profile's `expires_at`: expired and expiring
 * soon. They come only from the profile this device verified, sit beside the
 * rotation health without replacing it, and change no grant.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomId, type JsonObject } from '@ak-vault/protocol';
import { calendarDaysUntil } from '../src/ui/views.js';
import { DAY_MS, EXPIRING_SOON_DAYS, parseExpiresMs, rotationInfo, type RotationInput } from '../src/sync/rotation.js';
import type { ItemView } from '../src/sync/vault-sync.js';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, type Page } from './helpers/dashboard-page.js';

const NOW = 1_800_000_000_000;
const base: RotationInput = { createdMs: NOW - 10 * DAY_MS, rotatedMs: null, rotateTtlDays: null, flaggedMs: null, flaggedEpoch: null, keyEpoch: 1, workflow: null, expiresMs: null };

/** `expires_at` in the strict profile form (whole seconds, `Z`). */
afterEach(() => {
  vi.restoreAllMocks();
});

function iso(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

describe('parseExpiresMs', () => {
  it('reads the strict profile form, including dates before 1970', () => {
    expect(parseExpiresMs('2027-01-31T12:00:00Z')).toBe(Date.UTC(2027, 0, 31, 12));
    expect(parseExpiresMs('1969-12-31T00:00:00Z')).toBe(-DAY_MS);
    expect(parseExpiresMs('1970-01-01T00:00:00Z')).toBe(0);
  });

  it('ignores anything the profile rule would not accept', () => {
    for (const bad of [
      undefined, null, 1_800_000_000_000, ['2027-01-31T12:00:00Z'], '',
      '2027-01-31', '2027-01-31T12:00:00', '2027-01-31T12:00:00.000Z', '2027-01-31T12:00:00+00:00',
      ' 2027-01-31T12:00:00Z', '2027-02-30T00:00:00Z', '2027-13-01T00:00:00Z', '2027-01-31T24:00:00Z',
    ]) {
      expect(parseExpiresMs(bad), String(bad)).toBeNull();
    }
  });
});

describe('expiry in rotationInfo', () => {
  it('is expired at or after expires_at', () => {
    expect(rotationInfo({ ...base, expiresMs: NOW - 3 * DAY_MS }, NOW)).toMatchObject({ expiry: 'expired', expiresMs: NOW - 3 * DAY_MS });
    expect(rotationInfo({ ...base, expiresMs: NOW }, NOW)).toMatchObject({ expiry: 'expired' });
    expect(rotationInfo({ ...base, expiresMs: -DAY_MS }, NOW)).toMatchObject({ expiry: 'expired', expiresMs: -DAY_MS });
  });

  it(`is expiring soon within ${EXPIRING_SOON_DAYS} days`, () => {
    expect(rotationInfo({ ...base, expiresMs: NOW + 1 }, NOW).expiry).toBe('expiring_soon');
    expect(rotationInfo({ ...base, expiresMs: NOW + 3 * DAY_MS }, NOW)).toMatchObject({ expiry: 'expiring_soon' });
    expect(rotationInfo({ ...base, expiresMs: NOW + EXPIRING_SOON_DAYS * DAY_MS }, NOW).expiry).toBe('expiring_soon');
  });

  it('is ok when far in the future', () => {
    expect(rotationInfo({ ...base, expiresMs: NOW + EXPIRING_SOON_DAYS * DAY_MS + 1 }, NOW).expiry).toBe('ok');
    expect(rotationInfo({ ...base, expiresMs: NOW + 365 * DAY_MS }, NOW)).toMatchObject({ expiry: 'ok' });
  });

  it('is absent without expires_at', () => {
    expect(rotationInfo(base, NOW)).toMatchObject({ expiry: null, expiresMs: null });
  });

  it('leaves rotation health untouched, so neither hides the other', () => {
    const flagged = { ...base, rotateTtlDays: 365, flaggedMs: NOW - DAY_MS, flaggedEpoch: 2, keyEpoch: 2 };
    expect(rotationInfo({ ...flagged, expiresMs: NOW - DAY_MS }, NOW)).toMatchObject({ health: 'needs_rotate', expiry: 'expired' });
    expect(rotationInfo({ ...base, rotateTtlDays: 5, expiresMs: NOW + DAY_MS }, NOW)).toMatchObject({ health: 'overdue', expiry: 'expiring_soon' });
    expect(rotationInfo({ ...base, rotateTtlDays: 365, expiresMs: NOW - DAY_MS }, NOW)).toMatchObject({ health: 'ok', expiry: 'expired' });
  });
});

/** The viewer-time-zone calendar day of an `expires_at`, as the row prints it. */
function day(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${String(d.getFullYear()).padStart(4, '0')}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

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
    // Local noon keeps every whole-day offset on the same side of midnight, DST included.
    const t = new Date();
    const at = new Date(t.getFullYear(), t.getMonth(), t.getDate(), 12).getTime();
    vi.spyOn(Date, 'now').mockReturnValue(at);
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
    expect(byTestId(row(page, 'expired'), 'expiry-due').textContent).toBe(`expired ${day(at - 2 * DAY_MS)} (2 days ago)`);
    expect(byTestId(row(page, 'soon'), 'expiry-due').textContent).toBe(`expires ${day(at + 3 * DAY_MS)} (in 3 days)`);
    expect(byTestId(row(page, 'far'), 'expiry-due').textContent).toBe(`expires ${day(at + 365 * DAY_MS)} (in 365 days)`);
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

  it('reads under a day either side as today, and shows a pre-1970 expiry as expired', async () => {
    // Freeze the clock (before the controller captures Date.now) at local noon, so "today" holds a day either side of it.
    const t = new Date();
    const frozen = new Date(t.getFullYear(), t.getMonth(), t.getDate(), 12).getTime();
    vi.spyOn(Date, 'now').mockReturnValue(frozen);
    const world = new FakeWorld();
    const owner = world.owner.record.device_id;
    const seed = (name: string, expiresAt: string) =>
      world.ownerSet(name, 'a', { schema: 'agentkit.secret/v1', profile: { expires_at: { value: expiresAt, by: owner, at: frozen, src: 'local' } } }, frozen);
    seed('one-second-past', iso(frozen - 1000));
    seed('exactly-now', iso(frozen));
    seed('in-23-hours', iso(frozen + 23 * 3_600_000));
    seed('pre-1970', '1969-12-31T00:00:00Z');
    const { page } = await new Browser(world).enroll();
    const text = (name: string) => byTestId(row(page, name), 'expiry-due').textContent;
    const badge = (name: string) => byTestId(row(page, name), 'expiry-health').textContent;
    expect(text('one-second-past')).toBe(`expired ${day(frozen - 1000)} (today)`);
    expect(badge('one-second-past')).toBe('expired');
    expect(text('exactly-now')).toBe(`expired ${day(frozen)} (today)`);
    expect(badge('exactly-now')).toBe('expired');
    expect(text('in-23-hours')).toBe(`expires ${day(frozen + 23 * 3_600_000)} (in 1 day)`);
    expect(badge('in-23-hours')).toBe('expires soon');
    expect(badge('pre-1970')).toBe('expired');
    expect(text('pre-1970')).toMatch(new RegExp(`^expired ${day(-DAY_MS)} \\(\\d+ days ago\\)$`));
    expect(byTestId(page.root, 'expiry-expired').textContent).toBe('3 expired');
  });

  it('prints a year before 100 in full and counts its days from that year', () => {
    const ms = parseExpiresMs('0050-06-01T00:00:00Z')!;
    const now = new Date(2026, 9, 29, 12).getTime();
    expect(day(ms)).toMatch(/^0050-/);
    expect(calendarDaysUntil(ms, now)).toBeLessThan(-700_000);
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
