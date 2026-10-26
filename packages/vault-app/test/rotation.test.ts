// @vitest-environment happy-dom
/**
 * Credential rotation: the pure health and transition rules, then the whole
 * guided flow through the real controller and views against the in-memory
 * world. A rotation step is a signed revision of the item, the Vault step turns
 * done only from a verified head, and the provider revocation stays unconfirmed
 * until an operator says so.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openItem, type MembershipEvent } from '@ak-vault/protocol';
import { AppError } from '../src/app-error.js';
import {
  MS_PER_DAY, applyRotationChange, parseExpiresAt, parseRotation, rotationHealth, vaultStepDone, type RotationInput,
} from '../src/sync/rotation.js';
import { exposureTimes } from '../src/sync/vault-sync.js';
import { updateRotation } from '../src/sync/write-ops.js';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, type Page } from './helpers/dashboard-page.js';

const OLD = 'old-provider-key-91d0c2';
const NEW = 'new-provider-key-5be7a1';
const DAY = MS_PER_DAY;

function input(over: Partial<RotationInput> = {}): RotationInput {
  return { createdMs: null, rotatedMs: null, rotateTtlDays: null, rotation: null, exposedSinceMs: null, expiresAt: null, ...over };
}

describe('rotation health', () => {
  const now = 1_800_000_000_000;
  it('never invents a date: no ttl and no expiry is untracked, a ttl without any base date is untracked too', () => {
    expect(rotationHealth(input(), now)).toBe('untracked');
    expect(rotationHealth(input({ rotateTtlDays: 30 }), now)).toBe('untracked');
    expect(rotationHealth(input({ createdMs: now - DAY }), now)).toBe('untracked');
  });

  it('derives due, due soon and overdue from the last rotation, falling back to creation', () => {
    expect(rotationHealth(input({ createdMs: now - 10 * DAY, rotateTtlDays: 90 }), now)).toBe('ok');
    expect(rotationHealth(input({ createdMs: now - 80 * DAY, rotateTtlDays: 90 }), now)).toBe('due_soon');
    expect(rotationHealth(input({ createdMs: now - 91 * DAY, rotateTtlDays: 90 }), now)).toBe('overdue');
    // A later rotation moves the due date; creation no longer counts.
    expect(rotationHealth(input({ createdMs: now - 400 * DAY, rotatedMs: now - 5 * DAY, rotateTtlDays: 90 }), now)).toBe('ok');
  });

  it('uses expires_at only in its strict form', () => {
    expect(parseExpiresAt('2027-01-01T00:00:00Z')).toBe(Date.parse('2027-01-01T00:00:00Z'));
    for (const bad of ['2027-01-01', '2027-01-01T00:00:00+01:00', 'tomorrow', '2027-13-01T00:00:00Z', null]) expect(parseExpiresAt(bad)).toBeNull();
    expect(rotationHealth(input({ expiresAt: new Date(now - 1000).toISOString().replace(/\.\d+Z$/, 'Z') }), now)).toBe('expired');
    expect(rotationHealth(input({ expiresAt: new Date(now + 3 * DAY).toISOString().replace(/\.\d+Z$/, 'Z') }), now)).toBe('expiring_soon');
    expect(rotationHealth(input({ expiresAt: 'soon' }), now)).toBe('untracked');
  });

  it('keeps an exposed item at needs_rotate until the Vault holds a value newer than the rekey', () => {
    const exposed = now - DAY;
    expect(rotationHealth(input({ exposedSinceMs: exposed, rotatedMs: exposed - 1 }), now)).toBe('needs_rotate');
    expect(rotationHealth(input({ exposedSinceMs: exposed }), now)).toBe('needs_rotate');
    expect(rotationHealth(input({ exposedSinceMs: Number.MAX_SAFE_INTEGER, rotatedMs: now }), now)).toBe('needs_rotate');
    // The value changed, but nobody confirmed the provider revocation.
    expect(rotationHealth(input({ exposedSinceMs: exposed, rotatedMs: exposed + 1 }), now)).toBe('awaiting_revocation');
    const revoked = parseRotation({ state: 'revoked', started_ms: exposed, updated_ms: now - 5, revoked_ms: now - 5 });
    expect(rotationHealth(input({ exposedSinceMs: exposed, rotatedMs: exposed + 1, rotation: revoked }), now)).toBe('untracked');
    // A confirmation older than the newest value does not cover that value.
    const stale = parseRotation({ state: 'revoked', started_ms: 1, updated_ms: 2, revoked_ms: 2 });
    expect(rotationHealth(input({ exposedSinceMs: exposed, rotatedMs: exposed + 1, rotation: stale }), now)).toBe('awaiting_revocation');
  });

  it('shows an open rotation as rotating until the verified head carries a newer value', () => {
    const started = now - DAY;
    const open = (state: string) => parseRotation({ state, started_ms: started, updated_ms: started });
    expect(rotationHealth(input({ rotation: open('in_progress'), rotatedMs: started - 1 }), now)).toBe('rotating');
    expect(rotationHealth(input({ rotation: open('paused') }), now)).toBe('paused');
    expect(rotationHealth(input({ rotation: open('failed') }), now)).toBe('failed');
    expect(vaultStepDone(input({ rotation: open('in_progress'), rotatedMs: started }))).toBe(true);
    expect(rotationHealth(input({ rotation: open('in_progress'), rotatedMs: started }), now)).toBe('awaiting_revocation');
  });

  it('treats malformed rotation metadata as none, never as a state', () => {
    for (const bad of [null, 1, 'x', [], {}, { state: 'done', started_ms: 1, updated_ms: 1 }, { state: 'in_progress', started_ms: -1, updated_ms: 1 }, { state: 'revoked', started_ms: 1, updated_ms: 1 }, { state: 'paused', started_ms: 1, updated_ms: 1, revoked_ms: 3 }]) {
      expect(parseRotation(bad)).toBeNull();
    }
  });
});

describe('rotation steps', () => {
  const now = 1_800_000_000_000;
  const open = (state: 'in_progress' | 'paused' | 'failed') => parseRotation({ state, started_ms: now - 1000, updated_ms: now - 1000 });
  const refused = (fn: () => unknown) => expect(fn).toThrow(AppError);

  it('walks start, pause, resume, fail and resume', () => {
    let rot = applyRotationChange(input(), { kind: 'start' }, now).rotation!;
    expect(rot).toMatchObject({ state: 'in_progress', startedMs: now });
    rot = applyRotationChange(input({ rotation: rot }), { kind: 'pause' }, now + 1).rotation!;
    expect(rot.state).toBe('paused');
    rot = applyRotationChange(input({ rotation: rot }), { kind: 'resume' }, now + 2).rotation!;
    rot = applyRotationChange(input({ rotation: rot }), { kind: 'fail' }, now + 3).rotation!;
    expect(rot).toMatchObject({ state: 'failed', startedMs: now });
    expect(applyRotationChange(input({ rotation: rot }), { kind: 'resume' }, now + 4).rotation!.state).toBe('in_progress');
  });

  it('refuses a step that does not fit the state it was taken from', () => {
    refused(() => applyRotationChange(input({ rotation: open('in_progress') }), { kind: 'start' }, now));
    refused(() => applyRotationChange(input(), { kind: 'pause' }, now));
    refused(() => applyRotationChange(input({ rotation: open('paused') }), { kind: 'pause' }, now));
    refused(() => applyRotationChange(input({ rotation: open('in_progress') }), { kind: 'resume' }, now));
    refused(() => applyRotationChange(input({ rotation: open('failed') }), { kind: 'fail' }, now));
    refused(() => applyRotationChange(input(), { kind: 'cancel' }, now));
  });

  it('cancels only before the Vault holds the new value', () => {
    expect(applyRotationChange(input({ rotation: open('in_progress') }), { kind: 'cancel' }, now).rotation).toBeNull();
    refused(() => applyRotationChange(input({ rotation: open('in_progress'), rotatedMs: now - 500 }), { kind: 'cancel' }, now));
  });

  it('confirms the provider revocation only after the Vault step, once, and never before the newest value', () => {
    refused(() => applyRotationChange(input({ rotation: open('in_progress'), rotatedMs: now - 2000 }), { kind: 'confirm_revoked' }, now));
    refused(() => applyRotationChange(input(), { kind: 'confirm_revoked' }, now));
    const vaultDone = input({ rotation: open('in_progress'), rotatedMs: now - 500 });
    const out = applyRotationChange(vaultDone, { kind: 'confirm_revoked' }, now);
    expect(out.rotation).toMatchObject({ state: 'revoked', revokedMs: now });
    refused(() => applyRotationChange({ ...vaultDone, rotation: out.rotation }, { kind: 'confirm_revoked' }, now));
    // A device whose clock runs behind cannot record a confirmation older than the value it confirms.
    expect(applyRotationChange(vaultDone, { kind: 'confirm_revoked' }, now - 10_000).rotation!.revokedMs).toBe(now - 500);
    // An exposed item rotated outside the dashboard can be confirmed without a started rotation.
    expect(applyRotationChange(input({ exposedSinceMs: now - 5000, rotatedMs: now - 1000 }), { kind: 'confirm_revoked' }, now).rotation!.state).toBe('revoked');
  });

  it('bounds the schedule', () => {
    expect(applyRotationChange(input(), { kind: 'set_ttl', days: 30 }, now).rotateTtlDays).toBe(30);
    expect(applyRotationChange(input({ rotateTtlDays: 30 }), { kind: 'set_ttl', days: null }, now).rotateTtlDays).toBeNull();
    for (const days of [0, -1, 1.5, NaN, 3651, Infinity]) refused(() => applyRotationChange(input(), { kind: 'set_ttl', days }, now));
  });
});

describe('rotation write guards', () => {
  const client = { put: () => Promise.reject(new Error('must not send')) } as never;
  const stub = (state: object, self: object) => ({ state, self, items: [], itemStates: new Map(), vaultKeys: new Map() }) as never;
  const call = (snapshot: never) => updateRotation({ client, snapshot, signer: {} as never, itemId: 'x', change: { kind: 'start' } });

  it('refuses while a rekey is required, and for a device that cannot write', async () => {
    await expect(call(stub({ rekey_required: true, key_epoch: 1 }, { kind: 'human', role: 'owner' }))).rejects.toMatchObject({ code: 'rekey_required' });
    await expect(call(stub({ rekey_required: false, key_epoch: 1 }, { kind: 'human', role: 'reader' }))).rejects.toMatchObject({ code: 'device_mismatch' });
    await expect(call(stub({ rekey_required: false, key_epoch: 1 }, { kind: 'machine', role: 'owner' }))).rejects.toMatchObject({ code: 'device_mismatch' });
  });
});

describe('rekey exposure times', () => {
  it('takes the newest rekey that listed an item and never clears an item without a usable time', () => {
    const ev = (type: string, ts: number, ids: string[]) => ({ type, ts, body: { needs_rotate: ids } }) as unknown as MembershipEvent;
    const out = exposureTimes([ev('rekey', 10, ['a', 'b']), ev('device_add', 99, ['a']), ev('rekey', 30, ['a'])], ['a', 'b', 'c']);
    expect(out.get('a')).toBe(30);
    expect(out.get('b')).toBe(10);
    expect(out.get('c')).toBe(Number.MAX_SAFE_INTEGER);
    expect(exposureTimes([ev('rekey', 0, ['a'])], ['a']).get('a')).toBe(Number.MAX_SAFE_INTEGER);
  });
});

// The sentinel check of the dashboard suite: neither provider value may reach the console.
let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toMatch(new RegExp(`${OLD}|${NEW}`));
    s.mockRestore();
  }
});

function row(page: Page): HTMLElement {
  return allByTestId(page.root, 'item')[0]!;
}

function text(root: ParentNode, id: string): string {
  return byTestId(root, id).textContent ?? '';
}

/** The handlers start their write synchronously, so the screen is busy until the write and its re-pull finish. */
async function settled(page: Page): Promise<void> {
  await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', busy: false }), { timeout: 3000 });
}

async function click(page: Page, root: ParentNode, id: string): Promise<void> {
  byTestId(root, id).click();
  await settled(page);
}

async function submitValue(page: Page, value: string): Promise<void> {
  (byTestId(page.root, 'rotate-value') as HTMLInputElement).value = value;
  byTestId(page.root, 'rotate-value').closest('form')!.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
  await settled(page);
}

function headMeta(world: FakeWorld, itemId: string): { value: string; meta: Record<string, unknown> } {
  const entry = [...world.log].reverse().find((e) => e.record.item_id === itemId && e.conflict_id === null)!;
  return openItem({ ...entry.record, vk: world.vks.get(entry.record.key_epoch)!, env: entry.record.env }) as unknown as { value: string; meta: Record<string, unknown> };
}

describe('guided rotation in the dashboard', () => {
  it('explains rekey versus provider rotation, and an exposed item starts at needs rotation', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('stripe-live', OLD, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 400 * DAY });
    world.rekey([id], Date.now() - 1000);
    const { page } = await new Browser(world).enroll();
    expect(text(page.root, 'rekey-explainer')).toContain('key epoch 2');
    expect(text(page.root, 'rekey-explainer')).toContain('changes no provider credential');
    expect(text(page.root, 'rotation-counts')).toContain('1 needs rotation');
    expect(text(row(page), 'rotation-health')).toBe('Needs rotation');
  });

  it('runs start, new value, revocation as three separate states and writes only signed revisions', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('stripe-live', OLD, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 400 * DAY });
    world.rekey([id], Date.now() - 1000);
    const { page } = await new Browser(world).enroll();
    await click(page, row(page), 'rotate-open');
    expect(text(page.root, 'rotation-panel')).toContain('cannot be read back');
    expect((byTestId(page.root, 'rotate-submit') as HTMLButtonElement).disabled).toBe(true);
    expect((byTestId(page.root, 'rotation-confirm-revoked') as HTMLButtonElement).disabled).toBe(true);

    await click(page, page.root, 'rotation-start');
    expect(text(row(page), 'rotation-status')).toBe('Status: Needs rotation');
    expect(headMeta(world, id).meta['rotation']).toMatchObject({ state: 'in_progress' });
    expect(headMeta(world, id).value).toBe(OLD);
    expect(headMeta(world, id).meta).not.toHaveProperty('rotated_ms');

    await submitValue(page, NEW);
    expect(headMeta(world, id).value).toBe(NEW);
    expect(text(row(page), 'rotation-health')).toBe('Vault updated, old key not confirmed revoked');
    expect(text(page.root, 'vault-step')).toContain('Confirmed');
    expect((byTestId(page.root, 'rotate-value') as HTMLInputElement).value).toBe('');
    expect(text(page.root, 'rotation-counts')).toContain('1 vault updated, old key not confirmed revoked');

    await click(page, page.root, 'rotation-confirm-revoked');
    expect(headMeta(world, id).meta['rotation']).toMatchObject({ state: 'revoked' });
    expect(text(row(page), 'rotation-health')).not.toMatch(/Needs rotation|not confirmed/);
    expect((byTestId(page.root, 'rotation-confirm-revoked') as HTMLButtonElement).disabled).toBe(true);
    expect(page.root.innerHTML).not.toMatch(new RegExp(`${OLD}|${NEW}`));
    for (const e of world.exchanges) expect(e.requestBody + e.responseBody).not.toMatch(new RegExp(`${OLD}|${NEW}`));
  });

  it('pauses, fails and cancels before the Vault step, and keeps the value and its rotated date', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('github-token', OLD, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 5 * DAY, rotate_ttl_days: 90 });
    const { page } = await new Browser(world).enroll();
    expect(text(row(page), 'rotation-health')).toBe('On schedule');
    await click(page, row(page), 'rotate-open');
    await click(page, page.root, 'rotation-start');
    await click(page, page.root, 'rotation-pause');
    expect(text(row(page), 'rotation-health')).toBe('Rotation paused');
    await click(page, page.root, 'rotation-resume');
    await click(page, page.root, 'rotation-fail');
    expect(text(row(page), 'rotation-health')).toBe('Rotation failed');
    await click(page, page.root, 'rotation-resume');
    await click(page, page.root, 'rotation-cancel');
    expect(text(row(page), 'rotation-health')).toBe('On schedule');
    const head = headMeta(world, id);
    expect(head.value).toBe(OLD);
    expect(head.meta).not.toHaveProperty('rotation');
    expect(head.meta).not.toHaveProperty('rotated_ms');
    expect(head.meta['rotate_ttl_days']).toBe(90);
  });

  it('edits the schedule as a signed revision and refuses an out-of-range value', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('npm-token', OLD, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 100 * DAY });
    const { page } = await new Browser(world).enroll();
    expect(text(row(page), 'rotation-health')).toBe('No schedule');
    await click(page, row(page), 'rotate-open');
    const set = async (v: string) => {
      (byTestId(page.root, 'ttl-input') as HTMLInputElement).value = v;
      byTestId(page.root, 'ttl-input').closest('form')!.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
      await settled(page);
    };
    await set('90');
    expect(headMeta(world, id).meta['rotate_ttl_days']).toBe(90);
    expect(text(row(page), 'rotation-health')).toBe('Overdue');
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    await set('0');
    await set('abc');
    await set('99999');
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'rotation_invalid' } });
    await set('');
    expect(headMeta(world, id).meta).not.toHaveProperty('rotate_ttl_days');
  });

  it('turns a concurrent edit into a conflict instead of overwriting it, and a stale step into a refusal', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('db-password', OLD, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 5 * DAY });
    const b = new Browser(world);
    const { page } = await b.enroll();
    // Another device writes between this page's pull and its step.
    world.ownerSet('db-password', 'someone-elses-value', { schema: 'agentkit.secret/v1', created_ms: Date.now() - 5 * DAY });
    expect(await page.controller.rotate(id, { kind: 'start' })).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'conflict' } });
    expect(headMeta(world, id).value).toBe('someone-elses-value');
    // Refreshed, the step lands on the new head and keeps the other device's value.
    expect(await page.controller.rotate(id, { kind: 'start' })).toBe(true);
    expect(headMeta(world, id).value).toBe('someone-elses-value');
    // The same step again from the now-open rotation is refused, not written.
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    expect(await page.controller.rotate(id, { kind: 'start' })).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_invalid' } });
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });

  it('refuses a step for an item that does not exist', async () => {
    const world = new FakeWorld();
    world.ownerSet('k', OLD);
    const { page } = await new Browser(world).enroll();
    expect(await page.controller.rotate('00000000000000000000000000000000', { kind: 'start' })).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'not_found' } });
  });

  it('ends on the removed view when the device was removed before the step reached the server', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('k', OLD);
    const b = new Browser(world);
    const { page } = await b.enroll();
    world.removeDevice((page.controller.current() as { deviceId: string }).deviceId);
    expect(await page.controller.rotate(id, { kind: 'start' })).toBe(false);
    expect(page.controller.current().kind).toBe('removed');
    expect(b.devices.entries.size).toBe(0);
    expect(headMeta(world, id).meta).not.toHaveProperty('rotation');
  });

  it('keeps an offline step recoverable: a network failure writes nothing and the screen stays usable', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('k', OLD);
    const b = new Browser(world);
    const { page } = await b.enroll();
    const real = world.fetch.bind(world);
    (world as unknown as { fetch: typeof fetch }).fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'PUT') throw new TypeError('offline');
      return real(input, init);
    }) as typeof fetch;
    expect(await page.controller.rotate(id, { kind: 'start' })).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error' } });
    expect(headMeta(world, id).meta).not.toHaveProperty('rotation');
  });
});
