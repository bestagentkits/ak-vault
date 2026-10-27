// @vitest-environment happy-dom
/**
 * Credential rotation in the dashboard: health states, the guided workflow with
 * its separate vault and provider steps, and the refusals around it. Runs the
 * real controller, views and protocol library against the in-memory world.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openItem, verifyAuditChain } from '@ak-vault/protocol';
import { DAY_MS, parseRotationWorkflow, rotationInfo, stillNeedsRotate, type RotationInput } from '../src/sync/rotation.js';
import { dueText } from '../src/ui/views.js';
import { updateRotation } from '../src/sync/write-ops.js';
import { appendRotationAudit } from '../src/sync/audit.js';
import type { AkvClient } from '../src/sync/akv-client.js';
import type { ItemView, VaultSnapshot } from '../src/sync/vault-sync.js';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, type Page } from './helpers/dashboard-page.js';

const SENTINEL = 'rotation-sentinel-3c91e07a';
const NEW_SENTINEL = 'rotation-sentinel-new-58d2b4f6';

let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toMatch(/rotation-sentinel/);
    s.mockRestore();
  }
});

const NOW = 1_800_000_000_000;
const base: RotationInput = { createdMs: NOW - 10 * DAY_MS, rotatedMs: null, rotateTtlDays: null, flaggedMs: null, flaggedEpoch: null, keyEpoch: 1, workflow: null };

describe('rotation due text', () => {
  const text = (offsetMs: number) => {
    const info = rotationInfo({ ...base, rotatedMs: NOW + offsetMs - 30 * DAY_MS, rotateTtlDays: 30 }, NOW);
    return dueText(info).replace(/^due \S+ /, '');
  };
  it('keeps the health state independent of the day rounding', () => {
    const health = (offsetMs: number) => rotationInfo({ ...base, rotatedMs: NOW + offsetMs - 30 * DAY_MS, rotateTtlDays: 30 }, NOW).health;
    expect(health(-1000)).toBe('overdue');
    expect(health(0)).toBe('overdue');
    expect(health(23 * 3_600_000)).toBe('due_soon');
  });
  it('rounds whole days toward zero and says today within a day either side', () => {
    expect(text(-1000)).toBe('(today)');
    expect(text(0)).toBe('(today)');
    expect(text(23 * 3_600_000)).toBe('(today)');
    expect(text(-DAY_MS)).toBe('(1 day ago)');
    expect(text(-2 * DAY_MS - 5)).toBe('(2 days ago)');
    expect(text(DAY_MS)).toBe('(in 1 day)');
    expect(text(2 * DAY_MS + 5)).toBe('(in 2 days)');
  });
});

describe('rotation health', () => {
  it('is unknown without an interval or without any date, and never invents a due date', () => {
    expect(rotationInfo(base, NOW)).toMatchObject({ health: 'unknown', dueMs: null, daysUntilDue: null });
    expect(rotationInfo({ ...base, rotateTtlDays: 30, createdMs: null }, NOW)).toMatchObject({ health: 'unknown', dueMs: null });
  });

  it('counts from the rotated date when there is one, else the created date', () => {
    expect(rotationInfo({ ...base, rotateTtlDays: 30 }, NOW)).toMatchObject({ health: 'ok', daysUntilDue: 20 });
    expect(rotationInfo({ ...base, rotateTtlDays: 30, rotatedMs: NOW - 2 * DAY_MS }, NOW)).toMatchObject({ health: 'ok', daysUntilDue: 28 });
    expect(rotationInfo({ ...base, rotateTtlDays: 12 }, NOW)).toMatchObject({ health: 'due_soon', daysUntilDue: 2 });
    expect(rotationInfo({ ...base, rotateTtlDays: 5 }, NOW)).toMatchObject({ health: 'overdue', daysUntilDue: -5 });
    expect(rotationInfo({ ...base, rotateTtlDays: 10 }, NOW).health).toBe('overdue');
  });

  it('keeps needs-rotate after any rewrite until a member confirms revocation of the old credential', () => {
    const flagged = { ...base, rotateTtlDays: 365, flaggedMs: NOW - DAY_MS, flaggedEpoch: 2, keyEpoch: 2 };
    const wf = { state: 'active' as const, startedMs: NOW - DAY_MS / 2, revokedMs: null };
    expect(rotationInfo(flagged, NOW).health).toBe('needs_rotate');
    // a rewrite (the dashboard's, or a CLI set that bumped rotated_ms for the same value) does not clear it
    expect(rotationInfo({ ...flagged, rotatedMs: NOW }, NOW).health).toBe('needs_rotate');
    expect(rotationInfo({ ...flagged, rotatedMs: NOW, workflow: wf }, NOW).health).toBe('needs_rotate');
    // a confirmation recorded before the latest write confirmed the previous credential
    expect(stillNeedsRotate({ ...flagged, rotatedMs: NOW, workflow: { ...wf, revokedMs: NOW - 1000 } })).toBe(true);
    // a rewrite from before the flag never clears it
    expect(stillNeedsRotate({ ...flagged, rotatedMs: NOW - 2 * DAY_MS, workflow: { ...wf, revokedMs: NOW } })).toBe(true);
    // a rewrite under the old epoch never clears it
    expect(stillNeedsRotate({ ...flagged, keyEpoch: 1, rotatedMs: NOW, workflow: { ...wf, revokedMs: NOW } })).toBe(true);
    expect(rotationInfo({ ...flagged, rotatedMs: NOW, workflow: { ...wf, revokedMs: NOW } }, NOW).health).toBe('ok');
  });

  it('shows awaiting-revoke after the vault write, never on schedule, until revocation is confirmed', () => {
    const wf = { state: 'active' as const, startedMs: NOW - DAY_MS, revokedMs: null };
    const written = { ...base, rotateTtlDays: 365, rotatedMs: NOW, workflow: wf };
    expect(rotationInfo(written, NOW).health).toBe('awaiting_revoke');
    expect(rotationInfo({ ...written, workflow: { ...wf, state: 'paused' } }, NOW).health).toBe('awaiting_revoke');
    expect(rotationInfo({ ...written, workflow: { ...wf, state: 'cancelled' } }, NOW).health).toBe('ok');
    expect(rotationInfo({ ...written, workflow: { ...wf, revokedMs: NOW } }, NOW).health).toBe('ok');
  });

  it('reads only a well-formed workflow', () => {
    expect(parseRotationWorkflow({ rotation: { state: 'active', started_ms: 5 } })).toEqual({ state: 'active', startedMs: 5, revokedMs: null });
    expect(parseRotationWorkflow({ rotation: { state: 'paused', started_ms: 5, revoked_ms: 9 } })).toEqual({ state: 'paused', startedMs: 5, revokedMs: 9 });
    for (const bad of [
      undefined, 'active', [], null,
      { state: 'done', started_ms: 5 },
      { state: 'active' },
      { state: 'active', started_ms: -1 },
      { state: 'active', started_ms: 1.5 },
      { state: 'active', started_ms: 5, revoked_ms: 'x' },
      { state: 'active', started_ms: 5, extra: true },
    ]) {
      expect(parseRotationWorkflow({ rotation: bad as never })).toBeNull();
    }
  });

  it('confirms revocation only after a vault value written after the start', () => {
    const wf = { state: 'active' as const, startedMs: NOW - DAY_MS, revokedMs: null };
    expect(rotationInfo({ ...base, workflow: wf, rotatedMs: NOW - 5 * DAY_MS }, NOW)).toMatchObject({ vaultUpdated: false, providerRevoked: false });
    expect(rotationInfo({ ...base, workflow: wf, rotatedMs: NOW }, NOW)).toMatchObject({ vaultUpdated: true, providerRevoked: false });
    expect(rotationInfo({ ...base, workflow: { ...wf, revokedMs: NOW }, rotatedMs: NOW }, NOW)).toMatchObject({ vaultUpdated: true, providerRevoked: true });
    // a revocation recorded before the latest value write confirms the previous credential, not this one
    expect(rotationInfo({ ...base, workflow: { ...wf, revokedMs: NOW - 1000 }, rotatedMs: NOW }, NOW).providerRevoked).toBe(false);
  });
});

async function open(world: FakeWorld, seed: (w: FakeWorld) => string): Promise<{ page: Page; itemId: string; browser: Browser }> {
  const itemId = seed(world);
  const browser = new Browser(world);
  const { page } = await browser.enroll();
  return { page, itemId, browser };
}

function item(page: Page, itemId: string): ItemView {
  const s = page.controller.current();
  if (s.kind !== 'vault') throw new Error(`not a vault screen: ${s.kind}`);
  const found = s.items.find((i) => i.itemId === itemId);
  if (!found) throw new Error('missing item');
  return found;
}

function headPayload(world: FakeWorld) {
  const entry = world.log.at(-1)!.record;
  return openItem({ ...entry, vk: world.vks.get(entry.key_epoch)!, env: entry.env }) as { name: string; value: string; meta: Record<string, unknown> };
}

function seedAged(w: FakeWorld, meta: Record<string, unknown> = {}): string {
  return w.ownerSet('stripe-key', SENTINEL, { schema: 'agentkit.secret/v1', created_ms: Date.now() - 100 * DAY_MS, rotate_ttl_days: 30, ...meta } as never);
}

describe('dashboard rotation health', () => {
  it('shows overdue, due soon, on schedule and unknown without inventing dates', async () => {
    const world = new FakeWorld();
    const d = Date.now();
    world.ownerSet('overdue', 'a', { schema: 'agentkit.secret/v1', created_ms: d - 100 * DAY_MS, rotate_ttl_days: 30 });
    world.ownerSet('soon', 'a', { schema: 'agentkit.secret/v1', created_ms: d - 25 * DAY_MS, rotate_ttl_days: 30 });
    world.ownerSet('fine', 'a', { schema: 'agentkit.secret/v1', created_ms: d - 1 * DAY_MS, rotate_ttl_days: 30 });
    world.ownerSet('no-ttl', 'a', { schema: 'agentkit.secret/v1', created_ms: d - 1 * DAY_MS });
    world.ownerSet('no-dates', 'a', { schema: 'agentkit.secret/v1', rotate_ttl_days: 30 });
    const { page } = await new Browser(world).enroll();
    const health = Object.fromEntries(allByTestId(page.root, 'item').map((li) => [byTestId(li, 'item-name').textContent, byTestId(li, 'rotation-health').textContent]));
    expect(health).toEqual({
      overdue: 'rotation overdue', soon: 'rotation due soon', fine: 'rotation on schedule', 'no-ttl': 'rotation unknown', 'no-dates': 'rotation unknown',
    });
    expect(byTestId(page.root, 'health-overdue').textContent).toBe('1 rotation overdue');
    expect(byTestId(page.root, 'health-unknown').textContent).toBe('2 rotation unknown');
    // the due text appears only where a due date exists
    expect(allByTestId(page.root, 'rotation-due')).toHaveLength(3);
  });

  it('separates a vault rekey from provider credential rotation in the text', async () => {
    const world = new FakeWorld();
    const { page } = await new Browser(world).enroll();
    const text = byTestId(page.root, 'rotation-summary').textContent!;
    expect(text).toMatch(/rekey/i);
    expect(text).toMatch(/Provider credential rotation replaces the secret at its provider/);
  });

  it('flags the items a rekey listed and clears the flag only after a new value under the new epoch', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w, { created_ms: Date.now() - DAY_MS, rotate_ttl_days: 365 }));
    expect(item(page, itemId).flaggedMs).toBeNull();
    world.ownerRekey([itemId]);
    await page.controller.refresh();
    expect(item(page, itemId)).toMatchObject({ flaggedEpoch: 2 });
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('needs rotation');
    expect(byTestId(page.root, 'health-needs_rotate').textContent).toBe('1 needs rotation');
    // an edit that keeps the value does not clear it
    await page.controller.setRotateTtl(itemId, 300);
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('needs rotation');
    await page.controller.startRotation(itemId);
    expect(await page.controller.rotate(itemId, NEW_SENTINEL)).toBe(true);
    // the vault holds the new value, but the old credential is not confirmed revoked
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('needs rotation');
    expect(await page.controller.confirmRevoked(itemId)).toBe(true);
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('rotation on schedule');
  });

  it('keeps the flag when the CLI re-saves the same value after the rekey', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w, { created_ms: Date.now() - DAY_MS, rotate_ttl_days: 365 }));
    world.ownerRekey([itemId]);
    world.ownerSet('stripe-key', SENTINEL, { schema: 'agentkit.secret/v1', created_ms: Date.now() - DAY_MS, rotate_ttl_days: 365, rotated_ms: Date.now() + 5 });
    await page.controller.refresh();
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('needs rotation');
  });
});

describe('guided rotation', () => {
  it('tracks the vault write and the provider revocation as separate steps and never shows a value', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    byTestId(page.root, 'rotate').click();
    expect(byTestId(page.root, 'rotation-state').textContent).toBe('No rotation in progress.');
    expect((byTestId(page.root, 'rotate-save') as HTMLButtonElement).disabled).toBe(true);

    byTestId(page.root, 'rotation-start').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_started' } }));
    expect(item(page, itemId).rotation).toMatchObject({ state: 'active', revokedMs: null });
    // the value and its rotated date are untouched by starting
    expect(headPayload(world)).toMatchObject({ value: SENTINEL });
    expect(headPayload(world).meta['rotated_ms']).toBeUndefined();
    expect(byTestId(page.root, 'step-vault').className).not.toContain('step-done');
    expect((byTestId(page.root, 'rotation-revoked') as HTMLButtonElement).disabled).toBe(true);

    // revocation cannot be recorded before the vault holds the new value
    expect(await page.controller.confirmRevoked(itemId)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'rotation_not_ready' } });

    // the same value is not a rotation
    expect(await page.controller.rotate(itemId, SENTINEL)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_value_unchanged' } });

    const input = byTestId(page.root, 'rotate-value') as HTMLInputElement;
    input.value = NEW_SENTINEL;
    (input.form as HTMLFormElement).dispatchEvent(new Event('submit', { cancelable: true }));
    expect(input.value).toBe('');
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_saved' } }));
    expect(headPayload(world).value).toBe(NEW_SENTINEL);
    expect(typeof headPayload(world).meta['rotated_ms']).toBe('number');
    expect(byTestId(page.root, 'step-vault').className).toContain('step-done');
    expect(byTestId(page.root, 'step-revoked').className).not.toContain('step-done');
    expect(byTestId(page.root, 'rotation-flow').textContent).toContain('old key not confirmed revoked');
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('old key not confirmed revoked');
    expect(page.root.textContent).not.toMatch(/\brotated \d{4}-/);

    byTestId(page.root, 'rotation-revoked').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_revoked' } }));
    expect(byTestId(page.root, 'step-revoked').className).toContain('step-done');
    expect(byTestId(page.root, 'step-revoked').textContent).toContain('cannot verify this with the provider');
    expect(byTestId(page.root, 'rotation-flow').textContent).toContain('old key revoked (member-confirmed)');
    expect(byTestId(page.root, 'rotation-state').textContent).toMatch(/^Rotation complete/);
    expect(allByTestId(page.root, 'rotation-pause')).toHaveLength(0);
    expect(byTestId(page.root, 'rotation-start').textContent).toBe('Start again');
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('rotation on schedule');
    // the value is unchanged by the metadata-only revisions, and the other device's CLI keys survive
    expect(headPayload(world)).toMatchObject({ value: NEW_SENTINEL });
    expect(headPayload(world).meta).toMatchObject({ schema: 'agentkit.secret/v1', rotate_ttl_days: 30 });

    // a later value write clears the confirmation: it confirmed the previous credential
    expect(await page.controller.rotate(itemId, `${NEW_SENTINEL}-2`)).toBe(true);
    expect(item(page, itemId).rotation!.revokedMs).toBeNull();
    expect(byTestId(page.root, 'step-revoked').className).not.toContain('step-done');

    expect(page.root.innerHTML).not.toContain('rotation-sentinel');
    for (const e of world.exchanges) {
      expect(e.url).not.toMatch(/rotation-sentinel/);
      expect(e.requestBody).not.toMatch(/rotation-sentinel/);
      expect(e.responseBody).not.toMatch(/rotation-sentinel/);
    }
  });

  it('keeps the value field out of password managers and masked', async () => {
    const world = new FakeWorld();
    const { page } = await open(world, (w) => seedAged(w));
    byTestId(page.root, 'rotate').click();
    const el = byTestId(page.root, 'rotate-value');
    expect(el.getAttribute('type')).toBe('text');
    expect(el.classList.contains('masked')).toBe(true);
    expect(el.getAttribute('autocomplete')).toBe('off');
    expect(el.hasAttribute('data-1p-ignore')).toBe(true);
    expect(page.root.querySelector('input[type="password"]')).toBeNull();
  });

  it('pauses, resumes, fails and cancels without touching the value', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    byTestId(page.root, 'rotate').click();
    await page.controller.startRotation(itemId);
    await page.controller.setRotationState(itemId, 'paused');
    expect(item(page, itemId).rotation!.state).toBe('paused');
    expect((byTestId(page.root, 'rotate-save') as HTMLButtonElement).disabled).toBe(true);
    await page.controller.setRotationState(itemId, 'active');
    await page.controller.setRotationState(itemId, 'failed');
    expect(item(page, itemId).rotation!.state).toBe('failed');
    await page.controller.startRotation(itemId);
    expect(item(page, itemId).rotation).toMatchObject({ state: 'active', revokedMs: null });
    await page.controller.setRotationState(itemId, 'cancelled');
    expect(item(page, itemId).rotation!.state).toBe('cancelled');
    expect(await page.controller.confirmRevoked(itemId)).toBe(false);
    expect(headPayload(world).value).toBe(SENTINEL);
  });

  it('refuses confirmation while paused or failed, an empty value, and a resume of a failed rotation', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.startRotation(itemId);
    expect(await page.controller.rotate(itemId, '')).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'value_too_large' } });
    expect(await page.controller.rotate(itemId, NEW_SENTINEL)).toBe(true);
    await page.controller.setRotationState(itemId, 'paused');
    expect(await page.controller.confirmRevoked(itemId)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'rotation_not_ready' } });
    await page.controller.setRotationState(itemId, 'failed');
    expect(await page.controller.confirmRevoked(itemId)).toBe(false);
    const writes = world.log.length;
    expect(await page.controller.setRotationState(itemId, 'active')).toBe(false);
    expect(world.log.length).toBe(writes);
    expect(item(page, itemId).rotation!.state).toBe('failed');
  });

  it('reports a conflict on the value save and on the revocation confirmation', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.startRotation(itemId);
    world.ownerSet('stripe-key', 'changed-elsewhere', { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000 });
    expect(await page.controller.rotate(itemId, NEW_SENTINEL)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'conflict' } });
    const stale = page.controller as unknown as { snapshot: VaultSnapshot };
    expect(stale.snapshot.heads.get(itemId)).toBeTruthy();
  });

  it('records a revocation no earlier than a value written by a device whose clock runs ahead', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.startRotation(itemId);
    const ahead = Date.now() + 10 * 60_000;
    const head = headPayload(world);
    world.ownerSet('stripe-key', 'cli-new-value', { ...head.meta, rotated_ms: ahead } as never);
    await page.controller.refresh();
    expect(await page.controller.confirmRevoked(itemId)).toBe(true);
    expect(item(page, itemId).rotation!.revokedMs).toBe(ahead);
    expect(byTestId(page.root, 'rotation-flow').textContent).toContain('old key revoked');
  });

  it('sets and clears the interval and refuses an invalid one', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    expect(await page.controller.setRotateTtl(itemId, 90)).toBe(true);
    expect(item(page, itemId).rotateTtlDays).toBe(90);
    expect(headPayload(world).meta['rotate_ttl_days']).toBe(90);
    const writes = world.log.length;
    for (const bad of [0, -1, 1.5, 40000, Number.NaN]) {
      expect(await page.controller.setRotateTtl(itemId, bad)).toBe(false);
      expect(page.controller.current()).toMatchObject({ notice: { code: 'invalid_rotation' } });
    }
    expect(world.log.length).toBe(writes);
    expect(await page.controller.setRotateTtl(itemId, null)).toBe(true);
    expect(item(page, itemId).rotateTtlDays).toBeNull();
    expect(byTestId(page.root, 'rotation-health').textContent).toBe('rotation unknown');
  });

  it('reports a concurrent edit as a conflict and keeps the other revision', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    world.ownerSet('stripe-key', 'changed-elsewhere', { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000 });
    expect(await page.controller.startRotation(itemId)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'conflict' } });
    expect(item(page, itemId).openConflicts).toBe(1);
  });

  it('derives the vault step from the pulled head, so a lost response still shows the committed write', async () => {
    const world = new FakeWorld();
    const { page, itemId, browser } = await open(world, (w) => seedAged(w));
    byTestId(page.root, 'rotate').click();
    await page.controller.startRotation(itemId);
    // the Worker applies the write but the response never reaches the page
    let armed = true;
    browser.afterFetch = async (url) => {
      if (armed && url.includes('/items/')) {
        armed = false;
        throw new TypeError('network down');
      }
    };
    expect(await page.controller.rotate(itemId, NEW_SENTINEL)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'network' } });
    expect(item(page, itemId).rotation!.revokedMs).toBeNull();
    await page.controller.refresh();
    expect(rotationInfo({ ...item(page, itemId), workflow: item(page, itemId).rotation } as never, Date.now()).vaultUpdated).toBe(true);
    expect(byTestId(page.root, 'step-vault').className).toContain('step-done');
    expect(byTestId(page.root, 'step-revoked').className).not.toContain('step-done');
  });

  it('is refused for a vault waiting on a rekey or a device that cannot write', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    const s = page.controller.current();
    if (s.kind !== 'vault') throw new Error('expected vault');
    // The controller builds snapshots from verified data; here the write functions get hand-made ones.
    const real = (page.controller as unknown as { snapshot: VaultSnapshot }).snapshot;
    const client = (page.controller as unknown as { client: never }).client;
    const signer = (page.controller as unknown as { signer: never }).signer;
    const args = { client, signer, itemId, patch: { rotateTtlDays: 7 } };
    await expect(updateRotation({ ...args, snapshot: { ...real, state: { ...real.state, rekey_required: true } } })).rejects.toMatchObject({ code: 'rekey_required' });
    await expect(updateRotation({ ...args, snapshot: { ...real, self: { ...real.self, role: 'reader' } } })).rejects.toMatchObject({ code: 'device_mismatch' });
    await expect(updateRotation({ ...args, snapshot: { ...real, self: { ...real.self, kind: 'machine' } } })).rejects.toMatchObject({ code: 'device_mismatch' });
    await expect(updateRotation({ ...args, itemId: 'no-such-item', snapshot: real })).rejects.toMatchObject({ code: 'not_found' });
    expect(s.canWrite).toBe(true);
  });

  it('does not carry a workflow forward as authority: a malformed one reads as none', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w, { rotation: { state: 'complete', started_ms: 1 } }));
    expect(item(page, itemId).rotation).toBeNull();
    byTestId(page.root, 'rotate').click();
    expect(byTestId(page.root, 'rotation-state').textContent).toBe('No rotation in progress.');
  });

  it('gives the other devices a rotation workflow they carry forward and the CLI keys they own', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.startRotation(itemId);
    const meta = headPayload(world).meta;
    expect(meta['rotation']).toMatchObject({ state: 'active' });
    expect(meta['schema']).toBe('agentkit.secret/v1');
    expect(world.log.at(-1)!.record.author).toBe((page.controller.current() as { deviceId: string }).deviceId);
  });
});


function auditPosts(world: FakeWorld): number {
  return world.exchanges.filter((x) => x.method === 'POST' && new URL(x.url).pathname.endsWith('/audit')).length;
}

function auditEvents(world: FakeWorld) {
  const keyEpoch = world.state().key_epoch;
  const out = verifyAuditChain(world.audit, { vaultKeys: (e) => world.vks.get(e), vaultId: world.vaultId, keyEpoch });
  return out.events.map((e) => {
    if (e.opaque) throw new Error('unexpected opaque audit entry');
    return e.event;
  });
}

describe('rotation audit stream', () => {
  it('appends one encrypted entry per state change, chained and without a name or value', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    const deviceId = (page.controller.current() as { deviceId: string }).deviceId;
    await page.controller.startRotation(itemId);
    await page.controller.rotate(itemId, NEW_SENTINEL);
    await page.controller.confirmRevoked(itemId);
    await page.controller.setRotationState(itemId, 'paused');
    await page.controller.setRotationState(itemId, 'active');
    await page.controller.setRotationState(itemId, 'failed');
    await page.controller.startRotation(itemId);
    await page.controller.setRotationState(itemId, 'cancelled');
    await page.controller.setRotationState(itemId, null);

    const events = auditEvents(world);
    expect(events.map((e) => e['type'])).toEqual([
      'rotation_started', 'rotation_vault_written', 'rotation_revoked', 'rotation_paused', 'rotation_resumed',
      'rotation_failed', 'rotation_started', 'rotation_cancelled', 'rotation_cleared',
    ]);
    for (const e of events) {
      expect(Object.keys(e).sort()).toEqual(['device_id', 'item_id', 'ts', 'type', 'v']);
      expect(e['v']).toBe(1);
      expect(e['type']).toMatch(/^[a-z][a-z0-9_]{0,63}$/); // the CLI reader's rule for an event type it does not know
      expect(e).toMatchObject({ item_id: itemId, device_id: deviceId });
      expect(typeof e['ts']).toBe('number');
    }
    // nothing readable on the wire or at rest: the stored entries are ciphertext
    const stored = JSON.stringify(world.audit);
    expect(stored).not.toMatch(/stripe-key|rotation-sentinel|rotation_started|item_id/);
    for (const e of world.exchanges) expect(e.requestBody).not.toMatch(/stripe-key|rotation-sentinel/);
  });

  it('writes no audit entry for an interval edit, a refused change or a failed write', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.setRotateTtl(itemId, 90);
    await page.controller.confirmRevoked(itemId); // refused: nothing in the vault yet
    await page.controller.rotate(itemId, SENTINEL); // refused: same value
    world.ownerSet('stripe-key', 'changed-elsewhere', { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000 });
    await page.controller.startRotation(itemId); // conflict
    expect(world.audit).toHaveLength(0);
  });

  it('reads the chain head again and re-seals when another device appended first', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    world.hostile.auditConflicts = 1;
    expect(await page.controller.startRotation(itemId)).toBe(true);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'info', code: 'rotation_started' } });
    const events = auditEvents(world);
    expect(events.map((e) => e['type'])).toEqual(['item_put', 'rotation_started']);
  });

  it('keeps the write and says the audit entry was not recorded when the append fails', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    world.hostile.auditAppendStatus = 500;
    expect(await page.controller.startRotation(itemId)).toBe(true);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'audit_failed' } });
    expect(item(page, itemId).rotation).toMatchObject({ state: 'active' });
    expect(world.audit).toHaveLength(0);
    world.hostile.auditAppendStatus = null;
    await page.controller.setRotationState(itemId, 'paused');
    expect(auditEvents(world).map((e) => e['type'])).toEqual(['rotation_paused']);
  });

  it('gives up after repeated head conflicts without undoing the write', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    world.hostile.auditConflicts = 10;
    expect(await page.controller.startRotation(itemId)).toBe(true);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'audit_failed' } });
    expect(item(page, itemId).rotation).toMatchObject({ state: 'active' });
  });

  it('refuses to chain onto a head the stored chain does not hold', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.startRotation(itemId);
    expect(world.audit).toHaveLength(1);
    world.hostile.auditForgedHead = true;
    const posted = auditPosts(world);
    expect(await page.controller.setRotationState(itemId, 'paused')).toBe(true);
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'error', code: 'audit_failed' } });
    // the server would accept an entry chained on its forged head; the client never sends one
    expect(auditPosts(world)).toBe(posted);
    expect(world.audit).toHaveLength(1);
  });

  it('refuses to append for a vault waiting on a rekey or without the current epoch key, sending nothing', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    // The controller never builds these snapshots; the guards are defence in depth, exercised directly.
    const real = (page.controller as unknown as { snapshot: VaultSnapshot }).snapshot;
    const client = (page.controller as unknown as { client: AkvClient }).client;
    const args = { client, action: 'rotation_started' as const, itemId, nowMs: Date.now() };
    const before = world.exchanges.length;
    await expect(appendRotationAudit({ ...args, snapshot: { ...real, state: { ...real.state, rekey_required: true } } })).rejects.toMatchObject({ code: 'audit_failed' });
    const vaultKeys = new Map(real.vaultKeys);
    vaultKeys.delete(real.state.key_epoch);
    await expect(appendRotationAudit({ ...args, snapshot: { ...real, vaultKeys } })).rejects.toMatchObject({ code: 'audit_failed' });
    expect(world.exchanges.length).toBe(before);
    expect(world.audit).toHaveLength(0);
  });

  it('seals under the current key epoch after a rekey', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.startRotation(itemId);
    world.ownerRekey([itemId]);
    await page.controller.refresh();
    await page.controller.setRotationState(itemId, 'paused');
    expect(page.controller.current()).toMatchObject({ notice: { kind: 'info', code: 'rotation_updated' } });
    expect(world.audit.map((e) => e.kid)).toEqual(['e1', 'e2']);
    // the chain verifies across the epoch change, each entry under its own epoch's audit key
    expect(auditEvents(world).map((e) => e['type'])).toEqual(['rotation_started', 'rotation_paused']);
  });

  it('audits a transition from the previous and next state, and nothing for a no-op', async () => {
    const world = new FakeWorld();
    const { page, itemId } = await open(world, (w) => seedAged(w));
    await page.controller.setRotationState(itemId, 'paused'); // no workflow: nothing to pause
    await page.controller.startRotation(itemId);
    await page.controller.setRotationState(itemId, 'active'); // already active
    await page.controller.setRotationState(itemId, 'paused');
    expect(auditEvents(world).map((e) => e['type'])).toEqual(['rotation_started', 'rotation_paused']);
  });
});

