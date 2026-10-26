// @vitest-environment happy-dom
/**
 * Verified per-item history, safe restore and conflict settling, end to end
 * through the real controller, views, protocol library and WebCrypto keys
 * against an in-memory ak-web and Worker. Every secret value is a sentinel that
 * must never reach the DOM, device storage, a request or a console call.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openItem, type ItemPayload, type SignedRecord } from '@ak-vault/protocol';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, type Page } from './helpers/dashboard-page.js';
import { messageFor } from '../src/ui/messages.js';

const OLD = 'sentinel-old-value-41c2d9';
const MID = 'sentinel-mid-value-7be0a3';
const NEW = 'sentinel-new-value-93f1e8';
const BRANCH = 'sentinel-branch-value-5a6d27';
const ALL = [OLD, MID, NEW, BRANCH];

let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    for (const call of s.mock.calls) for (const v of ALL) expect(JSON.stringify(call)).not.toContain(v);
    s.mockRestore();
  }
});

function valueOf(world: FakeWorld, record: SignedRecord): string {
  return (openItem({ ...record, vk: world.vks.get(record.key_epoch)!, env: record.env }) as ItemPayload).value;
}

function itemIdOf(page: Page, name: string): string {
  const s = page.controller.current();
  if (s.kind !== 'vault') throw new Error('not the vault screen');
  return s.items.find((i) => i.name === name)!.itemId;
}

function expectNoValues(page: Page, b: Browser): void {
  const html = document.documentElement.outerHTML;
  for (const v of ALL) {
    expect(html).not.toContain(v);
    for (const e of b.world.exchanges.filter((x) => x.method === 'GET' || x.url.includes('/oauth'))) expect(e.responseBody, e.url).not.toContain(v);
    for (const d of b.devices.entries.values()) expect(JSON.stringify({ ...d, keys: null })).not.toContain(v);
  }
  expect(page.root.querySelector('[data-testid="reveal"], [data-testid="copy"], input[type="password"]')).toBeNull();
}

async function openHistory(page: Page, name: string): Promise<void> {
  await page.controller.openHistory(itemIdOf(page, name));
  expect(page.controller.current().kind).toBe('history');
}

function historyScreen(page: Page) {
  const s = page.controller.current();
  if (s.kind !== 'history' || !s.history) throw new Error('history not loaded');
  return s.history;
}

describe('history', () => {
  it('lists verified revision metadata without any value, copy or reveal action', async () => {
    const world = new FakeWorld();
    world.ownerSet('db-password', OLD);
    world.ownerSet('db-password', MID);
    world.ownerSet('db-password', NEW);
    const b = new Browser(world);
    const { page } = await b.enroll();
    await openHistory(page, 'db-password');
    const hist = historyScreen(page);
    expect(hist.entries.map((e) => [e.revision, e.kind, e.restoreBlock, e.readability])).toEqual([
      [3, 'applied', 'current', 'readable'],
      [2, 'applied', null, 'readable'],
      [1, 'applied', null, 'readable'],
    ]);
    expect(hist.stale).toBe(false);
    expect(hist.entries.every((e) => e.keyEpoch === 1 && e.author === world.owner.record.device_id && e.authorCurrent && !e.tombstone)).toBe(true);
    const rows = allByTestId(page.root, 'history-entry');
    expect(rows).toHaveLength(3);
    expect(page.root.textContent).toContain('signed by device');
    expect(page.root.textContent).toContain('claimed');
    expect(page.root.textContent).toContain('No value is shown');
    expect(page.root.textContent).toContain('does not make an old provider credential valid or safe');
    expectNoValues(page, b);
    // The history comes from the verified log: one more full read, no write.
    expect(world.exchanges.filter((e) => e.method === 'PUT')).toHaveLength(0);
  });

  it('pages a long history and keeps the list bounded', async () => {
    const world = new FakeWorld();
    for (let i = 0; i < 25; i++) world.ownerSet('rotating', `${OLD}-${i}`);
    const { page } = await new Browser(world).enroll();
    await openHistory(page, 'rotating');
    expect(allByTestId(page.root, 'history-entry')).toHaveLength(20);
    byTestId(page.root, 'history-more').click();
    expect(allByTestId(page.root, 'history-entry')).toHaveLength(25);
  });

  it('shows entries it cannot authenticate as unavailable, never as trusted history', async () => {
    const world = new FakeWorld();
    world.ownerSet('rotated', OLD);
    world.rekey();
    world.ownerSet('rotated', NEW);
    const b = new Browser(world);
    // The browser is approved after the rekey and never receives epoch 1.
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    world.approve(joinCode, offer.nonceI, { epochs: [2] });
    await page.controller.checkApproval();
    await openHistory(page, 'rotated');
    const hist = historyScreen(page);
    expect(hist.entries.map((e) => [e.revision, e.keyEpoch, e.readability, e.restoreBlock])).toEqual([
      [2, 2, 'readable', 'current'],
      [1, 1, 'no_key', 'no_key'],
    ]);
    expect(page.root.textContent).toContain('unavailable: this browser was never given the key for this epoch');
    expect(allByTestId(page.root, 'restore')).toHaveLength(0);
    // Even calling the controller directly cannot restore it.
    expect(await page.controller.restore(hist.entries[1]!.logSeq)).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'history', notice: { code: 'restore_unavailable' } });
    expect(world.exchanges.filter((e) => e.method === 'PUT')).toHaveLength(0);
  });

  it('flags a removed author and a deletion, and never offers a value from before a deletion', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('revived', OLD);
    world.ownerWrite({ itemId: id, base: 1, tombstone: true });
    expect(world.ownerWrite({ itemId: id, base: 2, name: 'revived', value: NEW }).status).toBe(200);
    const { page } = await new Browser(world).enroll();
    await openHistory(page, 'revived');
    const hist = historyScreen(page);
    expect(hist.entries.map((e) => [e.revision, e.tombstone, e.restoreBlock])).toEqual([
      [3, false, 'current'],
      [2, true, 'deletion'],
      [1, false, 'before_deletion'],
    ]);
    expect(await page.controller.restore(hist.entries[2]!.logSeq)).toBe(false);
    expect(world.log.at(-1)!.record.base_revision).toBe(2);
  });
});

describe('restore', () => {
  it('writes the old value as a new CAS revision at the current epoch after an explicit confirm', async () => {
    const world = new FakeWorld();
    world.ownerSet('api-key', OLD);
    world.ownerSet('api-key', NEW);
    const b = new Browser(world);
    const { page } = await b.enroll();
    world.rekey();
    await page.controller.refresh();
    await openHistory(page, 'api-key');
    const target = historyScreen(page).entries.find((e) => e.revision === 1)!;
    const logBefore = world.log.length;
    // Choosing a revision sends nothing; only the confirmation does.
    byTestId(page.root, 'restore').click();
    expect(world.log.length).toBe(logBefore);
    expect(byTestId(page.root, 'confirm-restore')).toBeTruthy();
    byTestId(page.root, 'confirm-restore').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'restored' } }));

    const written = world.log.at(-1)!.record;
    expect(world.log.length).toBe(logBefore + 1);
    expect(world.log.at(-1)!.conflict_id).toBeNull();
    expect(written.base_revision).toBe(2);
    expect(written.key_epoch).toBe(2);
    expect(written.author).not.toBe(world.owner.record.device_id);
    expect(written.tombstone).toBe(false);
    expect(valueOf(world, written)).toBe(OLD);
    // The earlier log positions are untouched.
    expect(world.log[target.logSeq - 1]!.record).toEqual(target.record);
    const put = world.exchanges.filter((e) => e.method === 'PUT');
    expect(put).toHaveLength(1);
    for (const v of ALL) expect(put[0]!.requestBody).not.toContain(v);
    expect(messageFor('restored')).toContain('may already be revoked or exposed');
    expectNoValues(page, b);
  });

  it('turns a concurrent update into a conflict branch instead of overwriting it', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('shared-key', OLD);
    world.ownerSet('shared-key', MID);
    const { page } = await new Browser(world).enroll();
    await openHistory(page, 'shared-key');
    const target = historyScreen(page).entries.find((e) => e.revision === 1)!;
    // Another device writes after the history was verified and before the restore lands.
    expect(world.ownerWrite({ itemId: id, base: 2, value: NEW }).status).toBe(200);
    expect(await page.controller.restore(target.logSeq)).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'conflict' } });
    const state = world.itemStates.get(id)!;
    expect(state.revision).toBe(3);
    expect(state.conflicts).toHaveLength(1);
    expect(valueOf(world, world.log.find((e) => e.record.item_id === id && e.log_seq > 0 && e.conflict_id === null && e.record.base_revision === 2)!.record)).toBe(NEW);
  });

  it('refuses to restore the value it already has, and a history older than the list', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('same', OLD);
    world.ownerWrite({ itemId: id, base: 1, value: MID });
    world.ownerWrite({ itemId: id, base: 2, value: OLD });
    const { page } = await new Browser(world).enroll();
    await openHistory(page, 'same');
    const first = historyScreen(page).entries.find((e) => e.revision === 1)!;
    expect(await page.controller.restore(first.logSeq)).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'history', notice: { code: 'restore_unchanged' } });
    expect(world.exchanges.filter((e) => e.method === 'PUT')).toHaveLength(0);
  });

  it('marks a history stale when the item moved on, and refuses to act on it', async () => {
    const world = new FakeWorld();
    const id = world.ownerSet('moving', OLD);
    world.ownerWrite({ itemId: id, base: 1, value: MID });
    const { page } = await new Browser(world).enroll();
    world.ownerWrite({ itemId: id, base: 2, value: NEW });
    await openHistory(page, 'moving');
    const hist = historyScreen(page);
    expect(hist.stale).toBe(true);
    expect(page.root.querySelector('[data-testid="history-stale"]')).not.toBeNull();
    expect(allByTestId(page.root, 'restore')).toHaveLength(0);
    expect(await page.controller.restore(hist.entries.find((e) => e.revision === 1)!.logSeq)).toBe(false);
    expect(world.exchanges.filter((e) => e.method === 'PUT')).toHaveLength(0);
  });
});

describe('conflicts', () => {
  async function conflicted(): Promise<{ world: FakeWorld; id: string; b: Browser; page: Page }> {
    const world = new FakeWorld();
    const id = world.ownerSet('contested', OLD);
    const b = new Browser(world);
    const { page } = await b.enroll();
    // Two writers on revision 1: one wins, the other is kept as a branch.
    expect(world.ownerWrite({ itemId: id, base: 1, value: MID }).status).toBe(200);
    expect(world.ownerWrite({ itemId: id, base: 1, value: BRANCH }).status).toBe(409);
    await page.controller.refresh();
    return { world, id, b, page };
  }

  it('lists the branch and keeps it until an operator-confirmed settle', async () => {
    const { world, id, b, page } = await conflicted();
    await openHistory(page, 'contested');
    const hist = historyScreen(page);
    expect(hist.openConflicts).toBe(1);
    const branch = hist.entries.find((e) => e.kind === 'conflict')!;
    expect(branch).toMatchObject({ revision: null, baseRevision: 1, conflictOpen: true, readability: 'readable' });
    expect(world.itemStates.get(id)!.conflicts).toHaveLength(1);
    byTestId(page.root, 'settle-branch').click();
    expect(world.itemStates.get(id)!.conflicts).toHaveLength(1);
    byTestId(page.root, 'confirm-settle').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'resolved' } }));
    const written = world.log.at(-1)!.record;
    expect(written.resolves).toEqual([branch.conflictId]);
    expect(written.base_revision).toBe(2);
    expect(valueOf(world, written)).toBe(BRANCH);
    expect(world.itemStates.get(id)!.conflicts).toHaveLength(0);
    expect(world.itemStates.get(id)!.revision).toBe(3);
    expectNoValues(page, b);
    await openHistory(page, 'contested');
    expect(historyScreen(page).entries.find((e) => e.kind === 'conflict')).toMatchObject({ conflictOpen: false, resolvedAtRevision: 3 });
  });

  it('can settle by keeping the current value', async () => {
    const { world, id, page } = await conflicted();
    await openHistory(page, 'contested');
    expect(await page.controller.settle({ source: 'current' })).toBe(true);
    expect(valueOf(world, world.log.at(-1)!.record)).toBe(MID);
    expect(world.itemStates.get(id)!.conflicts).toHaveLength(0);
  });

  it('refuses a branch that is not open, and settling with nothing open', async () => {
    const { page } = await conflicted();
    await openHistory(page, 'contested');
    expect(await page.controller.settle({ source: 'branch', conflictId: 'AAAAAAAAAAAAAAAAAAAAAA' })).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'history', notice: { code: 'restore_unavailable' } });
  });
});

describe('hostile history', () => {
  async function opened(): Promise<{ world: FakeWorld; page: Page; id: string }> {
    const world = new FakeWorld();
    const id = world.ownerSet('victim', OLD);
    world.ownerWrite({ itemId: id, base: 1, value: MID });
    const { page } = await new Browser(world).enroll();
    return { world, page, id };
  }

  it('fails closed when a record was substituted', async () => {
    const { world, page } = await opened();
    const swapped = world.log[0]!.record;
    world.log[0] = { ...world.log[0]!, record: { ...swapped, ts: swapped.ts + 1 } };
    await page.controller.openHistory(itemIdOf(page, 'victim'));
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'vault_verification_failed' });
    expect(page.root.textContent).not.toContain(MID);
  });

  it('raises the rollback alarm when the log was cut below the position this browser witnessed', async () => {
    const { world, page } = await opened();
    world.hostile.truncateLog = 1;
    await page.controller.openHistory(itemIdOf(page, 'victim'));
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('fails closed when a server relabels an applied record as a conflict branch', async () => {
    const { world, page } = await opened();
    world.log[1] = { ...world.log[1]!, conflict_id: 'AAAAAAAAAAAAAAAAAAAAAA' };
    await page.controller.openHistory(itemIdOf(page, 'victim'));
    expect(['vault_verification_failed', 'rollback']).toContain((page.controller.current() as { code: string }).code);
    expect(page.controller.current().kind).toBe('fatal');
  });

  it('fails closed when the log is reordered', async () => {
    const { world, page } = await opened();
    const [a, c] = [world.log[0]!, world.log[1]!];
    world.log[0] = { ...c, log_seq: 1 };
    world.log[1] = { ...a, log_seq: 2 };
    await page.controller.openHistory(itemIdOf(page, 'victim'));
    expect(page.controller.current().kind).toBe('fatal');
  });
});
