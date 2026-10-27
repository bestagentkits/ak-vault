// @vitest-environment happy-dom
/**
 * Per-item history, restore and conflict resolution through the real
 * controller, views, protocol library and WebCrypto keys against an in-memory
 * ak-web and Worker. Values are synthetic sentinels that must never reach the
 * DOM, a request body the dashboard sends, device storage or the console.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openItem } from '@ak-vault/protocol';
import { openRecord } from '../src/sync/vault-sync.js';
import { ACCOUNT, FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, settle, type Page } from './helpers/dashboard-page.js';

const S = (n: string) => `sentinel-history-${n}-4d1e8a07c3`;

let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toContain('sentinel-history-');
    s.mockRestore();
  }
});

function itemIdOf(world: FakeWorld): string {
  return world.log[0]!.record.item_id;
}

function openHistory(page: Page): void {
  byTestId(page.root, 'history').click();
  expect(page.controller.current().kind).toBe('history');
}

function titles(page: Page): string[] {
  return allByTestId(page.root, 'entry-title').map((e) => e.textContent ?? '');
}

function noPlaintext(page: Page, world: FakeWorld): void {
  expect(page.root.innerHTML).not.toContain('sentinel-history-');
  expect(document.documentElement.outerHTML).not.toContain('sentinel-history-');
  expect(page.root.querySelector('[data-testid="reveal"], [data-testid="copy"], input[type="password"]')).toBeNull();
  for (const e of world.exchanges) {
    expect(e.requestBody, e.url).not.toContain('sentinel-history-');
    expect(e.responseBody, e.url).not.toContain('sentinel-history-');
  }
}

function readValue(world: FakeWorld, logSeq: number): string {
  const record = world.log[logSeq - 1]!.record;
  return (openItem({ ...record, vk: world.vks.get(record.key_epoch)! }) as { value: string }).value;
}

/** An item with three revisions written by the owner device. */
async function threeRevisions() {
  const world = new FakeWorld();
  world.ownerSet('prod-api-key', S('one'));
  world.ownerSet('prod-api-key', S('two'));
  world.ownerSet('prod-api-key', S('three'));
  const b = new Browser(world);
  const { page } = await b.enroll();
  return { world, b, page };
}

describe('history', () => {
  it('lists verified revision metadata, newest first, without any value, reveal or copy', async () => {
    const { world, page } = await threeRevisions();
    openHistory(page);
    expect(byTestId(page.root, 'history-title').textContent).toBe('History of prod-api-key');
    expect(titles(page)).toEqual(['Revision 3', 'Revision 2', 'Revision 1']);
    const text = page.root.textContent!;
    expect(text).toContain('current');
    expect(text).toContain('key epoch 1');
    expect(text).toContain(`device ${world.owner.record.device_id.slice(0, 8)} (current device)`);
    expect(text).toContain('the value is stored encrypted and never shown');
    // Only earlier revisions can be restored.
    expect(allByTestId(page.root, 'restore').length).toBe(2);
    noPlaintext(page, world);
  });

  it('opens the history of a vault that gained a device after this browser last pulled', async () => {
    const { world, page } = await threeRevisions();
    const second = await new Browser(world).signIn();
    const joinCode = byTestId(second.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await second.controller.submitOffer(offer.code);
    world.approve(joinCode, offer.nonceI);
    await page.controller.refresh();
    page.controller.openHistory(itemIdOf(world));
    expect(page.controller.current().kind).toBe('history');
    expect(titles(page)).toEqual(['Revision 3', 'Revision 2', 'Revision 1']);
    await page.controller.refresh();
    expect(page.controller.current().kind).toBe('history');
    noPlaintext(page, world);
  });

  it('opens from the item list and returns to it', async () => {
    const { page } = await threeRevisions();
    openHistory(page);
    byTestId(page.root, 'history-back').click();
    expect(page.controller.current().kind).toBe('vault');
  });

  it('shows a tombstone in a re-created item without offering to restore through it', async () => {
    const world = new FakeWorld();
    world.ownerSet('reborn', S('a'));
    const itemId = itemIdOf(world);
    expect(world.ownerWrite(itemId, 'reborn', '', { base: 1, tombstone: true }).status).toBe(200);
    expect(world.ownerWrite(itemId, 'reborn', S('b'), { base: 2 }).status).toBe(200);
    const { page } = await new Browser(world).enroll();
    openHistory(page);
    expect(titles(page)).toEqual(['Revision 3', 'Revision 2 (deletion)', 'Revision 1']);
    expect(page.root.textContent).toContain('a deletion carries no value');
    const rows = allByTestId(page.root, 'history-entry');
    expect(rows[1]!.querySelector('[data-testid="restore"]')).toBeNull();
    noPlaintext(page, world);
  });

  it('does not list or open a deleted item, and refuses to restore into it', async () => {
    const world = new FakeWorld();
    world.ownerSet('gone', S('a'));
    world.ownerSet('gone', S('b'));
    const itemId = itemIdOf(world);
    world.ownerWrite(itemId, 'gone', '', { base: 2, tombstone: true });
    const { page } = await new Browser(world).enroll();
    expect(allByTestId(page.root, 'item').length).toBe(0);
    page.controller.openHistory(itemId);
    expect(page.controller.current().kind).toBe('vault');
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    expect(await page.controller.restore(itemId, 1)).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'not_found' } });
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });

  it('says unavailable / unverified for a revision under a key epoch this browser never held, and refuses to restore it', async () => {
    const world = new FakeWorld();
    world.ownerSet('rotated', S('old'));
    world.rekey();
    world.ownerSet('rotated', S('new'));
    const b = new Browser(world);
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    world.approve(joinCode, offer.nonceI, { omitEpochs: [1] });
    await page.controller.checkApproval();
    expect(page.controller.current().kind).toBe('vault');
    openHistory(page);
    expect(titles(page)).toEqual(['Revision 2', 'Revision 1']);
    const old = allByTestId(page.root, 'history-entry')[1]!;
    expect(old.textContent).toContain('unavailable / unverified content');
    expect(old.textContent).toContain('key epoch 1');
    expect(old.querySelector('[data-testid="restore"]')).toBeNull();
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    expect(await page.controller.restore(world.log[0]!.record.item_id, 1)).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'history', notice: { code: 'history_unavailable' } });
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
    noPlaintext(page, world);
  });
});

describe('restore', () => {
  it('asks for confirmation with the provider warning, then writes a new signed CAS revision', async () => {
    const { world, page } = await threeRevisions();
    openHistory(page);
    const before = world.log.length;
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    allByTestId(page.root, 'restore')[1]!.click(); // revision 1
    expect(byTestId(page.root, 'restore-confirm').textContent).toContain('rotate or revoke it there');
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
    byTestId(page.root, 'confirm-restore').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'history', notice: { code: 'restored' } }));

    expect(world.log.length).toBe(before + 1);
    const written = world.log.at(-1)!;
    expect(written.conflict_id).toBeNull();
    expect(written.record).toMatchObject({ base_revision: 3, key_epoch: 1, tombstone: false, resolves: [] });
    expect(written.record.author).toBe((page.controller.current() as { deviceId: string }).deviceId);
    expect(readValue(world, world.log.length)).toBe(S('one'));
    // Earlier log positions are untouched.
    expect([1, 2, 3].map((n) => readValue(world, n))).toEqual([S('one'), S('two'), S('three')]);
    expect(titles(page)).toEqual(['Revision 4', 'Revision 3', 'Revision 2', 'Revision 1']);
    expect(page.root.textContent).toContain('Restored as a new revision');
    noPlaintext(page, world);
  });

  it('cancel writes nothing', async () => {
    const { world, page } = await threeRevisions();
    openHistory(page);
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    allByTestId(page.root, 'restore')[0]!.click();
    (byTestId(page.root, 'restore-confirm').querySelector('.secondary') as HTMLElement).click();
    expect(page.root.querySelector('[data-testid="restore-confirm"]')).toBeNull();
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });

  it('uses the current key epoch for a revision written under an older epoch the browser holds', async () => {
    const world = new FakeWorld();
    world.ownerSet('rotated', S('old'));
    world.rekey();
    world.ownerSet('rotated', S('new'));
    const { page } = await new Browser(world).enroll();
    openHistory(page);
    allByTestId(page.root, 'restore')[0]!.click();
    byTestId(page.root, 'confirm-restore').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'restored' } }));
    expect(world.log[0]!.record.key_epoch).toBe(1);
    expect(world.log.at(-1)!.record).toMatchObject({ key_epoch: 2, base_revision: 2 });
    expect(readValue(world, world.log.length)).toBe(S('old'));
  });

  it('turns a concurrent update into a preserved conflict, never a last-writer-wins overwrite', async () => {
    const { world, page } = await threeRevisions();
    openHistory(page);
    world.ownerSet('prod-api-key', S('four')); // another device writes after this browser pulled
    allByTestId(page.root, 'restore')[1]!.click();
    byTestId(page.root, 'confirm-restore').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'conflict' } }));
    const last = world.log.at(-1)!;
    expect(last.conflict_id).not.toBeNull();
    expect(readValue(world, 4)).toBe(S('four'));
    const state = world.itemStates.get(itemIdOf(world))!;
    expect(state.revision).toBe(4);
    expect(state.conflicts.length).toBe(1);
    // The refreshed history shows the head and the open branch.
    expect(page.controller.current().kind).toBe('history');
    expect(allByTestId(page.root, 'conflicts').length).toBe(1);
    noPlaintext(page, world);
  });

  it('refuses a revision that already has the current value, without writing', async () => {
    const world = new FakeWorld();
    world.ownerSet('same', S('x'));
    world.ownerSet('same', S('y'));
    world.ownerSet('same', S('x'));
    const { page } = await new Browser(world).enroll();
    openHistory(page);
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    allByTestId(page.root, 'restore')[1]!.click(); // revision 1 has the value of revision 3
    byTestId(page.root, 'confirm-restore').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'restore_current' } }));
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });

  it('refuses to restore a position that is the current head, a tombstone or a branch', async () => {
    const world = new FakeWorld();
    world.ownerSet('x', S('a'));
    const itemId = itemIdOf(world);
    world.ownerWrite(itemId, 'x', '', { base: 1, tombstone: true });
    world.ownerWrite(itemId, 'x', S('b'), { base: 2 });
    const stale = world.ownerWrite(itemId, 'x', S('branch'), { base: 2 });
    expect(stale.status).toBe(409);
    const { page } = await new Browser(world).enroll();
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    for (const logSeq of [3, 2, 4, 99]) expect(await page.controller.restore(itemId, logSeq)).toBe(false);
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });
});

describe('conflicts', () => {
  async function conflicted() {
    const world = new FakeWorld();
    world.ownerSet('shared', S('base'));
    const itemId = itemIdOf(world);
    expect(world.ownerWrite(itemId, 'shared', S('head'), { base: 1 }).status).toBe(200);
    const branch = world.ownerWrite(itemId, 'shared', S('branch'), { base: 1 });
    expect(branch.status).toBe(409);
    const { page } = await new Browser(world).enroll();
    openHistory(page);
    return { world, page, itemId, conflictId: branch.conflictId! };
  }

  it('shows the open branch with its provenance and keeps it listed', async () => {
    const { world, page } = await conflicted();
    expect(titles(page)).toEqual(['Conflicting branch on revision 1', 'Revision 2', 'Revision 1']);
    expect(byTestId(page.root, 'conflicts').textContent).toContain('ak secrets sync settle');
    expect(allByTestId(page.root, 'resolve-choice').length).toBe(2);
    noPlaintext(page, world);
  });

  it('keeps the current value, resolves the branch with a new revision and keeps the branch in history', async () => {
    const { world, page, itemId, conflictId } = await conflicted();
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    allByTestId(page.root, 'resolve-choice')[0]!.click();
    expect(byTestId(page.root, 'resolve-confirm').textContent).toContain('mark all 1 open branch resolved');
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
    byTestId(page.root, 'confirm-resolve').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'resolved' } }));
    const rec = world.log.at(-1)!.record;
    expect(rec).toMatchObject({ item_id: itemId, base_revision: 2, resolves: [conflictId] });
    expect(readValue(world, world.log.length)).toBe(S('head'));
    expect(world.itemStates.get(itemId)!.conflicts).toEqual([]);
    expect(allByTestId(page.root, 'conflicts').length).toBe(0);
    expect(titles(page)).toContain('Conflicting branch on revision 1');
    expect(page.root.textContent).toContain('resolved at revision 3');
    noPlaintext(page, world);
  });

  it('adopts the branch value and resolves it', async () => {
    const { world, page, conflictId } = await conflicted();
    allByTestId(page.root, 'resolve-choice')[1]!.click();
    byTestId(page.root, 'confirm-resolve').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'resolved' } }));
    expect(world.log.at(-1)!.record.resolves).toEqual([conflictId]);
    expect(readValue(world, world.log.length)).toBe(S('branch'));
  });

  it('cancel writes nothing', async () => {
    const { world, page } = await conflicted();
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    allByTestId(page.root, 'resolve-choice')[0]!.click();
    (byTestId(page.root, 'resolve-confirm').parentElement!.querySelector('.secondary') as HTMLElement).click();
    expect(page.root.querySelector('[data-testid="resolve-confirm"]')).toBeNull();
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });

  it('does not offer to resolve while a branch is a deletion, and refuses both keep and adopt', async () => {
    const world = new FakeWorld();
    world.ownerSet('shared', S('base'));
    const itemId = itemIdOf(world);
    world.ownerWrite(itemId, 'shared', S('head'), { base: 1 });
    const del = world.ownerWrite(itemId, 'shared', '', { base: 1, tombstone: true });
    expect(del.status).toBe(409);
    const { page } = await new Browser(world).enroll();
    openHistory(page);
    expect(allByTestId(page.root, 'resolve-choice').length).toBe(0);
    expect(byTestId(page.root, 'resolve-blocked').textContent).toContain('ak secrets sync settle');
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    expect(await page.controller.resolve(itemId, del.conflictId!)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'history_unavailable' } });
    expect(await page.controller.resolve(itemId, null)).toBe(false);
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });

  it('keeps the base64 marker when it restores or adopts a value the CLI wrote as base64', async () => {
    const world = new FakeWorld();
    const meta = { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000, value_encoding: 'base64' };
    world.ownerSet('binary', S('AAEC'), meta);
    const itemId = itemIdOf(world);
    world.ownerWrite(itemId, 'binary', S('plain'), { base: 1 });
    const { page } = await new Browser(world).enroll();
    expect(await page.controller.restore(itemId, 1)).toBe(true);
    const written = openRecord(world.log.at(-1)!.record, world.vks.get(1));
    expect(written).toMatchObject({ value: S('AAEC'), meta: { value_encoding: 'base64' } });
  });

  it('refuses a value whose encoding it does not know', async () => {
    const world = new FakeWorld();
    world.ownerSet('odd', S('x'), { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000, value_encoding: 'hex' });
    const itemId = itemIdOf(world);
    world.ownerWrite(itemId, 'odd', S('y'), { base: 1 });
    const { page } = await new Browser(world).enroll();
    expect(await page.controller.restore(itemId, 1)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'history_unavailable' } });
  });

  it('refuses to restore a value from before the item was deleted and re-created', async () => {
    const world = new FakeWorld();
    world.ownerSet('reborn', S('a'));
    const itemId = itemIdOf(world);
    world.ownerWrite(itemId, 'reborn', '', { base: 1, tombstone: true });
    world.ownerWrite(itemId, 'reborn', S('b'), { base: 2 });
    world.ownerWrite(itemId, 'reborn', S('c'), { base: 3 });
    const { page } = await new Browser(world).enroll();
    expect(await page.controller.restore(itemId, 1)).toBe(false);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'history_unavailable' } });
  });

  it('refuses to resolve when there is no open branch', async () => {
    const { world, page } = await threeRevisions();
    const puts = world.exchanges.filter((e) => e.method === 'PUT').length;
    expect(await page.controller.resolve(itemIdOf(world), null)).toBe(false);
    expect(world.exchanges.filter((e) => e.method === 'PUT').length).toBe(puts);
  });
});

describe('hostile history fails closed', () => {
  it('refuses a log with a withheld entry and shows no history', async () => {
    const { world, page } = await threeRevisions();
    world.hostile.dropLogSeq = 2;
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
    expect(page.root.querySelector('[data-testid="history-list"]')).toBeNull();
  });

  it('refuses a log whose record signature was tampered with', async () => {
    const { world, page } = await threeRevisions();
    world.hostile.mutateEntry = (e) => (e.log_seq === 2 ? { ...e, record: { ...e.record, ts: e.record.ts + 1 } } : e);
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'vault_verification_failed' });
    expect(page.root.querySelector('[data-testid="history-list"]')).toBeNull();
  });

  it('refuses a log whose branch label was changed (a fork the head chain does not cover)', async () => {
    const { world, page } = await threeRevisions();
    world.hostile.mutateEntry = (e) => (e.log_seq === 3 ? { ...e, conflict_id: 'AAAAAAAAAAAAAAAAAAAAAA' } : e);
    await page.controller.refresh();
    expect(['rollback', 'vault_verification_failed']).toContain((page.controller.current() as { code: string }).code);
    expect(page.controller.current().kind).toBe('fatal');
  });

  it('refuses a rolled-back log while the history is open', async () => {
    const { world, page } = await threeRevisions();
    openHistory(page);
    world.hostile.truncateLog = 1;
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('refuses a log whose positions were reordered, by the head this browser kept', async () => {
    const { world, page } = await threeRevisions();
    const [two, three] = [world.log[1]!, world.log[2]!];
    world.hostile.mutateEntry = (e) => (e.log_seq === 2 ? { ...three, log_seq: 2 } : e.log_seq === 3 ? { ...two, log_seq: 3 } : e);
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
    expect(page.root.querySelector('[data-testid="history-list"]')).toBeNull();
  });
});

describe('restore authorization', () => {
  it('writes nothing once the owner removed this device after the history opened (simulated Worker refusal)', async () => {
    const { world, page } = await threeRevisions();
    openHistory(page);
    const before = world.log.length;
    const putsBefore = world.exchanges.filter((e) => e.method === 'PUT').length;
    world.removeDevice((page.controller.current() as { deviceId: string }).deviceId);
    // The browser cannot know yet. The fake Worker refuses a device the chain no longer lists.
    expect(await page.controller.restore(itemIdOf(world), 1)).toBe(false);
    // Zero PUTs or only refused ones: either way nothing is appended.
    expect(world.exchanges.filter((e) => e.method === 'PUT').slice(putsBefore).every((e) => e.status === 403)).toBe(true);
    expect(world.log.length).toBe(before);
    // The pull after the refusal finds the removal and leaves the vault.
    expect(page.controller.current().kind).toBe('removed');
    noPlaintext(page, world);
  });
});

describe('retention', () => {
  it('pages the list and bounds what is held per item', async () => {
    const world = new FakeWorld();
    for (let i = 0; i < 25; i++) world.ownerSet('busy', S(String(i)));
    const { page } = await new Browser(world).enroll();
    openHistory(page);
    expect(allByTestId(page.root, 'history-entry').length).toBe(20);
    byTestId(page.root, 'history-more').click();
    expect(allByTestId(page.root, 'history-entry').length).toBe(25);
    expect(page.root.querySelector('[data-testid="history-more"]')).toBeNull();
    expect(page.root.querySelector('[data-testid="history-omitted"]')).toBeNull();
  });
});

describe('device storage', () => {
  it('keeps the account device free of values after a restore', async () => {
    const { world, b, page } = await threeRevisions();
    openHistory(page);
    allByTestId(page.root, 'restore')[1]!.click();
    byTestId(page.root, 'confirm-restore').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ notice: { code: 'restored' } }));
    for (const d of b.devices.entries.values()) expect(JSON.stringify({ ...d, keys: null })).not.toContain('sentinel-history-');
    expect(b.devices.entries.has(ACCOUNT)).toBe(true);
    noPlaintext(page, world);
  });
});
