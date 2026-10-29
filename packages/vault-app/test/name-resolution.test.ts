// @vitest-environment happy-dom
/**
 * Name resolution for writes: a name matches after NFC normalization, against
 * every live head (listed, hidden or unreadable), so a create never adds a
 * second live item under a name another device already resolves, a replace
 * targets exactly one listed item, and a head this browser cannot open blocks
 * a create instead of being skipped.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openItem, randomId, type JsonObject, type SignedRecord } from '@ak-vault/protocol';
import { FakeWorld } from './helpers/fake-world.js';
import { Browser, byTestId, type Page } from './helpers/dashboard-page.js';

const SENTINEL = 'sentinel-value-2c9e71d4a8';
const NFC = 'café-api-key';
const NFD = 'café-api-key';
const SECRET_META: JsonObject = { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000 };

let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toContain(SENTINEL);
    s.mockRestore();
  }
});

function puts(world: FakeWorld): number {
  return world.exchanges.filter((e) => e.method === 'PUT').length;
}

/** A browser enrolled without the key of `omitEpochs`, on the vault screen. */
async function enrollWithout(world: FakeWorld, omitEpochs: number[]): Promise<{ b: Browser; page: Page }> {
  const b = new Browser(world);
  const page = await b.signIn();
  const joinCode = byTestId(page.root, 'join-code').textContent!;
  const offer = world.offerFor(joinCode);
  await page.controller.submitOffer(offer.code);
  world.approve(joinCode, offer.nonceI, { omitEpochs });
  await page.controller.checkApproval();
  expect(page.controller.current().kind).toBe('vault');
  return { b, page };
}

/** Open a write-request link in an enrolled browser and sign in from it. */
async function openRequest(world: FakeWorld, b: Browser, id: string): Promise<Page> {
  await b.load(world.formUrl(id));
  return b.signIn();
}

async function enrolled(world: FakeWorld): Promise<{ b: Browser; page: Page }> {
  const b = new Browser(world);
  const { page } = await b.enroll();
  return { b, page };
}

function lastWrittenName(world: FakeWorld): { itemId: string; name: string } {
  const record: SignedRecord = world.log.at(-1)!.record;
  const payload = openItem({ ...record, vk: world.vks.get(record.key_epoch)! }) as { name: string };
  return { itemId: record.item_id, name: payload.name };
}

describe('NFC name matching', () => {
  it('closes a create for the NFD spelling of an existing NFC name as already_exists', async () => {
    const world = new FakeWorld();
    world.ownerSet(NFC, 'old');
    const id = world.prepareWrite({ name: NFD });
    const { b } = await enrolled(world);
    const page = await openRequest(world, b, id);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_exists' } });
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'failed', reason: 'already_exists' });
    expect(puts(world)).toBe(0);
  });

  it('replaces the existing NFC item when a replace request names its NFD spelling', async () => {
    const world = new FakeWorld();
    const itemId = world.ownerSet(NFC, 'old');
    const id = world.prepareWrite({ name: NFD }, { operation: 'replace' });
    const { b } = await enrolled(world);
    const page = await openRequest(world, b, id);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true });
    expect(await page.controller.submitWrite(SENTINEL)).toBe(true);
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'completed' });
    // The stored spelling is kept, so a device matching names byte for byte still finds the item.
    expect(lastWrittenName(world)).toEqual({ itemId, name: NFC });
    expect(world.itemStates.get(itemId)!.revision).toBe(2);
    expect([...world.itemStates.values()].filter((s) => s.revision > 0 && !s.tombstone)).toHaveLength(1);
  });

  it('updates the existing item from the dashboard form instead of creating a second one', async () => {
    const world = new FakeWorld();
    const itemId = world.ownerSet(NFC, 'old');
    const { page } = await enrolled(world);
    expect(await page.controller.set(NFD, SENTINEL)).toBe(true);
    expect(lastWrittenName(world)).toEqual({ itemId, name: NFC });
    expect([...world.itemStates.values()].filter((s) => s.revision > 0 && !s.tombstone)).toHaveLength(1);
  });

  it('keeps an NFD spelling another device stored when the update names it in NFC', async () => {
    const world = new FakeWorld();
    const itemId = randomId();
    expect(world.ownerWrite(itemId, NFD, 'old', { base: 0 }).status).toBe(200);
    const { page } = await enrolled(world);
    expect(await page.controller.set(NFC, SENTINEL)).toBe(true);
    expect(lastWrittenName(world)).toEqual({ itemId, name: NFD });
  });

  it('stores a new item under the NFC spelling of the requested name', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NFD });
    const { b, page } = await enrolled(world);
    expect(await page.controller.set(`${NFD}-form`, SENTINEL)).toBe(true);
    expect(lastWrittenName(world).name).toBe(`${NFC}-form`);
    const reqPage = await openRequest(world, b, id);
    expect(await reqPage.controller.submitWrite(SENTINEL)).toBe(true);
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'completed' });
    expect(lastWrittenName(world).name).toBe(NFC);
  });

  it('finds the NFC item by its NFD spelling', async () => {
    const world = new FakeWorld();
    const itemId = world.ownerSet(NFC, 'old');
    const { page } = await enrolled(world);
    await page.controller.search(NFD);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', matches: [itemId] });
  });
});

describe('a hidden policy item', () => {
  const policyMeta = (governed: string): JsonObject => ({ kind: 'policy', item_ids: [governed], policy: { require_approval: true } });

  it('blocks a create of its name, a replace and a dashboard set', async () => {
    const world = new FakeWorld();
    const governed = world.ownerSet('governed', 'g');
    world.ownerWrite(randomId(), NFC, '', { base: 0, meta: policyMeta(governed) });
    const create = world.prepareWrite({ name: NFD });
    const replace = world.prepareWrite({ name: NFC }, { operation: 'replace' });
    const { b, page } = await enrolled(world);
    expect((page.controller.current() as { items: unknown[] }).items).toHaveLength(1);

    const createPage = await openRequest(world, b, create);
    expect(createPage.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_exists' } });
    expect(world.writeRequests.get(create)).toMatchObject({ state: 'failed', reason: 'already_exists' });

    const replacePage = await openRequest(world, b, replace);
    expect(replacePage.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_device_error' } });
    expect(world.writeRequests.get(replace)).toMatchObject({ state: 'failed', reason: 'device_error' });

    await replacePage.controller.leaveWrite();
    expect(await replacePage.controller.set(NFC, SENTINEL)).toBe(false);
    expect(replacePage.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'name_not_writable' } });
    expect(puts(world)).toBe(0);
  });
});

describe('an unreadable live head', () => {
  /** An item at key epoch 1 that a browser enrolled without epoch 1 cannot open, plus a readable one at epoch 2. */
  function worldWithUnreadable(): { world: FakeWorld; readable: string } {
    const world = new FakeWorld();
    world.ownerSet('legacy', 'a');
    world.rekey();
    const readable = world.ownerSet('current', 'b', SECRET_META);
    return { world, readable };
  }

  it('fails a create request closed without writing', async () => {
    const { world } = worldWithUnreadable();
    const id = world.prepareWrite({ name: 'brand-new' });
    const { b } = await enrollWithout(world, [1]);
    const page = await openRequest(world, b, id);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_device_error' } });
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'failed', reason: 'device_error' });
    expect(puts(world)).toBe(0);
  });

  it('refuses a new item from the dashboard with name_unverifiable, and still updates a readable one', async () => {
    const { world, readable } = worldWithUnreadable();
    const { page } = await enrollWithout(world, [1]);
    expect(await page.controller.set('brand-new', SENTINEL)).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'name_unverifiable' } });
    expect(puts(world)).toBe(0);
    expect(await page.controller.set('current', SENTINEL)).toBe(true);
    expect(lastWrittenName(world)).toEqual({ itemId: readable, name: 'current' });
  });
});

describe('more than one live item with the name', () => {
  it('refuses a create, a replace and a dashboard set', async () => {
    const world = new FakeWorld();
    world.ownerSet(NFC, 'a');
    expect(world.ownerWrite(randomId(), NFD, 'b', { base: 0 }).status).toBe(200);
    const create = world.prepareWrite({ name: NFC });
    const replace = world.prepareWrite({ name: NFC }, { operation: 'replace' });
    const { b, page } = await enrolled(world);
    expect((page.controller.current() as { items: unknown[] }).items).toHaveLength(2);

    const createPage = await openRequest(world, b, create);
    expect(world.writeRequests.get(create)).toMatchObject({ state: 'failed', reason: 'already_exists' });
    expect(createPage.controller.current()).toMatchObject({ notice: { code: 'write_exists' } });

    const replacePage = await openRequest(world, b, replace);
    expect(world.writeRequests.get(replace)).toMatchObject({ state: 'failed', reason: 'not_found' });
    expect(replacePage.controller.current()).toMatchObject({ notice: { code: 'write_missing' } });

    await replacePage.controller.leaveWrite();
    expect(await replacePage.controller.set(NFD, SENTINEL)).toBe(false);
    expect(replacePage.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'duplicate_name' } });
    expect(puts(world)).toBe(0);
  });
});
