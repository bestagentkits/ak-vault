// @vitest-environment happy-dom
/**
 * The human-only write request through the real controller, views and protocol
 * library against the in-memory Worker: the link carries only an opaque ID in its
 * fragment, the form shows the target opened with the vault's seal key, the value
 * is typed in the browser and reaches the server only inside the sealed record.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openItem } from '@ak-vault/protocol';
import { FakeWorld, ORIGIN } from './helpers/fake-world.js';
import { Browser, byTestId, type Page } from './helpers/dashboard-page.js';

const SENTINEL = 'sentinel-value-2b6d8e4a90';
const NAME_SENTINEL = 'sentinel-name-5c1f7a3d82';

let spies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of spies) {
    for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toContain(SENTINEL);
    s.mockRestore();
  }
});

/** Enrolled browser, then open the request link and sign in again, as a person following the URL would. */
async function openLink(b: Browser, rid: string): Promise<Page> {
  await b.load(`${ORIGIN}/app/#write=${rid}`);
  return b.signIn();
}

function type(page: Page, value: string): void {
  (byTestId(page.root, 'write-value') as HTMLInputElement).value = value;
  (byTestId(page.root, 'write-value') as HTMLInputElement).form!.dispatchEvent(new Event('submit', { cancelable: true }));
}

describe('write request', () => {
  it('creates a secret: the form opens the sealed name and the value reaches the server only sealed', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    const rid = world.prepareIntent(NAME_SENTINEL, 'create', 'high');
    const first = await b.load(`${ORIGIN}/app/#write=${rid}`);
    // The ID leaves the address bar before anything else runs and waits out the sign-in redirect.
    expect(first.replaced).toContain(`${ORIGIN}/app/`);
    expect(b.writeRequest.value).toBe(rid);
    const page = await b.signIn();
    expect(page.controller.current()).toMatchObject({ kind: 'write', request: { operation: 'create', name: NAME_SENTINEL, sensitivity: 'high' } });
    expect(byTestId(page.root, 'write-name').textContent).toBe(NAME_SENTINEL);
    const field = byTestId(page.root, 'write-value') as HTMLInputElement;
    expect(field.getAttribute('type')).toBe('text');
    expect(page.root.querySelector('input[type="password"]')).toBeNull();
    expect(field.getAttribute('autocomplete')).toBe('off');

    type(page, SENTINEL);
    expect(field.value).toBe('');
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'saved' } }));
    expect(world.intents.get(rid)!.status).toBe('completed');
    expect(b.writeRequest.value).toBeNull();

    const entry = world.log.at(-1)!.record;
    const payload = openItem({ ...entry, vk: world.vks.get(1)!, env: entry.env }) as { name: string; value: string; sensitivity: string };
    expect(payload).toMatchObject({ name: NAME_SENTINEL, value: SENTINEL, sensitivity: 'high' });
    for (const e of world.exchanges) {
      expect(e.requestBody, e.url).not.toContain(SENTINEL);
      expect(e.responseBody, e.url).not.toContain(SENTINEL);
      if (e.url.includes('/write-intents/')) expect(e.requestBody, e.url).not.toContain(NAME_SENTINEL);
    }
    // The ID is never sent as a URL query or to the config and token endpoints.
    expect(world.exchanges.filter((e) => !e.url.includes('/write-intents/')).some((e) => e.url.includes(rid) || e.requestBody.includes(rid))).toBe(false);
    expect(page.root.innerHTML).not.toContain(SENTINEL);
  });

  it('replaces the value of an existing secret at its verified revision', async () => {
    const world = new FakeWorld();
    const itemId = world.ownerSet('api-key', 'old');
    const b = new Browser(world);
    await b.enroll();
    const rid = world.prepareIntent('api-key', 'replace');
    const page = await openLink(b, rid);
    expect(page.controller.current()).toMatchObject({ kind: 'write', request: { operation: 'replace', name: 'api-key' } });
    // A replace keeps the stored sensitivity, so the form offers no choice.
    expect(page.root.querySelector('[data-testid="write-sensitivity"]')).toBeNull();
    type(page, SENTINEL);
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'saved' } }));
    const entry = world.log.at(-1)!.record;
    expect(entry.item_id).toBe(itemId);
    expect(entry.base_revision).toBe(1);
    expect(world.intents.get(rid)!.status).toBe('completed');
  });

  it('declining cancels the request and writes nothing', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    const rid = world.prepareIntent('declined', 'create');
    const page = await openLink(b, rid);
    byTestId(page.root, 'write-cancel').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'write_cancelled' } }));
    expect(world.intents.get(rid)!.status).toBe('cancelled');
    expect(world.log.length).toBe(0);
    expect(b.writeRequest.value).toBeNull();
  });

  it('refuses a request that no longer fits the vault and tells the server it conflicted', async () => {
    const world = new FakeWorld();
    world.ownerSet('taken', 'a');
    const b = new Browser(world);
    await b.enroll();
    const rid = world.prepareIntent('taken', 'create');
    const page = await openLink(b, rid);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'conflict' } });
    expect(world.intents.get(rid)!.status).toBe('failed');
    expect(b.writeRequest.value).toBeNull();
  });

  it('ends as a conflict when the item changes between the form and the save', async () => {
    const world = new FakeWorld();
    world.ownerSet('shared', 'a');
    const b = new Browser(world);
    await b.enroll();
    const rid = world.prepareIntent('shared', 'replace');
    const page = await openLink(b, rid);
    world.ownerSet('shared', 'b');
    expect(await page.controller.submitWrite(SENTINEL, 'normal')).toBe(false);
    expect(world.intents.get(rid)!.status).toBe('conflict');
    expect(page.controller.current()).toMatchObject({ kind: 'vault' });
    // Only the owner's own two records exist: the stale write never landed.
    expect(world.log.length).toBe(2);
  });

  it('shows the vault with an error for an unknown, used or other-vault request', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    const used = world.prepareIntent('used', 'create');
    world.intents.get(used)!.status = 'completed';
    for (const rid of [used, 'AAAAAAAAAAAAAAAAAAAAAA']) {
      const page = await openLink(b, rid);
      expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'write_request_gone' } });
      expect(b.writeRequest.value).toBeNull();
    }
  });

  it('ignores a fragment that is not an opaque request ID', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.load(`${ORIGIN}/app/#write=not-an-id`);
    expect(b.writeRequest.value).toBeNull();
    await b.load(`${ORIGIN}/app/#write=${'A'.repeat(22)}x`);
    expect(b.writeRequest.value).toBeNull();
  });

  it('refuses a target sealed under a key this vault does not hold', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    const rid = world.prepareIntent('forged', 'create');
    const row = world.intents.get(rid)!;
    (row.target as { vault_id: string }).vault_id = 'A'.repeat(22);
    const page = await openLink(b, rid);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'write_request_gone' } });
  });
});
