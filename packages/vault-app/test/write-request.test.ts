// @vitest-environment happy-dom
/**
 * Human write requests end to end: the link's fragment, sign-in, opening the
 * sealed intent with the device's own seal key, the create/replace checks, the
 * CAS write with `?write_request=`, cancel, conflict and stale links, and that
 * the typed value never reaches the DOM, the logs, the pending store or any
 * request other than the sealed record.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomId, type SignedRecord } from '@ak-vault/protocol';
import { parseWriteLink } from '../src/sync/write-request.js';
import { remaining } from '../src/ui/views.js';
import { FakeWorld, ORIGIN } from './helpers/fake-world.js';
import { Browser, byTestId, type Page } from './helpers/dashboard-page.js';

const SENTINEL = 'sentinel-value-4d2b8e61f0';
const NAME = 'deploy-api-key';
const CLIENT = 'https://assistant.example.test/client';

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

/** An enrolled browser opens the link in a fresh page and signs in from it. */
async function openLink(world: FakeWorld, link: string, b?: Browser): Promise<{ b: Browser; page: Page; linkPage: Page }> {
  const browser = b ?? new Browser(world);
  if (!b) await browser.enroll();
  const linkPage = await browser.load(link);
  const page = await browser.signIn();
  return { b: browser, page, linkPage };
}

function deviceOf(page: Page): string {
  const s = page.controller.current();
  if (s.kind !== 'vault') throw new Error('not on the vault screen');
  return s.deviceId;
}

function writeRequestCalls(world: FakeWorld): string[] {
  return world.exchanges.filter((e) => e.url.includes('/write-requests/') || e.url.includes('write_request=')).map((e) => `${e.method} ${new URL(e.url).pathname}`);
}

async function submit(page: Page, value: string): Promise<HTMLInputElement> {
  const input = byTestId(page.root, 'write-value') as HTMLInputElement;
  input.value = value;
  (input.form as HTMLFormElement).dispatchEvent(new Event('submit', { cancelable: true }));
  expect(input.value).toBe('');
  await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'write', busy: false }));
  return input;
}

function expectNoValueAnywhere(world: FakeWorld, b: Browser, page: Page): void {
  expect(page.root.innerHTML).not.toContain(SENTINEL);
  expect(document.documentElement.outerHTML).not.toContain(SENTINEL);
  for (const e of world.exchanges) {
    expect(e.requestBody, e.url).not.toContain(SENTINEL);
    expect(e.responseBody, e.url).not.toContain(SENTINEL);
    expect(e.url).not.toContain(SENTINEL);
  }
  for (const d of b.devices.entries.values()) expect(JSON.stringify({ ...d, keys: null })).not.toContain(SENTINEL);
  expect(JSON.stringify(b.pending.value)).not.toContain(SENTINEL);
  expect(JSON.stringify(page.controller.current())).not.toContain(SENTINEL);
}

describe('write-request link', () => {
  it('parses only an exact fragment of two canonical 16-byte IDs', () => {
    const a = randomId();
    const v = randomId();
    expect(parseWriteLink(`#write=${a}&vault=${v}`)).toEqual({ requestId: a, vaultId: v });
    for (const bad of [
      '', '#', `#vault=${v}&write=${a}`, `#write=${a}`, `#write=${a}&vault=${v}&x=1`, `#write=${a}&vault=${v.slice(0, 21)}`,
      `#write=${a}&vault=${v.slice(0, 21)}=`, `#write=${'A'.repeat(21)}B&vault=${v}`, '#write=<script>&vault=x', `write=${a}&vault=${v}`,
    ]) {
      expect(parseWriteLink(bad), bad).toBeNull();
    }
  });

  it('formats the remaining time', () => {
    expect(remaining(10_000 + 605_000, 10_000)).toBe('10m 05s');
    expect(remaining(10_000 + 9_500, 10_000)).toBe('9s');
    expect(remaining(10_000, 10_000)).toBe('expired');
  });

  it('clears the fragment, survives the sign-in redirect and opens the request', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME, purpose: 'Deploy to staging' });
    const { b, page, linkPage } = await openLink(world, world.formUrl(id));
    expect(linkPage.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(linkPage.controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'write_signin' } });
    expect(b.pending.value).toBeNull();
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true, request: { name: NAME, purpose: 'Deploy to staging', clientId: CLIENT, operation: 'create' } });
    expect(byTestId(page.root, 'write-name').textContent).toBe(NAME);
    expect(byTestId(page.root, 'write-client').textContent).toBe(CLIENT);
    expect(byTestId(page.root, 'write-expiry').textContent).toMatch(/^(9|10)m \d\ds$/);
    const input = byTestId(page.root, 'write-value') as HTMLInputElement;
    expect(input.getAttribute('type')).toBe('password');
    expect(input.value).toBe('');
    expect(input.getAttribute('autocomplete')).toBe('off');
  });

  it('opens a link pasted into a running dashboard (fragment change)', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const { page } = await b.enroll();
    const id = world.prepareWrite({ name: NAME });
    await page.controller.openLink(new URL(world.formUrl(id)));
    expect(page.replaced.at(-1)).toBe(`${ORIGIN}/app/`);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true });
  });

  it('ignores a malformed fragment and calls no write-request route', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    const page = await b.load(`${ORIGIN}/app/#write=not-an-id&vault=${world.vaultId}`);
    expect(page.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: null });
    const after = await b.signIn();
    expect(after.controller.current().kind).toBe('vault');
    const other = await b.load(`${ORIGIN}/app/#section`);
    expect(other.replaced).toEqual([]);
    expect(writeRequestCalls(world)).toEqual([]);
  });

  it('refuses a link for another vault without calling the write routes', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    const { page } = await openLink(world, world.formUrl(id, randomId()));
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'write_wrong_vault' } });
    expect(writeRequestCalls(world)).toEqual([]);
    expect(world.writeRequests.get(id)!.state).toBe('pending_user');
  });

  it('asks a browser that is not enrolled yet to enroll first, then opens the request', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    const b = new Browser(world);
    await b.load(world.formUrl(id));
    const page = await b.signIn();
    expect(page.controller.current()).toMatchObject({ kind: 'join', notice: { code: 'write_enroll' } });
    expect(writeRequestCalls(world)).toEqual([]);
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    world.approve(joinCode, offer.nonceI);
    await page.controller.checkApproval();
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true, request: { name: NAME } });
  });

  it('shows a friendly message for an expired or closed link', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    world.writeRequests.get(id)!.expiresAt = Date.now() - 1;
    const { page } = await openLink(world, world.formUrl(id));
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, request: null, notice: { code: 'write_unavailable' } });
    expect(byTestId(page.root, 'notice').textContent).toContain('no longer open');
    expect(writeRequestCalls(world).filter((c) => !c.startsWith('GET'))).toEqual([]);
    await page.controller.leaveWrite();
    expect(page.controller.current().kind).toBe('vault');
  });

  it('wipes the device when it was revoked', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const { page } = await b.enroll();
    const id = world.prepareWrite({ name: NAME });
    world.removeDevice(deviceOf(page));
    await page.controller.openLink(new URL(world.formUrl(id)));
    expect(page.controller.current().kind).toBe('removed');
  });

  it('refuses while the vault needs a rekey, without calling the write routes', async () => {
    const world = new FakeWorld();
    const { page } = await new Browser(world).enroll();
    const other = await new Browser(world).enroll();
    const id = world.prepareWrite({ name: NAME });
    // A removal marks the vault rekey-required until an owner rekeys.
    world.removeDevice(deviceOf(other.page));
    await page.controller.refresh();
    const before = writeRequestCalls(world).length;
    await page.controller.openLink(new URL(world.formUrl(id)));
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'rekey_required' } });
    expect(writeRequestCalls(world).length).toBe(before);
  });

  it('offers a retry when the request cannot be loaded', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const { page } = await b.enroll();
    const id = world.prepareWrite({ name: NAME });
    const fetchWorld = world.fetch;
    let offline = true;
    (world as { fetch: typeof fetch }).fetch = async (input, init) => {
      if (offline && String(input).includes('/write-requests/')) throw new TypeError('offline');
      return fetchWorld(input, init);
    };
    await page.controller.openLink(new URL(world.formUrl(id)));
    expect(page.controller.current()).toMatchObject({ kind: 'write', retry: true, notice: { code: 'network' } });
    offline = false;
    byTestId(page.root, 'write-retry').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'write', open: true }));
  });
});

describe('completing a write request', () => {
  it('creates a new item with a fresh item ID and base revision 0, under a proof that covers the query', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME, sensitivity: 'high' });
    const { b, page } = await openLink(world, world.formUrl(id));
    await submit(page, SENTINEL);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { kind: 'info', code: 'write_saved' } });
    const row = world.writeRequests.get(id)!;
    expect(row.state).toBe('completed');
    expect(byTestId(page.root, 'write-receipt').textContent).toBe(`Receipt ${row.receipt!.slice(0, 8)}`);
    const put = world.exchanges.find((e) => e.method === 'PUT')!;
    expect(new URL(put.url).searchParams.get('write_request')).toBe(id);
    expect(put.status).toBe(200);
    const record = (JSON.parse(put.requestBody) as { record: SignedRecord }).record;
    expect(record.base_revision).toBe(0);
    expectNoValueAnywhere(world, b, page);
    await page.controller.leaveWrite();
    expect(page.controller.current()).toMatchObject({ kind: 'vault', items: [{ name: NAME, sensitivity: 'high' }] });
  });

  it('replaces an existing item with CAS on its head revision', async () => {
    const world = new FakeWorld();
    const itemId = world.ownerSet(NAME, 'old');
    world.ownerSet(NAME, 'older-still');
    const id = world.prepareWrite({ name: NAME }, { operation: 'replace' });
    const { b, page } = await openLink(world, world.formUrl(id));
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true, request: { operation: 'replace' } });
    await submit(page, SENTINEL);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'write_saved' } });
    const put = world.exchanges.find((e) => e.method === 'PUT')!;
    expect(new URL(put.url).pathname).toBe(`/v1/vaults/${world.vaultId}/items/${itemId}`);
    const record = (JSON.parse(put.requestBody) as { record: SignedRecord }).record;
    expect(record.base_revision).toBe(2);
    expect(world.itemStates.get(itemId)!.revision).toBe(3);
    expectNoValueAnywhere(world, b, page);
  });

  it('closes a create for a name that exists as already_exists', async () => {
    const world = new FakeWorld();
    world.ownerSet(NAME, 'old');
    const id = world.prepareWrite({ name: NAME });
    const { page } = await openLink(world, world.formUrl(id));
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_exists' } });
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'failed', reason: 'already_exists' });
    expect(world.exchanges.some((e) => e.method === 'PUT')).toBe(false);
    const close = world.exchanges.find((e) => e.method === 'POST' && e.url.endsWith('/close'))!;
    expect(JSON.parse(close.requestBody)).toEqual({ outcome: 'failed', reason: 'already_exists' });
  });

  it('closes a replace for a missing name as not_found', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME }, { operation: 'replace' });
    const { page } = await openLink(world, world.formUrl(id));
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_missing' } });
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'failed', reason: 'not_found' });
    expect(world.exchanges.some((e) => e.method === 'PUT')).toBe(false);
  });

  it('closes an intent this device cannot open as device_error', async () => {
    const world = new FakeWorld();
    // Sealed under another vault's seal key: the AEAD and vault binding refuse it.
    const id = world.prepareWrite({ name: NAME }, { vaultId: randomId() });
    const { page } = await openLink(world, world.formUrl(id));
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_device_error' } });
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'failed', reason: 'device_error' });
  });

  it('cancels with user_cancelled and clears the field', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    const { b, page } = await openLink(world, world.formUrl(id));
    const input = byTestId(page.root, 'write-value') as HTMLInputElement;
    input.value = SENTINEL;
    byTestId(page.root, 'write-cancel').click();
    expect(input.value).toBe('');
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'write', busy: false, notice: { code: 'write_cancelled' } }));
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'cancelled', reason: 'user_cancelled' });
    const close = world.exchanges.find((e) => e.method === 'POST' && e.url.endsWith('/close'))!;
    expect(JSON.parse(close.requestBody)).toEqual({ outcome: 'cancelled', reason: 'user_cancelled' });
    expect(world.exchanges.some((e) => e.method === 'PUT')).toBe(false);
    expectNoValueAnywhere(world, b, page);
  });

  it('reports a concurrent change as a preserved conflict branch', async () => {
    const world = new FakeWorld();
    world.ownerSet(NAME, 'old');
    const id = world.prepareWrite({ name: NAME }, { operation: 'replace' });
    const { b, page } = await openLink(world, world.formUrl(id));
    world.ownerSet(NAME, 'changed-elsewhere');
    await submit(page, SENTINEL);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_conflict' } });
    expect(byTestId(page.root, 'notice').textContent).toContain('conflict branch');
    expect(world.writeRequests.get(id)).toMatchObject({ state: 'conflict' });
    expect(world.exchanges.find((e) => e.method === 'PUT')!.status).toBe(409);
    expectNoValueAnywhere(world, b, page);
  });

  it('keeps the request open for a retry after a network failure, then completes it', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    const { b, page } = await openLink(world, world.formUrl(id));
    const fetchWorld = world.fetch;
    let offline = true;
    (world as { fetch: typeof fetch }).fetch = async (input, init) => {
      if (offline && (init?.method ?? 'GET') === 'PUT') throw new TypeError('offline');
      return fetchWorld(input, init);
    };
    await submit(page, SENTINEL);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true, notice: { code: 'network' } });
    expect(world.writeRequests.get(id)!.state).toBe('pending_user');
    offline = false;
    await submit(page, SENTINEL);
    expect(page.controller.current()).toMatchObject({ notice: { code: 'write_saved' } });
    expectNoValueAnywhere(world, b, page);
  });

  it('shows the stale-link message when the request expired before the value was sent', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    const { b, page } = await openLink(world, world.formUrl(id));
    world.writeRequests.get(id)!.expiresAt = Date.now() - 1;
    await submit(page, SENTINEL);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: false, notice: { code: 'write_unavailable' } });
    expect(world.itemStates.size).toBe(0);
    expectNoValueAnywhere(world, b, page);
  });

  it('never shows the value in an error message', async () => {
    const world = new FakeWorld();
    const id = world.prepareWrite({ name: NAME });
    const { b, page } = await openLink(world, world.formUrl(id));
    await submit(page, `\uD800${SENTINEL}`);
    expect(page.controller.current()).toMatchObject({ kind: 'write', open: true, notice: { code: 'value_too_large' } });
    expect((byTestId(page.root, 'write-value') as HTMLInputElement).value).toBe('');
    expectNoValueAnywhere(world, b, page);
  });
});
