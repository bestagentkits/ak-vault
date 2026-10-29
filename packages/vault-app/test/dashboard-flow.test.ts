// @vitest-environment happy-dom
/**
 * End to end through the real controller, views, protocol library and
 * WebCrypto keys against an in-memory ak-web and Worker: sign-in, SAS
 * enrollment, list, set, delete, and the refusals that keep values hidden and
 * tenants apart.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { b64encode, createDeviceKeys, openItem, randomBytes, randomId, type MembershipEvent } from '@ak-vault/protocol';
import { ACCOUNT, FakeWorld, ISSUER, ORIGIN } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, settle } from './helpers/dashboard-page.js';
import { deviceIdOf } from '../src/keys/webcrypto-device-keys.js';
import type { StoredDevice, WitnessedState } from '../src/keys/device-store.js';
import type { DeviceKx } from '@ak-vault/protocol';
import type { AkvClient } from '../src/sync/akv-client.js';
import { pullVault, type VaultSnapshot } from '../src/sync/vault-sync.js';

const SENTINEL = 'sentinel-value-7f3a9c1e5b';

function names(root: HTMLElement): string[] {
  return allByTestId(root, 'item-name').map((e) => e.textContent ?? '');
}

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

describe('sign-in', () => {
  it('uses PKCE S256, the CIMD client ID and the /app resource, and strips the code from the URL', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const start = await b.load();
    expect(byTestId(start.root, 'signin')).toBeTruthy();
    await start.controller.signIn();
    const auth = new URL(start.navigated[0]!);
    expect(auth.origin + auth.pathname).toBe(`${ISSUER}/oauth/authorize`);
    expect(auth.searchParams.get('client_id')).toBe(`${ORIGIN}/app/client.json`);
    expect(auth.searchParams.get('resource')).toBe(`${ORIGIN}/app`);
    expect(auth.searchParams.get('scope')).toBe('vault-app:session');
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
    expect(auth.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const page = await b.load(world.authorize(auth.href));
    expect(page.replaced).toEqual([`${ORIGIN}/app/`]);
    expect(page.controller.current().kind).toBe('join');
    expect(b.pending.value).toBeNull();
  });

  it('refuses a callback whose state differs and never redeems the code', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const page = await b.signIn({ state: b64encode(randomBytes(32)) });
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'signin_state_mismatch' } });
    expect(world.exchanges.some((e) => e.url === `${ISSUER}/oauth/token`)).toBe(false);
  });

  it('refuses a callback from another issuer (RFC 9207) or without iss', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    let page = await b.signIn({ iss: 'https://evil.example.test' });
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'signin_issuer_mismatch' } });
    world.hostile.omitIss = true;
    page = await b.signIn();
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'signin_issuer_mismatch' } });
    expect(world.exchanges.some((e) => e.url === `${ISSUER}/oauth/token`)).toBe(false);
  });

  it('refuses a replayed callback (the pending sign-in is single use)', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.load();
    await b.page!.controller.signIn();
    const cb = world.authorize(b.page!.navigated[0]!);
    expect((await b.load(cb)).controller.current().kind).toBe('join');
    expect((await b.load(cb)).controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'signin_state_mismatch' } });
  });

  it('revokes the previous grant before a new sign-in and on lock', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const page = await b.signIn();
    await page.controller.signIn();
    expect(world.revoked.length).toBe(1);
    const again = await b.load(world.authorize(page.navigated.at(-1)!));
    await again.controller.lock();
    expect(world.revoked.length).toBe(2);
    expect(again.controller.current()).toMatchObject({ kind: 'signed_out', notice: { code: 'locked' } });
  });
});

describe('clock skew', () => {
  it('says the clock is off instead of sending the user around the sign-in', async () => {
    const world = new FakeWorld();
    world.hostile.dateOffsetMs = 5 * 60_000;
    const page = await new Browser(world).load();
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: { kind: 'error', code: 'clock_skew' } });
    expect(page.root.textContent).toContain('clock');
  });

  it('turns a session the vault refuses into the clock message only while skewed', async () => {
    for (const [offset, code] of [[5 * 60_000, 'clock_skew'], [0, 'signin_required']] as const) {
      const world = new FakeWorld();
      const b = new Browser(world);
      await b.enroll();
      world.hostile.dateOffsetMs = offset;
      world.hostile.rejectProofs = true;
      const page = await b.signIn();
      expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: { kind: 'error', code } });
    }
  });

  it('tolerates a skew within a minute', async () => {
    const world = new FakeWorld();
    world.hostile.dateOffsetMs = 30_000;
    const page = await new Browser(world).load();
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: null });
  });
});

describe('enrollment', () => {
  it('shows the same SAS as the owner device and lists the vault after approval', async () => {
    const world = new FakeWorld();
    world.ownerSet('github-token', SENTINEL);
    const b = new Browser(world);
    const { page, sas, ownerSas } = await b.enroll();
    expect(sas).toMatch(/^\d{6}$/);
    expect(sas).toBe(ownerSas);
    expect(page.controller.current().kind).toBe('vault');
    expect(names(page.root)).toEqual(['github-token']);
  });

  it('keeps waiting while the owner has not approved, and refuses a device_add with another SAS', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    await page.controller.checkApproval();
    expect(page.controller.current()).toMatchObject({ kind: 'approve', notice: { code: 'enroll_not_approved' } });
    world.approve(joinCode, offer.nonceI, { wrongSas: true });
    await page.controller.checkApproval();
    expect(page.controller.current()).toMatchObject({ kind: 'approve', notice: { code: 'enroll_sas_mismatch' } });
  });

  it('refuses an offer for another vault origin or another device', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    await page.controller.submitOffer(world.offerFor(joinCode, { origin: 'https://vault.other.test' }).code);
    expect(page.controller.current()).toMatchObject({ kind: 'join', notice: { code: 'enroll_code_invalid' } });
    const other = new FakeWorld();
    await page.controller.submitOffer(other.offerFor(joinCode, { joiner: other.owner.record.device_id }).code);
    expect(page.controller.current()).toMatchObject({ kind: 'join', notice: { code: 'enroll_wrong_device' } });
    await page.controller.submitOffer('<script>alert(1)</script>');
    expect(page.controller.current()).toMatchObject({ kind: 'join', notice: { code: 'enroll_code_invalid' } });
  });

  it('refuses a vault whose chain does not start at the offered trust anchor', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode, { trustAnchor: new FakeWorld().owner.record.sign_pub });
    await page.controller.submitOffer(offer.code);
    world.approve(joinCode, offer.nonceI);
    await page.controller.checkApproval();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'vault_verification_failed' });
  });

  it('keeps one device per account: another account never sees this one', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    await b.enroll();
    world.hostile.appSub = 'acct-mallory';
    const page = await b.signIn();
    expect(page.controller.current().kind).toBe('join');
    expect([...b.devices.entries.keys()].sort()).toEqual([ACCOUNT, 'acct-mallory'].sort());
    expect(b.devices.entries.get('acct-mallory')!.enrollment).toBeNull();
  });

  it('creates one device when two tabs sign in for the first time together', async () => {
    // happy-dom has no navigator.locks, so this stands in for it: one exclusive
    // holder per name, waiters run in request order, as the Web Locks API does.
    const tails = new Map<string, Promise<unknown>>();
    const requested: string[] = [];
    const locks = {
      request: (name: string, _opts: LockOptions, cb: (lock: Lock | null) => Promise<unknown>) => {
        requested.push(name);
        const run = (tails.get(name) ?? Promise.resolve()).then(() => cb(null));
        tails.set(name, run.catch(() => undefined));
        return run;
      },
    } as unknown as Pick<LockManager, 'request'>;
    const world = new FakeWorld();
    const tab1 = new Browser(world, { locks });
    const tab2 = new Browser(world, { locks, devices: tab1.devices });
    const callbacks: URL[] = [];
    for (const tab of [tab1, tab2]) {
      const start = await tab.load();
      await start.controller.signIn();
      callbacks.push(world.authorize(start.navigated.at(-1)!));
    }
    const [p1, p2] = await Promise.all([tab1.load(callbacks[0]!), tab2.load(callbacks[1]!)]);
    const s1 = p1.controller.current();
    const s2 = p2.controller.current();
    expect(s1.kind).toBe('join');
    expect(s2.kind).toBe('join');
    expect((s1 as { deviceId: string }).deviceId).toBe((s2 as { deviceId: string }).deviceId);
    expect(tab1.devices.entries.size).toBe(1);
    expect(requested).toEqual([`akv-device:${ACCOUNT}`, `akv-device:${ACCOUNT}`]);
  });

  it('refuses a sync token minted for another account', async () => {
    const world = new FakeWorld();
    world.hostile.syncSub = 'acct-mallory';
    const page = await new Browser(world).signIn();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'token_exchange_failed' });
  });
});

describe('vault', () => {
  it('never puts a value in the DOM, device storage, a request or a response the dashboard reads in clear', async () => {
    const world = new FakeWorld();
    world.ownerSet('db-password', SENTINEL);
    const b = new Browser(world);
    const { page } = await b.enroll();
    await page.controller.set('new-secret', `${SENTINEL}-new`);
    expect(names(page.root)).toEqual(['db-password', 'new-secret']);
    expect(page.root.innerHTML).not.toContain(SENTINEL);
    expect(document.documentElement.outerHTML).not.toContain(SENTINEL);
    expect((byTestId(page.root, 'set-value') as HTMLInputElement).value).toBe('');
    for (const e of world.exchanges) {
      expect(e.requestBody, e.url).not.toContain(SENTINEL);
      expect(e.responseBody, e.url).not.toContain(SENTINEL);
    }
    for (const d of b.devices.entries.values()) expect(JSON.stringify({ ...d, keys: null })).not.toContain(SENTINEL);
    expect(JSON.stringify(b.pending.value)).not.toContain(SENTINEL);
    expect(page.root.querySelector('[data-testid="reveal"], [data-testid="copy"]')).toBeNull();
  });

  it('writes a value the owner device can read, with a name tag and the CLI metadata', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const { page } = await b.enroll();
    expect(await page.controller.set('api-key', 'v1')).toBe(true);
    const put = world.exchanges.find((e) => e.method === 'PUT')!;
    const body = JSON.parse(put.requestBody) as { record: { author: string; base_revision: number }; name_tag: { key_epoch: number; tag: string } };
    expect(body.name_tag.key_epoch).toBe(1);
    expect(body.record.base_revision).toBe(0);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'saved' } });
    const { openItem } = await import('@ak-vault/protocol');
    const entry = world.log.at(-1)!.record;
    const payload = openItem({ ...entry, vk: world.vks.get(1)!, env: entry.env }) as { name: string; value: string; meta: Record<string, unknown> };
    expect(payload.name).toBe('api-key');
    expect(payload.value).toBe('v1');
    expect(payload.meta['schema']).toBe('agentkit.secret/v1');
    expect(typeof payload.meta['created_ms']).toBe('number');
    // Exact-name search runs over the verified names in memory: no request leaves the page.
    const before = world.exchanges.length;
    await page.controller.search('api-key');
    expect(page.controller.current()).toMatchObject({ kind: 'vault', matches: [entry.item_id] });
    await page.controller.search('no-such-item');
    expect(page.controller.current()).toMatchObject({ kind: 'vault', matches: [] });
    expect(world.exchanges.length).toBe(before);
    expect(world.exchanges.some((e) => e.url.includes('/lookup'))).toBe(false);
  });

  it('keeps the value field out of the password manager and clears it on submit', async () => {
    const world = new FakeWorld();
    const { page } = await new Browser(world).enroll();
    const value = byTestId(page.root, 'set-value') as HTMLInputElement;
    expect(value.tagName).toBe('INPUT');
    expect(value.getAttribute('type')).toBe('text');
    expect(page.root.querySelector('input[type="password"]')).toBeNull();
    expect(value.classList.contains('masked')).toBe(true);
    const name = byTestId(page.root, 'set-name');
    for (const el of [value, name]) {
      expect(el.getAttribute('autocomplete')).toBe('off');
      expect(el.getAttribute('spellcheck')).toBe('false');
      expect(el.getAttribute('autocapitalize')).toBe('off');
      expect(el.hasAttribute('data-1p-ignore')).toBe(true);
      expect(el.getAttribute('data-lpignore')).toBe('true');
      expect(el.hasAttribute('data-bwignore')).toBe(true);
      expect(el.getAttribute('data-form-type')).toBe('other');
    }
    (name as HTMLInputElement).value = 'typed-name';
    value.value = SENTINEL;
    (value.form as HTMLFormElement).dispatchEvent(new Event('submit', { cancelable: true }));
    expect(value.value).toBe('');
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'saved' } }));
    expect(names(page.root)).toEqual(['typed-name']);
    expect(page.root.innerHTML).not.toContain(SENTINEL);
  });

  it('never replaces a newer verified position with an older pull that finishes last', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const b = new Browser(world);
    const { page } = await b.enroll();
    // Hold the first change-log response of the next pull until a later pull finished.
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    let holding = true;
    b.afterFetch = async (url) => {
      if (holding && url.includes('/changes')) {
        holding = false;
        await held;
      }
    };
    const older = page.controller.refresh();
    await settle(() => expect(holding).toBe(false));
    world.ownerSet('two', 'b');
    await page.controller.refresh();
    const newer = b.devices.entries.get(ACCOUNT)!.enrollment!.witnessed!;
    expect(names(page.root)).toEqual(['one', 'two']);
    release();
    await older;
    expect(b.devices.entries.get(ACCOUNT)!.enrollment!.witnessed).toEqual(newer);
    expect(names(page.root)).toEqual(['one', 'two']);
  });

  it('pulls only the new log entries after the first pull, and still sees every change', async () => {
    const world = new FakeWorld();
    for (let i = 0; i < 5; i++) world.ownerSet(`item-${i}`, 'a');
    const b = new Browser(world);
    const { page } = await b.enroll();
    const cursors = () => world.exchanges.filter((e) => e.url.includes('/changes')).map((e) => Number(new URL(e.url).searchParams.get('cursor')));
    expect(cursors()).toEqual([0]);
    world.ownerSet('item-5', 'b');
    await page.controller.refresh();
    expect(cursors()).toEqual([0, 5]);
    expect(names(page.root)).toEqual(['item-0', 'item-1', 'item-2', 'item-3', 'item-4', 'item-5']);
    // A write of this browser's own, then the refresh after it, also continues from the cursor.
    expect(await page.controller.set('item-6', SENTINEL)).toBe(true);
    expect(cursors().at(-1)).toBe(6);
    expect(names(page.root)).toContain('item-6');
    // A delete of this browser's own (a tombstone) is applied on top of the cached replay.
    const cur = page.controller.current();
    const doomed = cur.kind === 'vault' ? cur.items.find((i) => i.name === 'item-0')!.itemId : '';
    expect(await page.controller.remove(doomed)).toBe(true);
    expect(names(page.root)).not.toContain('item-0');
    expect(b.devices.entries.get(ACCOUNT)!.enrollment!.witnessed!.log_seq).toBe(world.log.length);
  });

  it('continues only from a snapshot of this same device, and replays in full for any other', async () => {
    const world = new FakeWorld();
    for (let i = 0; i < 3; i++) world.ownerSet(`item-${i}`, 'a');
    const { page } = await new Browser(world).enroll();
    // The controller's pull inputs are private; this reaches them to call the pull with a prior
    // snapshot the controller itself never passes (one recorded as another device's).
    const inner = page.controller as unknown as { client: AkvClient; kx: DeviceKx; device: StoredDevice; snapshot: VaultSnapshot };
    const cursors = () => world.exchanges.filter((e) => e.url.includes('/changes')).map((e) => Number(new URL(e.url).searchParams.get('cursor')));
    const own = inner.snapshot;
    await pullVault(inner.client, inner.device, inner.kx, own);
    expect(cursors().at(-1)).toBe(3);
    const foreign: VaultSnapshot = { ...own, self: { ...own.self, device_id: 'another-device-id' } };
    const { snapshot } = await pullVault(inner.client, inner.device, inner.kx, foreign);
    expect(cursors().at(-1)).toBe(0);
    expect(snapshot.items.map((i) => i.name)).toEqual(['item-0', 'item-1', 'item-2']);
  });

  it('replays in full when a removal learned later is fenced below the cursor, and refuses the removed device\'s later records', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const a = new Browser(world);
    const { page } = await a.enroll();
    // A second device of the account joins and writes after position 1.
    const other = new Browser(world);
    const second = await other.enroll();
    expect(await second.page.controller.set('from-second', SENTINEL)).toBe(true);
    await page.controller.refresh();
    expect(names(page.root)).toEqual(['from-second', 'one']);
    const cursor = world.log.length;
    // The owner removes the second device with a fence below what the first browser already holds.
    world.removeDevice(deviceIdOf(other.devices.entries.get(ACCOUNT)!.keys), 1);
    const before = world.exchanges.length;
    await page.controller.refresh();
    expect(world.exchanges.slice(before).filter((e) => e.url.includes('/changes')).map((e) => new URL(e.url).searchParams.get('cursor'))).toContain('0');
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'vault_verification_failed' });
    expect(cursor).toBeGreaterThan(1);
  });

  it('replays in full when a demotion learned later is fenced below the cursor, and refuses the demoted account\'s later records', async () => {
    const world = new FakeWorld({ shared: true });
    world.addMember(createDeviceKeys({ account: 'acct-bob', role: 'owner', kind: 'human' }), 'owner');
    world.ownerSet('one', 'a');
    const { page } = await new Browser(world).enroll();
    expect(await page.controller.set('from-browser', SENTINEL)).toBe(true);
    await page.controller.refresh();
    expect(names(page.root)).toEqual(['from-browser', 'one']);
    // The account is demoted with a fence below the browser's record, which it already holds.
    world.setRole(ACCOUNT, 'reader', 1);
    const before = world.exchanges.length;
    await page.controller.refresh();
    expect(world.exchanges.slice(before).filter((e) => e.url.includes('/changes')).map((e) => new URL(e.url).searchParams.get('cursor'))).toContain('0');
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'vault_verification_failed' });
  });

  it('keeps pulling incrementally past a role change it already verified', async () => {
    const world = new FakeWorld({ shared: true });
    world.addMember(createDeviceKeys({ account: 'acct-bob', role: 'reader', kind: 'human' }), 'reader');
    world.ownerSet('one', 'a');
    const { page } = await new Browser(world).enroll();
    world.ownerSet('two', 'b');
    world.setRole('acct-bob', 'editor');
    const cursorsOf = async () => {
      const before = world.exchanges.length;
      await page.controller.refresh();
      return world.exchanges.slice(before).filter((e) => e.url.includes('/changes')).map((e) => new URL(e.url).searchParams.get('cursor'));
    };
    expect(await cursorsOf()).toEqual(['1']);
    world.ownerSet('three', 'c');
    expect(await cursorsOf()).toEqual(['2']);
    // The role fence (2) now lies below the cursor: the continuation checks it against the head kept there.
    world.ownerSet('four', 'd');
    expect(await cursorsOf()).toEqual(['3']);
    expect(names(page.root)).toEqual(['four', 'one', 'three', 'two']);
  });

  it('reads membership again when the log holds a record from a rekey that landed between the two reads', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const { page } = await new Browser(world).enroll();
    world.beforeNextChanges = () => {
      world.rekey();
      world.ownerSet('rotated', 'b');
    };
    await page.controller.refresh();
    expect(page.controller.current()).not.toMatchObject({ kind: 'fatal' });
    expect(names(page.root)).toEqual(['one', 'rotated']);
  });

  it('does not let a second removal at an already seen fence hide records past it', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const a = new Browser(world);
    const { page } = await a.enroll();
    const second = new Browser(world);
    const writer = await second.enroll();
    const third = new Browser(world);
    await third.enroll();
    expect(await writer.page.controller.set('from-second', SENTINEL)).toBe(true);
    const idOf = (b: Browser) => deviceIdOf(b.devices.entries.get(ACCOUNT)!.keys);
    // The first removal fences at 1; the first browser verifies in full and learns it.
    world.removeDevice(idOf(third), 1);
    await page.controller.refresh();
    expect(names(page.root)).toEqual(['from-second', 'one']);
    // A second removal at the same fence makes the writer's record (position 2) invalid.
    world.removeDevice(idOf(second), 1);
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'vault_verification_failed' });
  });

  it('keeps pulling incrementally across a removal fenced at the current position', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const a = new Browser(world);
    const { page } = await a.enroll();
    const other = new Browser(world);
    await other.enroll();
    world.ownerSet('two', 'b');
    world.removeDevice(deviceIdOf(other.devices.entries.get(ACCOUNT)!.keys));
    const before = world.exchanges.length;
    await page.controller.refresh();
    const cursors = world.exchanges.slice(before).filter((e) => e.url.includes('/changes')).map((e) => new URL(e.url).searchParams.get('cursor'));
    expect(cursors).toEqual(['1']);
    expect(names(page.root)).toEqual(['one', 'two']);
  });

  it.each(['/membership', '/changes'])('keeps the locked screen when a pull held at %s finishes after the lock', async (held) => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const b = new Browser(world);
    const { page } = await b.enroll();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let holding = true;
    b.afterFetch = async (url) => {
      if (holding && url.includes(held)) {
        holding = false;
        await gate;
      }
    };
    const pull = page.controller.refresh();
    await settle(() => expect(holding).toBe(false));
    await page.controller.lock();
    release();
    await pull;
    expect(page.controller.current()).toMatchObject({ kind: 'signed_out', notice: { kind: 'info', code: 'locked' } });
  });

  it('refuses a server that switched to another history after another tab saved a further position on it', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    world.ownerSet('two', 'b');
    const b = new Browser(world);
    const { page } = await b.enroll();
    // The server now shows a different history from position 2 on, and a second tab verified it to position 3.
    world.log.length = 1;
    world.logHeads.length = 2;
    world.ownerSet('other-1', 'c');
    world.ownerSet('other-2', 'd');
    const stored = b.devices.entries.get(ACCOUNT)!;
    const w = stored.enrollment!.witnessed!;
    b.devices.entries.set(ACCOUNT, { ...stored, enrollment: { ...stored.enrollment!, witnessed: { ...w, log_seq: 3, log_head: world.logHeads[3]! } } });
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('refuses a server whose log shrank below the cursor of an incremental pull', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    world.ownerSet('two', 'b');
    const { page } = await new Browser(world).enroll();
    world.hostile.truncateLog = 1;
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('adopts a newer position another tab stored before it pulls again', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const tabA = new Browser(world);
    const { page: pageA } = await tabA.enroll();
    world.ownerSet('two', 'b');
    // A second tab of the same profile signs in and verifies the newer position.
    const tabB = new Browser(world, { devices: tabA.devices });
    await tabB.signIn();
    expect(tabA.devices.entries.get(ACCOUNT)!.enrollment!.witnessed!.log_seq).toBe(2);
    // The first tab still holds position 1. A server that now serves only position 1 must be refused.
    world.hostile.truncateLog = 1;
    await pageA.controller.refresh();
    expect(pageA.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('pulls again instead of showing a first view older than the position another tab stored', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const tabA = new Browser(world);
    const { page: pageA } = await tabA.enroll();
    // A second tab's first pull reads the log, then waits while the first tab stores a newer position.
    const tabB = new Browser(world, { devices: tabA.devices });
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    let holding = false;
    tabB.afterFetch = async (url) => {
      if (holding && url.includes('/changes')) {
        holding = false;
        await held;
      }
    };
    const start = await tabB.load();
    await start.controller.signIn();
    holding = true;
    const loading = tabB.load(world.authorize(start.navigated.at(-1)!));
    await settle(() => expect(holding).toBe(false));
    world.ownerSet('two', 'b');
    await pageA.controller.refresh();
    const stored = tabA.devices.entries.get(ACCOUNT)!.enrollment!.witnessed!;
    expect(stored.log_seq).toBe(2);
    release();
    const pageB = await loading;
    expect(pageB.controller.current().kind).toBe('vault');
    expect(names(pageB.root)).toEqual(['one', 'two']);
    expect(tabA.devices.entries.get(ACCOUNT)!.enrollment!.witnessed).toEqual(stored);
  });

  it('pulls again when a saved position is ahead of the view on another component', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const tabA = new Browser(world);
    const { page: pageA } = await tabA.enroll();
    const tabB = new Browser(world, { devices: tabA.devices });
    const start = await tabB.load();
    await start.controller.signIn();
    const callback = world.authorize(start.navigated.at(-1)!);
    // Tab A reads membership, then waits; the owner adds a device; tab B reads the newer membership
    // and the log, then waits; a new item lands and tab A finishes with the newer log.
    let releaseA!: () => void;
    const heldA = new Promise<void>((r) => { releaseA = r; });
    let holdA = true;
    tabA.afterFetch = async (url) => {
      if (holdA && url.includes('/membership')) {
        holdA = false;
        await heldA;
      }
    };
    let releaseB!: () => void;
    const heldB = new Promise<void>((r) => { releaseB = r; });
    let holdB = true;
    tabB.afterFetch = async (url) => {
      if (holdB && url.includes('/changes')) {
        holdB = false;
        await heldB;
      }
    };
    const refreshA = pageA.controller.refresh();
    await settle(() => expect(holdA).toBe(false));
    world.addDevice(createDeviceKeys({ account: ACCOUNT, role: 'owner', kind: 'human' }));
    const loading = tabB.load(callback);
    await settle(() => expect(holdB).toBe(false));
    world.ownerSet('two', 'b');
    releaseA();
    await refreshA;
    const stored = tabA.devices.entries.get(ACCOUNT)!.enrollment!.witnessed!;
    expect(stored.log_seq).toBe(2);
    releaseB();
    const pageB = await loading;
    expect(pageB.controller.current().kind).toBe('vault');
    expect(names(pageB.root)).toEqual(['one', 'two']);
    const merged = tabA.devices.entries.get(ACCOUNT)!.enrollment!.witnessed!;
    expect(merged.log_seq).toBe(2);
    expect(merged.membership_seq).toBeGreaterThan(stored.membership_seq);
  });

  it('raises an integrity alarm when two pulls reach the same position with different heads', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    const b = new Browser(world);
    const { page } = await b.enroll();
    const stored = b.devices.entries.get(ACCOUNT)!;
    const w = stored.enrollment!.witnessed!;
    // Another tab stored a different head at the position this pull reaches again.
    const forked: StoredDevice = { ...stored, enrollment: { ...stored.enrollment!, witnessed: { ...w, log_head: `${w.log_head.slice(0, -2)}AA` } satisfies WitnessedState } };
    b.devices.entries.set(ACCOUNT, forked);
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'fork' });
    expect(b.devices.entries.get(ACCOUNT)).toEqual(forked);
  });

  it('deletes an item with a signed tombstone after an explicit confirm', async () => {
    const world = new FakeWorld();
    world.ownerSet('old-token', SENTINEL);
    const { page } = await new Browser(world).enroll();
    byTestId(page.root, 'delete').click();
    byTestId(page.root, 'confirm-delete').click();
    await settle(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'deleted' } }));
    expect(names(page.root)).toEqual([]);
    expect(world.log.at(-1)!.record.tombstone).toBe(true);
  });

  it('reports a concurrent edit as a conflict and refreshes', async () => {
    const world = new FakeWorld();
    world.ownerSet('shared', 'a');
    const { page } = await new Browser(world).enroll();
    world.ownerSet('shared', 'b');
    expect(await page.controller.set('shared', 'c')).toBe(false);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'conflict' } });
    const item = (page.controller.current() as { items: { openConflicts: number }[] }).items[0]!;
    expect(item.openConflicts).toBe(1);
  });

  it('renders hostile names and profile text inert', async () => {
    const world = new FakeWorld();
    const xss = '<img src=x onerror="globalThis.__pwned=1">';
    world.ownerSet(xss, SENTINEL);
    const at = 1_700_000_000_123;
    world.ownerSet('profiled', SENTINEL, {
      schema: 'agentkit.secret/v1',
      profile: { description: { value: '<script>globalThis.__pwned=1</script>', by: world.owner.record.device_id, at, src: 'local' } },
    }, at);
    const { page } = await new Browser(world).enroll();
    expect(names(page.root)).toContain(xss);
    expect(page.root.querySelector('img, script, iframe, [onerror]')).toBeNull();
    expect(page.root.textContent).toContain('<script>globalThis.__pwned=1</script>');
    expect((globalThis as Record<string, unknown>)['__pwned']).toBeUndefined();
  });

  it('carries the verified profile on a write, not fields the check dropped', async () => {
    const world = new FakeWorld();
    const at = 1_700_000_000_123;
    const owner = world.owner.record.device_id;
    const field = (value: string | string[], by: string) => ({ value, by, at, src: 'local' });
    // `tags` claims another device's name, so receivers drop it; `description` is the owner's own.
    world.ownerSet('forged', 'a', { schema: 'agentkit.secret/v1', profile: { description: field('kept', owner), tags: field(['forged'], randomId()) } }, at);
    // An invalid profile (unknown key) is not verifiable at all.
    world.ownerSet('invalid', 'a', { schema: 'agentkit.secret/v1', profile: { nonsense: field('x', owner) } }, at);
    const { page } = await new Browser(world).enroll();
    const profileOf = (n: number) => {
      const record = world.log[n]!.record;
      return (openItem({ ...record, vk: world.vks.get(record.key_epoch)! }) as { meta: Record<string, unknown> }).meta['profile'] as Record<string, unknown> | undefined;
    };
    expect(await page.controller.set('forged', 'b')).toBe(true);
    expect(Object.keys(profileOf(world.log.length - 1)!)).toEqual(['description']);
    expect(await page.controller.set('invalid', 'b')).toBe(true);
    expect(profileOf(world.log.length - 1)).toBeUndefined();
  });

  it('carries no profile once any base under it was never held', async () => {
    const world = new FakeWorld();
    const at = 1_700_000_000_123;
    const owner = world.owner.record.device_id;
    const profile = { description: { value: 'unchecked', by: owner, at, src: 'local' } };
    const meta = { schema: 'agentkit.secret/v1', profile };
    const id = world.ownerSet('rotated', 'a', meta, at);
    world.rekey();
    expect(world.ownerWrite(id, 'rotated', 'b', { base: 1, ts: at + 1, meta }).status).toBe(200);
    expect(world.ownerWrite(id, 'rotated', 'c', { base: 2, ts: at + 2, meta }).status).toBe(200);
    const b = new Browser(world);
    const page = await b.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    world.approve(joinCode, offer.nonceI, { omitEpochs: [1] });
    await page.controller.checkApproval();
    expect(await page.controller.set('rotated', 'd')).toBe(true);
    const record = world.log.at(-1)!.record;
    const written = openItem({ ...record, vk: world.vks.get(record.key_epoch)! }) as { meta: Record<string, unknown> };
    expect(written.meta['profile']).toBeUndefined();
  });

  it('refuses a server that rolls the change log back below what this browser verified', async () => {
    const world = new FakeWorld();
    world.ownerSet('one', 'a');
    world.ownerSet('two', 'b');
    const { page } = await new Browser(world).enroll();
    world.hostile.truncateLog = 1;
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('refuses a membership chain that forks from the one it verified', async () => {
    const world = new FakeWorld();
    const { page } = await new Browser(world).enroll();
    world.hostile.membership = world.events.slice(0, 1) as MembershipEvent[];
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'fatal', code: 'rollback' });
  });

  it('wipes its device and shows the removed view once an owner removes it', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const { page } = await b.enroll();
    const s = page.controller.current() as { deviceId: string };
    world.removeDevice(s.deviceId);
    await page.controller.refresh();
    expect(page.controller.current().kind).toBe('removed');
    expect(b.devices.entries.size).toBe(0);
  });

  it('shows the removed view when ak-web reports the device revoked', async () => {
    const world = new FakeWorld();
    const b = new Browser(world);
    const { page } = await b.enroll();
    world.hostile.revokedDids.add((page.controller.current() as { deviceId: string }).deviceId);
    await b.signIn();
    expect(b.page!.controller.current().kind).toBe('removed');
  });
});
