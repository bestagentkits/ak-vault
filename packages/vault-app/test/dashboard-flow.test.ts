// @vitest-environment happy-dom
/**
 * End to end through the real controller, views, protocol library and
 * WebCrypto keys against an in-memory ak-web and Worker: sign-in, SAS
 * enrollment, list, set, delete, and the refusals that keep values hidden and
 * tenants apart.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { b64encode, randomBytes, type MembershipEvent } from '@ak-vault/protocol';
import { ACCOUNT, FakeWorld, ISSUER, ORIGIN } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId } from './helpers/dashboard-page.js';

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
    expect(byTestId(page.root, 'set-value').getAttribute('type')).toBe('password');
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
    // Exact-name lookup goes through the blind index.
    await page.controller.search('api-key');
    expect(page.controller.current()).toMatchObject({ kind: 'vault', matches: [entry.item_id] });
    expect(world.exchanges.some((e) => e.url.includes('/lookup?tag='))).toBe(true);
  });

  it('deletes an item with a signed tombstone after an explicit confirm', async () => {
    const world = new FakeWorld();
    world.ownerSet('old-token', SENTINEL);
    const { page } = await new Browser(world).enroll();
    byTestId(page.root, 'delete').click();
    byTestId(page.root, 'confirm-delete').click();
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'deleted' } }));
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
