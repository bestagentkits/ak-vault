// @vitest-environment happy-dom
/**
 * The "Vault access" tab through the real controller and views against an
 * in-memory vault: members, roles, devices, epochs, rekey and needs-rotate
 * states, the capability list, and the cases that must not mislead (stale role,
 * concurrent removal, offline, hostile account text). All data is synthetic.
 */
import { createDeviceKeys, type MembershipState } from '@ak-vault/protocol';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { diffAccess, membershipViewOf } from '../src/sync/membership-view.js';
import { ACCOUNT, FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId, type Page } from './helpers/dashboard-page.js';

let consoleSpies: ReturnType<typeof vi.spyOn>[] = [];
beforeEach(() => {
  consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
});
afterEach(() => {
  for (const s of consoleSpies) {
    expect(s.mock.calls).toEqual([]);
    s.mockRestore();
  }
});

async function openAccess(world: FakeWorld): Promise<{ b: Browser; page: Page }> {
  const b = new Browser(world);
  const { page } = await b.enroll();
  byTestId(page.root, 'tab-access').click();
  return { b, page };
}

function text(root: HTMLElement, id: string): string {
  return byTestId(root, id).textContent ?? '';
}

describe('vault access tab', () => {
  it('shows a personal vault: own role, epochs, this browser, and no owner operation', async () => {
    const world = new FakeWorld('personal');
    const { page } = await openAccess(world);
    expect(text(page.root, 'access-summary')).toContain('personal vault');
    expect(text(page.root, 'access-summary')).toContain('your role: owner');
    expect(text(page.root, 'access-summary')).toContain('key epoch 1');
    expect(allByTestId(page.root, 'member')).toHaveLength(1);
    expect(text(page.root, 'member')).toContain('you');
    expect(text(page.root, 'member')).toContain('(this browser)');
    expect(text(page.root, 'cap-view_access')).toContain('allowed');
    expect(text(page.root, 'cap-write_secrets')).toContain('allowed');
    for (const id of ['invite_member', 'change_role', 'remove_member', 'remove_device', 'rekey']) {
      expect(text(page.root, `cap-${id}`), id).toContain('not available');
    }
    expect(text(page.root, 'cap-invite_member')).toContain('personal vault');
    // No signing affordance exists: the tab has no button except the two tabs, Lock and Refresh.
    expect(page.root.querySelectorAll('[data-testid="access"] button')).toHaveLength(0);
  });

  it('lists a shared vault with roles, devices and a plain statement that licenses do not create members', async () => {
    const world = new FakeWorld('shared');
    world.addMember('acct-editor', 'editor');
    world.addMember('acct-reader', 'reader');
    const { page } = await openAccess(world);
    expect(allByTestId(page.root, 'member-role').map((e) => e.textContent)).toEqual(['owner', 'editor', 'reader']);
    expect(allByTestId(page.root, 'member-account').map((e) => e.textContent)).toEqual([ACCOUNT, 'acct-editor', 'acct-reader']);
    expect(text(page.root, 'access-summary')).toContain('shared vault');
    expect(page.root.textContent).toContain('license seat never makes someone a vault member');
    expect(page.root.textContent).toContain('no pending invitations to show');
    expect(text(page.root, 'cap-invite_member')).toContain('owner device');
  });

  it('inserts hostile account text as text, never as markup', async () => {
    const world = new FakeWorld('shared');
    world.addMember('<img src=x onerror=alert(1)>', 'editor');
    const { page } = await openAccess(world);
    expect(page.root.querySelector('img')).toBeNull();
    expect(allByTestId(page.root, 'member-account').map((e) => e.textContent)).toContain('<img src=x onerror=alert(1)>');
  });

  it('makes no extra request and posts no membership event from the tab', async () => {
    const world = new FakeWorld('shared');
    const b = new Browser(world);
    const { page } = await b.enroll();
    const before = world.exchanges.length;
    byTestId(page.root, 'tab-access').click();
    byTestId(page.root, 'tab-secrets').click();
    byTestId(page.root, 'tab-access').click();
    expect(world.exchanges.length).toBe(before);
    expect(world.exchanges.filter((e) => e.method !== 'GET' && /\/membership|\/recovery|\/seal-key/.test(e.url))).toEqual([]);
  });

  it('re-verifies on refresh and keeps showing the verification time', async () => {
    const world = new FakeWorld('shared');
    const { page } = await openAccess(world);
    await page.controller.refresh();
    expect(text(page.root, 'access-verified')).toContain('Verified in this browser');
  });
});

describe('removal, rekey and rotation', () => {
  it('explains a pending rekey, pauses writes, and makes no retroactive promise', async () => {
    const world = new FakeWorld('shared');
    world.addMember('acct-bob', 'editor');
    const { page } = await openAccess(world);
    world.removeMember('acct-bob');
    await page.controller.refresh();
    expect(allByTestId(page.root, 'member')).toHaveLength(1);
    expect(text(page.root, 'access-changes')).toContain('A member was removed');
    expect(text(page.root, 'access-changes')).toContain('needs a rekey');
    expect(text(page.root, 'rekey-pending')).toContain('does not take back anything a removed member already read');
    expect(text(page.root, 'cap-write_secrets')).toContain('Paused until an owner device rekeys');
    expect(text(page.root, 'access-summary')).toContain('1 removed device');
    byTestId(page.root, 'tab-secrets').click();
    expect((page.root.querySelector('form.set button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('marks needs-rotate items after the rekey and clears the pending banner', async () => {
    const world = new FakeWorld('shared');
    world.addMember('acct-bob', 'editor');
    const itemId = world.ownerSet('PROVIDER_API_KEY', 'synthetic-value');
    const { page } = await openAccess(world);
    world.removeMember('acct-bob');
    world.rekey([itemId]);
    await page.controller.refresh();
    expect(text(page.root, 'cap-write_secrets')).toContain('allowed');
    expect(page.root.querySelector('[data-testid="rekey-pending"]')).toBeNull();
    expect(text(page.root, 'needs-rotate')).toContain('1 listed item marked');
    expect(text(page.root, 'needs-rotate')).toContain('stay valid until you rotate them at the provider');
    expect(text(page.root, 'access-summary')).toContain('key epoch 2');
    byTestId(page.root, 'tab-secrets').click();
    expect(byTestId(page.root, 'item-needs-rotate').textContent).toBe('needs rotation');
  });
});

describe('stale and concurrent states', () => {
  it('a demoted account sees a fixed explanation and a read-only dashboard, and keeps its device', async () => {
    const world = new FakeWorld('shared');
    const bob = world.addMember('acct-bob', 'owner');
    const { b, page } = await openAccess(world);
    byTestId(page.root, 'tab-secrets').click();
    expect(page.root.querySelector('form.set')).not.toBeNull();
    // Another owner demotes this account after the page's last pull.
    world.actor = bob;
    world.setRole(ACCOUNT, 'reader');
    const form = page.root.querySelector('form.set') as HTMLFormElement;
    (form.querySelector('#set-name') as HTMLInputElement).value = 'SOME_NAME';
    (form.querySelector('#set-value') as HTMLInputElement).value = 'synthetic-value';
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await vi.waitFor(() => expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { code: 'role_forbidden' } }));
    expect(page.root.querySelector('form.set')).toBeNull();
    expect(text(page.root, 'read-only')).toContain('reader');
    expect(page.root.querySelector('[data-testid="delete"]')).toBeNull();
    byTestId(page.root, 'tab-access').click();
    expect(text(page.root, 'access-changes')).toContain('Your role changed from owner to reader');
    expect(text(page.root, 'cap-write_secrets')).toContain('Your role is reader');
    expect(await b.devices.get(ACCOUNT)).not.toBeNull();
    // Nothing was written to the vault.
    expect(world.log).toHaveLength(0);
  });

  it('a concurrent removal of this account ends at the removed screen and wipes the device key', async () => {
    const world = new FakeWorld('shared');
    const bob = world.addMember('acct-bob', 'owner');
    const { b, page } = await openAccess(world);
    world.actor = bob;
    world.removeMember(ACCOUNT);
    await page.controller.refresh();
    expect(page.controller.current().kind).toBe('removed');
    expect(await b.devices.get(ACCOUNT)).toBeNull();
  });

  it('a write after this account was removed ends at the removed screen and wipes the device key', async () => {
    const world = new FakeWorld('shared');
    const bob = world.addMember('acct-bob', 'owner');
    const { b, page } = await openAccess(world);
    byTestId(page.root, 'tab-secrets').click();
    world.actor = bob;
    world.removeMember(ACCOUNT);
    const form = page.root.querySelector('form.set') as HTMLFormElement;
    (form.querySelector('#set-name') as HTMLInputElement).value = 'SOME_NAME';
    (form.querySelector('#set-value') as HTMLInputElement).value = 'synthetic-value';
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    await vi.waitFor(() => expect(page.controller.current().kind).toBe('removed'));
    expect(await b.devices.get(ACCOUNT)).toBeNull();
    expect(world.log).toHaveLength(0);
  });

  it('offline: keeps the last verified membership with its time and a network notice', async () => {
    const world = new FakeWorld('shared');
    world.addMember('acct-editor', 'editor');
    const { b, page } = await openAccess(world);
    b.afterFetch = async () => {
      throw new TypeError('offline');
    };
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'network' } });
    expect(allByTestId(page.root, 'member')).toHaveLength(2);
    expect(text(page.root, 'access-verified')).toContain('last membership this browser verified');
  });

  it('a member added concurrently shows up with a change notice', async () => {
    const world = new FakeWorld('shared');
    const { page } = await openAccess(world);
    world.addMember('acct-new', 'editor');
    await page.controller.refresh();
    expect(text(page.root, 'access-changes')).toContain('A member was added');
    expect(allByTestId(page.root, 'member')).toHaveLength(2);
  });

  it('does not log account names or ids', async () => {
    const world = new FakeWorld('shared');
    world.addMember('acct-editor', 'editor');
    await openAccess(world);
    for (const s of consoleSpies) expect(s.mock.calls).toEqual([]);
  });
});

describe('membershipViewOf and diffAccess', () => {
  function state(overrides: Partial<MembershipState> = {}): { st: MembershipState; selfId: string } {
    const self = createDeviceKeys({ account: 'a', role: 'owner', kind: 'human' });
    const st: MembershipState = {
      vault_id: 'v', vault_kind: 'shared', owner_account: 'a', trust_anchor: '', recovery_sign_pub: '', recovery_author: '', seq: 3, head: '',
      membership_epoch: 3, key_epoch: 2, rekey_required: false, needs_rotate: [], wraps_digest: null,
      members: [{ account: 'a', role: 'owner' }], devices: [self.record], removed_device_ids: [], removals: [], ...overrides,
    };
    return { st, selfId: self.record.device_id };
  }

  it('refuses a view for a device that is not in the verified chain', () => {
    expect(() => membershipViewOf(state().st, 'nope')).toThrow();
  });

  it('orders owners before editors before readers and counts devices per account', () => {
    const { st, selfId } = state();
    const rd = createDeviceKeys({ account: 'z', role: 'reader', kind: 'human' });
    const ed = createDeviceKeys({ account: 'b', role: 'editor', kind: 'machine' });
    st.members.push({ account: 'z', role: 'reader' }, { account: 'b', role: 'editor' });
    st.devices.push(rd.record, ed.record);
    const v = membershipViewOf(st, selfId);
    expect(v.accounts.map((a) => a.role)).toEqual(['owner', 'editor', 'reader']);
    expect(v.accounts[1]!.devices[0]!.kind).toBe('machine');
    expect(v.canWrite).toBe(true);
  });

  it('a reader view cannot write and says why', () => {
    const { st, selfId } = state({ members: [{ account: 'a', role: 'reader' }] });
    st.devices[0] = { ...st.devices[0]!, role: 'reader' };
    const v = membershipViewOf(st, selfId);
    expect(v.canWrite).toBe(false);
    expect(v.capabilities.find((c) => c.id === 'write_secrets')).toEqual({ id: 'write_secrets', allowed: false, reason: 'role' });
  });

  it('diffs role, membership and rekey changes', () => {
    const a = state();
    const before = membershipViewOf(a.st, a.selfId);
    const next = membershipViewOf({ ...a.st, rekey_required: true, members: [{ account: 'a', role: 'owner' }, { account: 'q', role: 'editor' }] }, a.selfId);
    expect(diffAccess(before, next).map((c) => c.kind)).toEqual(['member_added', 'rekey_started']);
    expect(diffAccess(next, before).map((c) => c.kind)).toEqual(['member_removed', 'rekey_done']);
    expect(diffAccess(before, before)).toEqual([]);
  });
});
