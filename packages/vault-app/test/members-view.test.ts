// @vitest-environment happy-dom
/**
 * Members and access screen: the projection of the verified chain, the
 * capability rules of a `browser` session, and the states an owner's later
 * actions put it in (removal, rekey, rotation flags, a demoted role, offline).
 * All data is synthetic.
 */
import { describe, expect, it, vi } from 'vitest';
import { createDeviceKeys, type MembershipState } from '@ak-vault/protocol';
import { buildMembershipView, capabilitiesFor, roleCanWrite } from '../src/sync/membership-view.js';
import { newViewState, render } from '../src/ui/views.js';
import type { AppController, Screen } from '../src/app-controller.js';
import { ACCOUNT, FakeWorld } from './helpers/fake-world.js';
import { Browser, allByTestId, byTestId } from './helpers/dashboard-page.js';

const SENTINEL = 'sentinel-value-members-4d2e8b';

function device(account: string, id: string, role: 'owner' | 'editor' | 'reader', kind: 'human' | 'machine' = 'human') {
  return { device_id: id, sign_pub: 'sp', kx_pub: 'kp', account, role, kind };
}

function state(over: Partial<MembershipState> = {}): MembershipState {
  return {
    vault_id: 'v', vault_kind: 'shared', owner_account: 'acct-owner-1', trust_anchor: 'a', recovery_sign_pub: 'r', recovery_author: 'r',
    seq: 4, head: 'h', membership_epoch: 4, key_epoch: 2, rekey_required: false, needs_rotate: [], wraps_digest: null,
    members: [{ account: 'acct-owner-1', role: 'owner' }, { account: 'acct-reader-2', role: 'reader' }, { account: 'acct-editor-3', role: 'editor' }],
    devices: [device('acct-owner-1', 'dev-owner-aaaa', 'owner'), device('acct-reader-2', 'dev-reader-bbbb', 'reader'), device('acct-editor-3', 'dev-editor-cccc', 'editor'), device('acct-editor-3', 'dev-machine-dddd', 'editor', 'machine')],
    removed_device_ids: [], removals: [], role_changes: [],
    ...over,
  } as MembershipState;
}

describe('membership projection', () => {
  it('lists members by role, with devices, and marks this browser and the creator', () => {
    const v = buildMembershipView(state(), 'dev-owner-aaaa', new Map());
    expect(v.members.map((m) => [m.shortId, m.role])).toEqual([['acct-own', 'owner'], ['acct-edi', 'editor'], ['acct-rea', 'reader']]);
    expect(v.members[0]).toMatchObject({ you: true, ownerAccount: true });
    expect(v.members[0]!.devices).toEqual([{ shortId: 'dev-owne', kind: 'human', thisBrowser: true }]);
    expect(v.members[1]!.devices).toHaveLength(2);
    expect(v.selfRole).toBe('owner');
    expect(v.vaultKind).toBe('shared');
  });

  it('shows only a short prefix of any account or device ID', () => {
    const v = buildMembershipView(state(), 'dev-owner-aaaa', new Map());
    const all = JSON.stringify(v);
    expect(all).not.toContain('acct-owner-1');
    expect(all).not.toContain('dev-owner-aaaa');
  });

  it('fails closed to reader when the state does not contain this device', () => {
    const v = buildMembershipView(state(), 'dev-unknown', new Map());
    expect(v.selfRole).toBe('reader');
    expect(v.capabilities.find((c) => c.id === 'set_secret')).toMatchObject({ allowed: false, reason: 'role_read_only' });
  });

  it('reports removals and the rotation flags, naming only items this browser lists', () => {
    const v = buildMembershipView(
      state({ rekey_required: true, needs_rotate: ['i1', 'i2', 'i3'], removals: [{ device_id: 'dev-gone-eeee', sign_pub: 's', removed_seq: 3, key_epoch: 1, log_fence: 0, log_head: '', role: 'owner', kind: 'human' }] }),
      'dev-owner-aaaa',
      new Map([['i1', 'stripe-key'], ['i3', 'db-url']]),
    );
    expect(v.rekeyRequired).toBe(true);
    expect(v.removedDevices).toEqual([{ shortId: 'dev-gone', keyEpoch: 1 }]);
    expect(v.rotation).toEqual({ names: ['db-url', 'stripe-key'], unlisted: 1 });
  });

  it('never grants a membership capability to a browser session, whatever the role', () => {
    for (const role of ['owner', 'editor', 'reader'] as const) {
      for (const id of ['invite_member', 'remove_member', 'change_role', 'rekey', 'enroll_device', 'reveal_value'] as const) {
        expect(capabilitiesFor(role, false).find((c) => c.id === id)!.allowed).toBe(false);
      }
    }
  });

  it('allows writes only for owner and editor, and not while a rekey is pending', () => {
    const write = (role: 'owner' | 'editor' | 'reader', rekey: boolean) => capabilitiesFor(role, rekey).find((c) => c.id === 'set_secret')!;
    expect(roleCanWrite('reader')).toBe(false);
    expect(write('owner', false).allowed).toBe(true);
    expect(write('editor', false).allowed).toBe(true);
    expect(write('reader', false)).toMatchObject({ allowed: false, reason: 'role_read_only' });
    expect(write('owner', true)).toMatchObject({ allowed: false, reason: 'rekey_pending' });
  });
});

describe('members screen through the dashboard', () => {
  async function open(world = new FakeWorld()) {
    const b = new Browser(world);
    const { page } = await b.enroll();
    byTestId(page.root, 'tab-members').click();
    return { world, b, page };
  }

  it('shows the enrolled account, its device and the browser-session limits', async () => {
    const { page } = await open();
    expect(allByTestId(page.root, 'member')).toHaveLength(1);
    expect(byTestId(page.root, 'member').textContent).toContain(`Account ${ACCOUNT.slice(0, 8)}`);
    expect(allByTestId(page.root, 'device').some((d) => d.textContent!.includes('this browser'))).toBe(true);
    expect(byTestId(page.root, 'self-role').textContent).toContain('owner');
    const caps = allByTestId(page.root, 'capability').map((c) => c.textContent!);
    expect(caps.find((c) => c.includes('Invite an account'))).toContain('cannot');
    expect(caps.find((c) => c.includes('Rekey the vault'))).toContain('cannot');
    expect(caps.find((c) => c.includes('Set a secret'))).toContain('can');
    expect(byTestId(page.root, 'invitations').textContent).toContain('one owning account');
    expect(page.root.querySelector('[data-testid="rekey-pending"]')).toBeNull();
  });

  it('shows a pending rekey after a removal, pauses writes, and states the limits of removal', async () => {
    const world = new FakeWorld();
    const other = createDeviceKeys({ account: ACCOUNT, role: 'owner', kind: 'human' });
    world.addDevice(other);
    const { page } = await open(world);
    expect(allByTestId(page.root, 'device')).toHaveLength(3);
    world.removeDevice(other.record.device_id);
    await page.controller.refresh();
    expect(byTestId(page.root, 'rekey-pending').textContent).toContain('Writes are paused');
    expect(byTestId(page.root, 'removed-devices').textContent).toContain(other.record.device_id.slice(0, 8));
    expect(byTestId(page.root, 'no-clawback').textContent).toContain('does not revoke provider keys');
    byTestId(page.root, 'tab-secrets').click();
    expect((page.root.querySelector('form.set button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('lists items flagged for rotation after the rekey and clears the pending state', async () => {
    const world = new FakeWorld();
    const itemId = world.ownerSet('stripe-live', SENTINEL);
    const other = createDeviceKeys({ account: ACCOUNT, role: 'owner', kind: 'human' });
    world.addDevice(other);
    const { page } = await open(world);
    world.removeDevice(other.record.device_id);
    world.rekey([itemId]);
    await page.controller.refresh();
    expect(page.root.querySelector('[data-testid="rekey-pending"]')).toBeNull();
    expect(byTestId(page.root, 'key-state').textContent).toContain('Key epoch 2');
    expect(byTestId(page.root, 'needs-rotate').textContent).toContain('stripe-live');
    expect(page.root.textContent).not.toContain(SENTINEL);
  });

  it('keeps the last verified view and says so when the network is down', async () => {
    const { world, page } = await open();
    world.hostile.offline = true;
    await page.controller.refresh();
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'network' } });
    expect(allByTestId(page.root, 'member')).toHaveLength(1);
    expect(byTestId(page.root, 'notice').textContent).toContain('network request failed');
  });

  it('keeps the device and explains a refused write instead of treating it as a removal', async () => {
    const { world, b, page } = await open();
    byTestId(page.root, 'tab-secrets').click();
    world.hostile.forbidWrites = true;
    expect(await page.controller.set('some-name', 'v')).toBe(false);
    // The chain still grants the role, so the refusal is not blamed on it.
    expect(page.controller.current()).toMatchObject({ kind: 'vault', notice: { kind: 'error', code: 'write_refused' } });
    expect(b.devices.entries.size).toBe(1);
  });

  it('re-pulls after a refused write and shows a real demotion as read-only, keeping the device', async () => {
    const world = new FakeWorld({ shared: true });
    const bob = createDeviceKeys({ account: 'acct-bob', role: 'owner', kind: 'human' });
    world.addMember(bob, 'owner');
    world.ownerSet('keep-me', SENTINEL);
    const { page, b } = await open(world);
    expect(byTestId(page.root, 'invitations').textContent).toContain('no pending invitation');
    byTestId(page.root, 'tab-secrets').click();
    world.setRole(ACCOUNT, 'reader');
    world.hostile.forbidWrites = true;
    const before = world.exchanges.length;
    expect(await page.controller.set('some-name', 'v')).toBe(false);
    expect(world.exchanges.slice(before).some((e) => e.method === 'GET' && e.url.includes('/membership'))).toBe(true);
    expect(page.controller.current()).toMatchObject({ kind: 'vault', canWrite: false, notice: { code: 'role_forbidden' } });
    expect(byTestId(page.root, 'read-only')).toBeTruthy();
    expect((page.root.querySelector('form.set button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
    expect((byTestId(page.root, 'delete') as HTMLButtonElement).disabled).toBe(true);
    expect(b.devices.entries.size).toBe(1);
    byTestId(page.root, 'tab-members').click();
    expect(byTestId(page.root, 'self-role').textContent).toContain('reader');
    expect(byTestId(page.root, 'no-clawback').textContent).toContain('roles do not limit reading');
  });

  it('keeps focus on the pressed tab and marks it pressed', async () => {
    const { page } = await open();
    const tab = byTestId(page.root, 'tab-members');
    expect(tab.getAttribute('aria-pressed')).toBe('true');
    expect(document.activeElement).toBe(tab);
  });

  it('still shows the removed view when the refused write was because the device was removed', async () => {
    const { world, b, page } = await open();
    const s = page.controller.current() as { deviceId: string };
    world.removeDevice(s.deviceId);
    world.hostile.forbidWrites = true;
    expect(await page.controller.set('some-name', 'v')).toBe(false);
    expect(page.controller.current().kind).toBe('removed');
    expect(b.devices.entries.size).toBe(0);
  });

  it('puts a reader in read-only mode: no save, no delete, and a plain explanation', async () => {
    const world = new FakeWorld();
    world.ownerSet('only-name', SENTINEL);
    const { page } = await open(world);
    const cur = page.controller.current() as Extract<Screen, { kind: 'vault' }>;
    const reader = buildMembershipView({ ...world.state(), members: [{ account: ACCOUNT, role: 'reader' }], devices: world.state().devices.map((d) => ({ ...d, role: 'reader' as const })) }, cur.deviceId, new Map());
    const root = document.createElement('div');
    document.body.appendChild(root);
    const vs = newViewState();
    const again = (): void => render(root, {} as AppController, { ...cur, canWrite: false, membership: reader }, vs, again);
    again();
    expect(byTestId(root, 'read-only')).toBeTruthy();
    expect((root.querySelector('form.set button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
    expect((byTestId(root, 'delete') as HTMLButtonElement).disabled).toBe(true);
    byTestId(root, 'tab-members').click();
    expect(byTestId(root, 'self-role').textContent).toContain('reader');
  });

  it('writes nothing about membership to the console, and no request carries a membership event from the browser', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
    const { world, page } = await open();
    await page.controller.refresh();
    for (const s of spies) {
      expect(s.mock.calls).toEqual([]);
      s.mockRestore();
    }
    expect(world.exchanges.filter((e) => e.method !== 'GET' && e.url.includes('/membership'))).toEqual([]);
  });
});
