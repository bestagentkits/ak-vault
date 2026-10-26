/**
 * Members screen: a read-only projection of the verified membership chain and
 * what this browser session may do. All text is fixed here or comes from the
 * verified state (short IDs, roles, item names the Secrets screen also shows);
 * nothing in it is a value, a token or a server message.
 *
 * Wording follows the guarantees: a removal ends future access only. Rotating
 * the vault key does not revoke provider keys a removed member already saw.
 */
import type { Capability, CapabilityId, CapabilityReason, MembershipView, MemberView } from '../sync/membership-view.js';
import { h, type Child } from './dom.js';

const CAPABILITY_LABEL: Record<CapabilityId, string> = {
  read_metadata: 'List and search item names and metadata',
  set_secret: 'Set a secret (write-only)',
  delete_secret: 'Delete a secret',
  reveal_value: 'Show or copy a secret value',
  invite_member: 'Invite an account to this vault',
  remove_member: 'Remove an account or device',
  change_role: 'Change a member’s role',
  rekey: 'Rekey the vault',
  enroll_device: 'Approve a new device',
};

const REASON_TEXT: Record<CapabilityReason, string> = {
  role_read_only: 'Your role in this vault is reader.',
  rekey_pending: 'Paused until an owner device rekeys the vault.',
  browser_session: 'Only an owner’s CLI device signs membership changes; the Worker refuses a browser session (ADR 0002 D1).',
  write_only_dashboard: 'The dashboard is write-only by design.',
};

const ROLE_TEXT = {
  owner: 'Owner: can write, and owner devices sign membership changes.',
  editor: 'Editor: can write items; cannot change membership.',
  reader: 'Reader: cannot write items. Like every member, a reader’s devices can decrypt every item; roles are not read boundaries.',
} as const;

const KIND_TEXT = { personal: 'personal vault', shared: 'shared vault', ci: 'CI vault' } as const;

function memberRow(m: MemberView): HTMLElement {
  const tags: Child[] = [
    h('span', { class: 'badge' }, [m.role]),
    m.you ? h('span', { class: 'badge' }, ['you']) : null,
    m.ownerAccount ? h('span', { class: 'badge' }, ['creator']) : null,
  ];
  const devices = m.devices.map((d) =>
    h('li', { 'data-testid': 'device' }, [`Device ${d.shortId} (${d.kind === 'human' ? 'person' : 'machine'})`, d.thisBrowser ? ' — this browser' : '']),
  );
  return h('li', { class: 'item', 'data-testid': 'member' }, [
    h('div', { class: 'item-head' }, [h('span', { class: 'name' }, [`Account ${m.shortId}`]), h('span', { class: 'meta' }, tags)]),
    h('ul', { class: 'devices' }, devices),
  ]);
}

function capabilityRow(c: Capability): HTMLElement {
  return h('li', { 'data-testid': 'capability', class: c.allowed ? 'cap-yes' : 'cap-no' }, [
    h('span', { class: 'badge' }, [c.allowed ? 'can' : 'cannot']),
    ` ${CAPABILITY_LABEL[c.id]}`,
    c.reason ? h('span', { class: 'muted' }, [` — ${REASON_TEXT[c.reason]}`]) : null,
  ]);
}

function keyStateSection(m: MembershipView): HTMLElement {
  const lines: Child[] = [
    h('p', { 'data-testid': 'key-state' }, [`Key epoch ${m.keyEpoch}, membership position ${m.membershipSeq}. Verified in this browser from the signed membership chain.`]),
  ];
  if (m.rekeyRequired) {
    lines.push(
      h('p', { class: 'notice notice-error', 'data-testid': 'rekey-pending' }, [
        'Rekey pending: a device or member was removed and no owner device has rekeyed yet. Writes are paused for everyone until an owner device rekeys. This browser cannot do it.',
      ]),
    );
  }
  if (m.rotation.names.length > 0 || m.rotation.unlisted > 0) {
    lines.push(
      h('div', { 'data-testid': 'needs-rotate' }, [
        h('p', {}, ['Needs rotation: these items were readable by a removed member. Rotate each one at its provider. This list does not clear when you rotate.']),
        m.rotation.names.length > 0 ? h('ul', {}, m.rotation.names.map((n) => h('li', {}, [n]))) : null,
        m.rotation.unlisted > 0 ? h('p', { class: 'muted' }, [`${m.rotation.unlisted} more flagged item(s) are not listed in this browser.`]) : null,
      ]),
    );
  }
  lines.push(
    h('p', { class: 'muted', 'data-testid': 'no-clawback' }, [
      'Once an owner device has rekeyed, a removed member no longer receives future changes. It cannot take back what they already read: rotating the vault key does not revoke provider keys that were disclosed to them. Rotate those at the provider. The vault key is shared by every member: any member device can decrypt every item, and roles do not limit reading.',
    ]),
  );
  return h('section', { 'aria-labelledby': 'h-keys' }, [h('h3', { id: 'h-keys' }, ['Keys and rotation']), ...lines]);
}

export function membersScreen(m: MembershipView): HTMLElement {
  return h('div', { 'data-testid': 'members-screen' }, [
    h('h2', {}, ['Members and access']),
    h('p', {}, [
      `This is a ${KIND_TEXT[m.vaultKind]}. Cryptographic membership is separate from your AgentKit login and license seats: an account is a member only when an owner device signed it into the vault.`,
    ]),
    h('p', { 'data-testid': 'self-role' }, [`Your role: ${m.selfRole}. ${ROLE_TEXT[m.selfRole]}`]),
    h('section', { 'aria-labelledby': 'h-members' }, [h('h3', { id: 'h-members' }, [`Members (${m.members.length})`]), h('ul', { class: 'items' }, m.members.map(memberRow))]),
    m.removedDevices.length > 0
      ? h('section', { 'aria-labelledby': 'h-removed' }, [
        h('h3', { id: 'h-removed' }, [`Removed devices (${m.removedDevices.length})`]),
        h('ul', { 'data-testid': 'removed-devices' }, m.removedDevices.map((d) => h('li', {}, [`Device ${d.shortId}, held keys up to epoch ${d.keyEpoch}`]))),
      ])
      : null,
    keyStateSection(m),
    h('section', { 'aria-labelledby': 'h-invites' }, [
      h('h3', { id: 'h-invites' }, ['Invitations']),
      h('p', { 'data-testid': 'invitations' }, [
        m.vaultKind === 'shared'
          ? 'Protocol v1 has no pending invitation: nothing waits on the server. An account becomes a member only when an owner device signs it in, and it appears above on your next refresh. Inviting, removing, changing roles and rekeying happen on an owner device, not in this browser.'
          : 'This vault has one owning account: only shared vaults can add other accounts. Devices of your account are added with an owner device (ak secrets devices approve).',
      ]),
    ]),
    h('section', { 'aria-labelledby': 'h-caps' }, [h('h3', { id: 'h-caps' }, ['What this browser can do']), h('ul', { class: 'caps' }, m.capabilities.map(capabilityRow))]),
  ]);
}
