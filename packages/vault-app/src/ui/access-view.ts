/**
 * The "Vault access" tab: members, roles, devices, key epoch, rekey state and
 * what this browser session may do. Read-only by construction: it has no
 * action that posts a membership event. Every string from the chain (account,
 * device ID) is inserted as text.
 */
import type { MembershipView } from '../sync/membership-view.js';
import { h, type Child } from './dom.js';
import { ACCESS_NOTES, CAPABILITY_LABEL, DENIED_TEXT, changeText } from './messages.js';

function shortId(id: string): string {
  return id.slice(0, 8);
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '' : `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function memberRow(a: MembershipView['accounts'][number]): HTMLElement {
  return h('li', { class: 'member', 'data-testid': 'member' }, [
    h('div', { class: 'member-head' }, [
      h('span', { class: 'name', 'data-testid': 'member-account' }, [a.account]),
      h('span', { class: `badge badge-role-${a.role}`, 'data-testid': 'member-role' }, [a.role]),
      a.isSelf ? h('span', { class: 'badge' }, ['you']) : null,
    ]),
    h('ul', { class: 'devices' }, a.devices.map((d) => h('li', { class: 'muted', 'data-testid': 'member-device' }, [
      `${d.kind === 'machine' ? 'machine' : 'device'} ${shortId(d.deviceId)}`,
      d.isThisBrowser ? ' (this browser)' : '',
    ]))),
  ]);
}

export function accessSection(view: MembershipView, verifiedAtMs: number, changes: readonly Parameters<typeof changeText>[0][], listedItemIds: ReadonlySet<string>): HTMLElement {
  const marked = view.needsRotate.filter((id) => listedItemIds.has(id)).length;
  const needsRotate: Child = marked
    ? h('p', { class: 'notice notice-error', role: 'status', 'data-testid': 'needs-rotate' }, [
      `${marked} listed item${marked > 1 ? 's' : ''} marked for rotation. ${ACCESS_NOTES.needsRotate} ${ACCESS_NOTES.noClawback}`,
    ])
    : null;
  return h('section', { class: 'access', 'aria-label': 'Vault access', 'data-testid': 'access' }, [
    changes.length
      ? h('p', { class: 'notice notice-info', role: 'status', 'data-testid': 'access-changes' }, [changes.map(changeText).join(' ')])
      : null,
    h('h2', {}, ['Vault access']),
    h('p', { class: 'meta', 'data-testid': 'access-summary' }, [
      h('span', { class: 'badge' }, [`${view.vaultKind} vault`]),
      h('span', { class: 'badge' }, [`your role: ${view.selfRole}`]),
      h('span', { class: 'badge' }, [`key epoch ${view.keyEpoch}`]),
      h('span', { class: 'badge' }, [`membership log #${view.membershipSeq}`]),
      view.removedDevices > 0 ? h('span', { class: 'badge' }, [`${view.removedDevices} removed device${view.removedDevices > 1 ? 's' : ''}`]) : null,
    ]),
    h('p', { class: 'muted', 'data-testid': 'access-verified' }, [`Verified in this browser at ${fmtTime(verifiedAtMs)}. ${ACCESS_NOTES.offline}`]),
    view.rekeyRequired
      ? h('p', { class: 'notice notice-error', role: 'status', 'data-testid': 'rekey-pending' }, [`Rekey pending. ${ACCESS_NOTES.rekey} ${ACCESS_NOTES.noClawback}`])
      : null,
    needsRotate,
    h('p', {}, [ACCESS_NOTES.membership]),
    h('h3', {}, ['Members']),
    h('ul', { class: 'members' }, view.accounts.map(memberRow)),
    h('p', { class: 'muted' }, [ACCESS_NOTES.invites]),
    h('h3', {}, ['What this browser session can do']),
    h('ul', { class: 'caps', 'data-testid': 'capabilities' }, view.capabilities.map((c) => h('li', { class: c.allowed ? 'cap cap-yes' : 'cap cap-no', 'data-testid': `cap-${c.id}` }, [
      h('span', { class: 'badge' }, [c.allowed ? 'allowed' : 'not available']),
      ` ${CAPABILITY_LABEL[c.id]}`,
      c.reason ? h('span', { class: 'muted' }, [` — ${DENIED_TEXT[c.reason]}`]) : null,
    ]))),
    h('p', { class: 'muted' }, [ACCESS_NOTES.ownerOps]),
  ]);
}
