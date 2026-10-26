/**
 * Screens. Every string from an item, a profile or a code is inserted as text.
 * Values are write-only: the value field is a CSS-masked text input (never a
 * password input, so no password manager offers to save it) with autofill,
 * spellcheck and manager capture off, cleared on submit, and no screen has a
 * reveal or copy action.
 */
import type { AppController, Notice, Screen } from '../app-controller.js';
import type { ItemView } from '../sync/vault-sync.js';
import { h, replaceChildren, type Child } from './dom.js';
import { messageFor } from './messages.js';
import { rotationMetaChips, rotationPanel, rotationSummary } from './rotation-view.js';

/** Keep the browser and password managers from storing, suggesting or correcting a field. */
export const NO_CAPTURE = {
  autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off',
  'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other',
} as const;

/** View-local state that survives a re-render (never a value). */
export interface ViewState {
  filter: string;
  confirmDelete: string | null;
  /** Item whose rotation panel is open. */
  rotating: string | null;
}

export function newViewState(): ViewState {
  return { filter: '', confirmDelete: null, rotating: null };
}

function noticeEl(notice: Notice | null): Child {
  if (!notice) return null;
  return h('p', { class: `notice notice-${notice.kind}`, role: notice.kind === 'error' ? 'alert' : 'status', 'data-testid': 'notice' }, [messageFor(notice.code)]);
}

function shortId(deviceId: string): string {
  return deviceId.slice(0, 8);
}

function header(c: AppController, deviceId: string | null): HTMLElement {
  return h('header', { class: 'bar' }, [
    h('h1', {}, ['AgentKit Vault']),
    deviceId ? h('span', { class: 'device', title: 'This browser’s device ID' }, [`Device ${shortId(deviceId)}`]) : null,
    deviceId ? h('button', { type: 'button', class: 'secondary', 'data-testid': 'lock' }, ['Lock'], { click: () => void c.lock('locked') }) : null,
  ]);
}

function signedOut(c: AppController, notice: Notice | null): HTMLElement[] {
  return [
    header(c, null),
    h('main', {}, [
      noticeEl(notice),
      h('p', {}, ['Sign in with your AgentKit account. This browser is a device of your vault: it encrypts and signs locally and never shows a value.']),
      h('button', { type: 'button', 'data-testid': 'signin' }, ['Sign in'], { click: () => void c.signIn() }),
    ]),
  ];
}

function joinScreen(c: AppController, s: Extract<Screen, { kind: 'join' }>): HTMLElement[] {
  const offer = h('textarea', { id: 'offer', name: 'offer', rows: '4', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', required: true, 'data-testid': 'offer-input' }) as HTMLTextAreaElement;
  return [
    header(c, s.deviceId),
    h('main', {}, [
      noticeEl(s.notice),
      h('h2', {}, ['Add this browser to your vault']),
      h('ol', {}, [
        h('li', {}, ['On a device that already owns the vault, run ', h('code', {}, ['ak secrets devices approve <join code>']), ' with this join code:']),
      ]),
      h('pre', { class: 'code', 'data-testid': 'join-code' }, [s.joinCode]),
      h('form', {}, [
        h('label', { for: 'offer' }, ['Paste the offer code it prints:']),
        offer,
        h('button', { type: 'submit' }, ['Continue']),
      ], {
        submit: (ev) => {
          ev.preventDefault();
          void c.submitOffer(offer.value);
        },
      }),
    ]),
  ];
}

function approveScreen(c: AppController, s: Extract<Screen, { kind: 'approve' }>): HTMLElement[] {
  const digits = `${s.sas.slice(0, 3)} ${s.sas.slice(3)}`;
  return [
    header(c, s.deviceId),
    h('main', {}, [
      noticeEl(s.notice),
      h('h2', {}, ['Compare this code']),
      h('p', {}, ['Approve on the owner device only if it shows exactly this code. If it differs, do not approve.']),
      h('p', { class: 'sas', 'aria-label': `Verification code ${s.sas.split('').join(' ')}`, 'data-testid': 'sas' }, [digits]),
      h('div', { class: 'row' }, [
        h('button', { type: 'button', 'data-testid': 'check-approval' }, ['I approved it, continue'], { click: () => void c.checkApproval() }),
        h('button', { type: 'button', class: 'secondary' }, ['Start over'], { click: () => void c.restartEnrollment() }),
      ]),
    ]),
  ];
}

function fmtDate(ms: number | null): string {
  if (ms === null) return '';
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

function matchesFilter(item: ItemView, filter: string): boolean {
  if (!filter) return true;
  const f = filter.toLowerCase();
  const fields = [item.name, item.creator ?? '', ...item.profile.flatMap((p) => (Array.isArray(p.value) ? p.value : [p.value]))];
  return fields.some((t) => t.toLowerCase().includes(f));
}

function itemRow(c: AppController, item: ItemView, vs: ViewState, rerender: () => void, busy: boolean, rekeyRequired: boolean, nowMs: number): HTMLElement {
  const confirming = vs.confirmDelete === item.itemId;
  const meta: Child[] = [
    h('span', { class: `badge badge-${item.sensitivity}` }, [item.sensitivity === 'high' ? 'high sensitivity' : 'normal']),
    item.createdMs !== null ? h('span', {}, [`created ${fmtDate(item.createdMs)}`]) : null,
    item.rotatedMs !== null ? h('span', {}, [`rotated ${fmtDate(item.rotatedMs)}`]) : null,
    ...rotationMetaChips(item, nowMs),
    item.creator ? h('span', {}, [`by ${item.creator}`]) : null,
    item.rotateTtlDays !== null ? h('span', {}, [`rotate every ${item.rotateTtlDays} days`]) : null,
    item.openConflicts > 0 ? h('span', { class: 'badge badge-conflict' }, [`${item.openConflicts} unresolved conflict${item.openConflicts > 1 ? 's' : ''}`]) : null,
  ];
  const profile = item.profile.length
    ? h('dl', { class: 'profile' }, item.profile.flatMap((p) => [
      h('dt', {}, [p.key.replace(/_/g, ' ')]),
      h('dd', {}, [Array.isArray(p.value) ? p.value.join(', ') : p.value, h('span', { class: 'origin', title: 'Where this field came from' }, [` (${p.origin})`])]),
    ]))
    : null;
  const actions = confirming
    ? h('div', { class: 'row' }, [
      h('button', { type: 'button', class: 'danger', disabled: busy, 'data-testid': 'confirm-delete' }, ['Delete for every device'], {
        click: () => {
          vs.confirmDelete = null;
          void c.remove(item.itemId);
        },
      }),
      h('button', { type: 'button', class: 'secondary' }, ['Cancel'], { click: () => { vs.confirmDelete = null; rerender(); } }),
    ])
    : h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'delete' }, ['Delete'], { click: () => { vs.confirmDelete = item.itemId; rerender(); } });
  const rotating = vs.rotating === item.itemId;
  const toggle = h('button', { type: 'button', class: 'secondary', 'aria-expanded': rotating ? 'true' : 'false', 'data-testid': 'rotate-open' }, [rotating ? 'Hide rotation' : 'Rotate'], {
    click: () => { vs.rotating = rotating ? null : item.itemId; rerender(); },
  });
  return h('li', { class: 'item', 'data-testid': 'item' }, [
    h('div', { class: 'item-head' }, [h('span', { class: 'name', 'data-testid': 'item-name' }, [item.name]), h('div', { class: 'row' }, [toggle, actions])]),
    h('div', { class: 'meta' }, meta),
    profile,
    rotating ? rotationPanel(c, item, busy, rekeyRequired, nowMs, () => { vs.rotating = null; rerender(); }) : null,
  ]);
}

function vaultScreen(c: AppController, s: Extract<Screen, { kind: 'vault' }>, vs: ViewState, rerender: () => void): HTMLElement[] {
  const nameInput = h('input', { id: 'set-name', name: 'name', type: 'text', maxlength: '4096', required: true, 'data-testid': 'set-name', ...NO_CAPTURE }) as HTMLInputElement;
  // A plain-text control masked by CSS, never type=password: a password field
  // beside a name field reads as a login form and invites "save password".
  const valueInput = h('input', { id: 'set-value', type: 'text', class: 'masked', required: true, 'data-testid': 'set-value', ...NO_CAPTURE }) as HTMLInputElement;
  const filterInput = h('input', { id: 'filter', type: 'search', autocomplete: 'off', spellcheck: 'false', placeholder: 'Filter by name or metadata', 'data-testid': 'filter' }) as HTMLInputElement;
  filterInput.value = vs.filter;
  filterInput.addEventListener('input', () => {
    vs.filter = filterInput.value;
    rerender();
    const again = document.getElementById('filter') as HTMLInputElement | null;
    again?.focus();
    again?.setSelectionRange(again.value.length, again.value.length);
  });

  const shown = s.items.filter((i) => (s.matches ? s.matches.includes(i.itemId) : true) && matchesFilter(i, vs.filter));
  const setForm = h('form', { class: 'set', 'aria-busy': s.busy ? 'true' : 'false' }, [
    h('h2', {}, ['Set a secret']),
    h('label', { for: 'set-name' }, ['Name']),
    nameInput,
    h('label', { for: 'set-value' }, ['Value (write-only: it is encrypted here and never shown again)']),
    valueInput,
    h('button', { type: 'submit', disabled: s.busy || s.rekeyRequired }, ['Save']),
  ], {
    submit: (ev) => {
      ev.preventDefault();
      const name = nameInput.value;
      const value = valueInput.value;
      // Clear the field before anything else so the value does not linger in the DOM.
      valueInput.value = '';
      void c.set(name, value);
    },
  });

  return [
    header(c, s.deviceId),
    h('main', {}, [
      noticeEl(s.notice),
      s.rekeyRequired ? h('p', { class: 'notice notice-error', role: 'status' }, [messageFor('rekey_required')]) : null,
      setForm,
      rotationSummary(s.items, s.keyEpoch, s.rekeyRequired, s.nowMs),
      h('section', {}, [
        h('div', { class: 'row' }, [
          filterInput,
          h('button', { type: 'button', class: 'secondary', title: 'Find the item with exactly this name', 'data-testid': 'exact' }, ['Exact name'], {
            click: () => void c.search(filterInput.value),
          }),
          s.matches ? h('button', { type: 'button', class: 'secondary' }, ['Show all'], { click: () => { vs.filter = ''; void c.search(''); } }) : null,
          h('button', { type: 'button', class: 'secondary', disabled: s.busy, 'data-testid': 'refresh' }, ['Refresh'], { click: () => void c.refresh() }),
        ]),
        h('p', { class: 'count', 'aria-live': 'polite' }, [`${shown.length} of ${s.items.length} items`]),
        h('ul', { class: 'items' }, shown.map((i) => itemRow(c, i, vs, rerender, s.busy, s.rekeyRequired, s.nowMs))),
        s.unreadable > 0 ? h('p', { class: 'muted' }, [`${s.unreadable} item(s) use a key this browser was never given.`]) : null,
        s.hidden > 0 ? h('p', { class: 'muted' }, [`${s.hidden} item(s) are policies or other kinds the dashboard does not list.`]) : null,
      ]),
    ]),
  ];
}

export function render(root: Element, c: AppController, screen: Screen, vs: ViewState, rerender: () => void): void {
  let nodes: HTMLElement[];
  switch (screen.kind) {
    case 'loading':
      nodes = [h('main', { 'aria-busy': 'true' }, [h('p', {}, ['Loading…'])])];
      break;
    case 'fatal':
      nodes = [header(c, null), h('main', {}, [h('p', { class: 'notice notice-error', role: 'alert', 'data-testid': 'notice' }, [messageFor(screen.code)]),
        h('button', { type: 'button' }, ['Sign in again'], { click: () => void c.signIn() })])];
      break;
    case 'signed_out':
      nodes = signedOut(c, screen.notice);
      break;
    case 'join':
      nodes = joinScreen(c, screen);
      break;
    case 'approve':
      nodes = approveScreen(c, screen);
      break;
    case 'vault':
      nodes = vaultScreen(c, screen, vs, rerender);
      break;
    case 'removed':
      nodes = [header(c, null), h('main', {}, [
        h('p', { class: 'notice notice-error', role: 'alert', 'data-testid': 'notice' }, [messageFor('device_removed')]),
        h('p', {}, ['Its device key was deleted from this browser. To use the dashboard again, sign in and enroll it as a new device.']),
        h('button', { type: 'button' }, ['Sign in'], { click: () => void c.signIn() }),
      ])];
      break;
  }
  replaceChildren(root, ...nodes);
}
