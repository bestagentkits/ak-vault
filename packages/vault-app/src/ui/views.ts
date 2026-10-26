/**
 * Screens. Every string from an item, a profile or a code is inserted as text.
 * Values are write-only: the value field is a CSS-masked text input (never a
 * password input, so no password manager offers to save it) with autofill,
 * spellcheck and manager capture off, cleared on submit, and no screen has a
 * reveal or copy action.
 */
import type { AppController, Notice, Screen } from '../app-controller.js';
import type { EntryReadability, HistoryEntry, ItemHistory, RestoreBlock } from '../sync/item-history.js';
import type { ItemView } from '../sync/vault-sync.js';
import { h, replaceChildren, type Child } from './dom.js';
import { messageFor } from './messages.js';

/** Keep the browser and password managers from storing, suggesting or correcting a field. */
export const NO_CAPTURE = {
  autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off',
  'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other',
} as const;

/** View-local state that survives a re-render (never a value). */
export interface ViewState {
  filter: string;
  confirmDelete: string | null;
  /** Log position of the revision awaiting a restore confirmation. */
  confirmRestore: number | null;
  /** `current` or a conflict ID awaiting a settle confirmation. */
  confirmSettle: string | null;
  /** How many history entries are listed. */
  historyShown: number;
}

export const HISTORY_PAGE = 20;

export function newViewState(): ViewState {
  return { filter: '', confirmDelete: null, confirmRestore: null, confirmSettle: null, historyShown: HISTORY_PAGE };
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

function itemRow(c: AppController, item: ItemView, vs: ViewState, rerender: () => void, busy: boolean): HTMLElement {
  const confirming = vs.confirmDelete === item.itemId;
  const meta: Child[] = [
    h('span', { class: `badge badge-${item.sensitivity}` }, [item.sensitivity === 'high' ? 'high sensitivity' : 'normal']),
    item.createdMs !== null ? h('span', {}, [`created ${fmtDate(item.createdMs)}`]) : null,
    item.rotatedMs !== null ? h('span', {}, [`rotated ${fmtDate(item.rotatedMs)}`]) : null,
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
    : h('div', { class: 'row' }, [
      h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'history' }, ['History'], { click: () => { resetHistoryState(vs); void c.openHistory(item.itemId); } }),
      h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'delete' }, ['Delete'], { click: () => { vs.confirmDelete = item.itemId; rerender(); } }),
    ]);
  return h('li', { class: 'item', 'data-testid': 'item' }, [
    h('div', { class: 'item-head' }, [h('span', { class: 'name', 'data-testid': 'item-name' }, [item.name]), actions]),
    h('div', { class: 'meta' }, meta),
    profile,
  ]);
}

function resetHistoryState(vs: ViewState): void {
  vs.confirmRestore = null;
  vs.confirmSettle = null;
  vs.historyShown = HISTORY_PAGE;
}

function fmtDateTime(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? 'unknown time' : `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

const READABILITY: Record<EntryReadability, string> = {
  readable: 'verified in this browser',
  no_key: 'unavailable: this browser was never given the key for this epoch',
  unverified: 'unverified: the ciphertext did not authenticate',
};

const RESTORE_BLOCK: Record<RestoreBlock, string> = {
  current: 'current revision',
  deletion: 'deletion',
  before_deletion: 'written before the item was deleted, so it is not offered',
  no_key: 'cannot restore: key epoch unavailable here',
  unverified: 'cannot restore: not verified',
};

function entryLabel(e: HistoryEntry): string {
  if (e.kind === 'conflict') return e.tombstone ? 'conflicting delete (branch)' : 'conflicting write (branch)';
  return e.tombstone ? `revision ${e.revision}: deleted` : `revision ${e.revision}`;
}

function entryRow(c: AppController, e: HistoryEntry, canWrite: boolean, busy: boolean, vs: ViewState, rerender: () => void): HTMLElement {
  const status: Child[] = [
    h('span', {}, [`signed by device ${shortId(e.author)}${e.authorCurrent ? '' : ' (removed device)'}`]),
    h('span', {}, [`claimed ${fmtDateTime(e.ts)}`]),
    h('span', {}, [`key epoch ${e.keyEpoch}`]),
    h('span', {}, [`log ${e.logSeq}`]),
    e.conflictId ? h('span', {}, [`branch ${e.conflictId}`]) : null,
    e.knownToRemoved && !e.tombstone ? h('span', { class: 'badge badge-conflict' }, ['key epoch was held by a removed device']) : null,
    e.tombstone ? null : h('span', { class: e.readability === 'readable' ? '' : 'badge badge-conflict' }, [READABILITY[e.readability]]),
  ];
  if (e.kind === 'conflict') {
    status.push(h('span', { class: `badge ${e.conflictOpen ? 'badge-conflict' : ''}` }, [e.conflictOpen ? 'open conflict' : `resolved${e.resolvedAtRevision ? ` at revision ${e.resolvedAtRevision}` : ''}`]));
  }
  if (e.resolves.length > 0) status.push(h('span', {}, [`settles ${e.resolves.length} branch${e.resolves.length > 1 ? 'es' : ''}`]));

  let actions: Child = null;
  if (e.kind === 'applied' && !e.tombstone) {
    if (e.restoreBlock !== null) {
      actions = h('span', { class: 'muted', 'data-testid': 'restore-blocked' }, [RESTORE_BLOCK[e.restoreBlock]]);
    } else if (!canWrite) {
      actions = h('span', { class: 'muted' }, ['This browser cannot write now. Restore from an owner device with the CLI.']);
    } else if (vs.confirmRestore === e.logSeq) {
      actions = h('div', { class: 'row' }, [
        h('button', { type: 'button', class: 'danger', disabled: busy, 'data-testid': 'confirm-restore' }, [`Write revision ${e.revision} as a new revision`], {
          click: () => { vs.confirmRestore = null; void c.restore(e.logSeq); },
        }),
        h('button', { type: 'button', class: 'secondary' }, ['Cancel'], { click: () => { vs.confirmRestore = null; rerender(); } }),
      ]);
    } else {
      actions = h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'restore' }, ['Restore'], { click: () => { vs.confirmRestore = e.logSeq; vs.confirmSettle = null; rerender(); } });
    }
  } else if (e.kind === 'conflict' && e.conflictOpen) {
    const id = e.conflictId!;
    if (e.tombstone) actions = h('span', { class: 'muted' }, ['This branch is a delete request; it cannot be adopted as a value.']);
    else if (e.restoreBlock !== null) actions = h('span', { class: 'muted', 'data-testid': 'restore-blocked' }, [RESTORE_BLOCK[e.restoreBlock]]);
    else if (e.readability !== 'readable') actions = h('span', { class: 'muted' }, ['Cannot adopt this branch here. Use `ak secrets sync settle` from an owner device.']);
    else if (!canWrite) actions = h('span', { class: 'muted' }, ['This browser cannot write now. Use `ak secrets sync settle` from an owner device.']);
    else if (vs.confirmSettle === id) {
      actions = h('div', { class: 'row' }, [
        h('button', { type: 'button', class: 'danger', disabled: busy, 'data-testid': 'confirm-settle' }, ['Adopt this branch and settle every open conflict'], {
          click: () => { vs.confirmSettle = null; void c.settle({ source: 'branch', conflictId: id }); },
        }),
        h('button', { type: 'button', class: 'secondary' }, ['Cancel'], { click: () => { vs.confirmSettle = null; rerender(); } }),
      ]);
    } else {
      actions = h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'settle-branch' }, ['Use this branch’s value'], { click: () => { vs.confirmSettle = id; vs.confirmRestore = null; rerender(); } });
    }
  }
  return h('li', { class: 'item', 'data-testid': 'history-entry' }, [
    h('div', { class: 'item-head' }, [h('span', { class: 'name' }, [entryLabel(e)]), actions]),
    h('div', { class: 'meta' }, status),
  ]);
}

function historyBody(c: AppController, s: Extract<Screen, { kind: 'history' }>, hist: ItemHistory, vs: ViewState, rerender: () => void): Child[] {
  const writable = s.canWrite && !hist.stale && !hist.deleted;
  const shown = hist.entries.slice(0, vs.historyShown);
  const open = hist.openConflictIds;
  const settleCurrent: Child = open.length > 0 && writable
    ? vs.confirmSettle === 'current'
      ? h('div', { class: 'row' }, [
        h('button', { type: 'button', class: 'danger', disabled: s.busy, 'data-testid': 'confirm-settle-current' }, [`Keep the current value and settle ${open.length} conflict${open.length > 1 ? 's' : ''}`], {
          click: () => { vs.confirmSettle = null; void c.settle({ source: 'current' }); },
        }),
        h('button', { type: 'button', class: 'secondary' }, ['Cancel'], { click: () => { vs.confirmSettle = null; rerender(); } }),
      ])
      : h('button', { type: 'button', class: 'secondary', disabled: s.busy, 'data-testid': 'settle-current' }, ['Keep the current value'], { click: () => { vs.confirmSettle = 'current'; vs.confirmRestore = null; rerender(); } })
    : null;
  return [
    hist.stale
      ? h('p', { class: 'notice notice-error', role: 'status', 'data-testid': 'history-stale' }, ['This item changed after the list was verified. Reload the history before restoring or settling anything.'])
      : null,
    hist.deleted ? h('p', { class: 'notice notice-error', role: 'status' }, ['This item is deleted. A deletion is kept for the life of the vault and is never undone from here.']) : null,
    h('p', { class: 'muted' }, [
      `Verified against the signed change log up to position ${hist.logSeq}. Times are claimed by the signing device. A server can withhold the newest entries, so a missing entry is not proof it never existed. No value is shown.`,
    ]),
    h('p', { class: 'muted' }, ['Restoring writes the old value as a new revision. It does not make an old provider credential valid or safe again; it may already be revoked or exposed, so check it with the provider and rotate it there if needed.']),
    open.length > 0
      ? h('section', { 'data-testid': 'conflicts' }, [
        h('h2', {}, [`${open.length} open conflict${open.length > 1 ? 's' : ''}`]),
        h('p', { class: 'muted' }, ['Every branch is kept until one new revision settles it. Settling lists all open branches and cannot be undone from here. From a terminal, `ak secrets sync settle` does the same.']),
        settleCurrent,
      ])
      : null,
    h('ul', { class: 'items' }, shown.map((e) => entryRow(c, e, writable, s.busy, vs, rerender))),
    hist.entries.length > shown.length
      ? h('button', { type: 'button', class: 'secondary', 'data-testid': 'history-more' }, [`Show older (${hist.entries.length - shown.length} more)`], { click: () => { vs.historyShown += HISTORY_PAGE; rerender(); } })
      : null,
    hist.omitted > 0 ? h('p', { class: 'muted' }, [`${hist.omitted} older entries are not listed.`]) : null,
  ];
}

function historyScreen(c: AppController, s: Extract<Screen, { kind: 'history' }>, vs: ViewState, rerender: () => void): HTMLElement[] {
  return [
    header(c, s.deviceId),
    h('main', { 'aria-busy': s.busy ? 'true' : 'false' }, [
      h('div', { class: 'row' }, [
        h('button', { type: 'button', class: 'secondary', 'data-testid': 'history-back' }, ['Back to the vault'], { click: () => { resetHistoryState(vs); c.closeHistory(); } }),
        h('button', { type: 'button', class: 'secondary', disabled: s.busy, 'data-testid': 'history-reload' }, ['Reload history'], { click: () => { resetHistoryState(vs); void c.refreshHistory(); } }),
      ]),
      h('h2', { 'data-testid': 'history-title' }, [`History of ${s.item.name}`]),
      noticeEl(s.notice),
      ...(s.history ? historyBody(c, s, s.history, vs, rerender) : [h('p', { class: 'muted', 'data-testid': 'history-loading' }, ['Verifying the change log…'])]),
    ]),
  ];
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
        h('ul', { class: 'items' }, shown.map((i) => itemRow(c, i, vs, rerender, s.busy))),
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
    case 'history':
      nodes = historyScreen(c, screen, vs, rerender);
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
