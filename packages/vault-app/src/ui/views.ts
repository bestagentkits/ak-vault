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
import { MAX_ROTATE_TTL_DAYS, rotationInfo, type RotationHealth, type RotationInfo } from '../sync/rotation.js';

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

const HEALTH_LABEL: Record<RotationHealth, string> = {
  needs_rotate: 'needs rotation',
  awaiting_revoke: 'old key not confirmed revoked',
  overdue: 'rotation overdue',
  due_soon: 'rotation due soon',
  ok: 'rotation on schedule',
  unknown: 'rotation unknown',
};

function infoOf(item: ItemView, nowMs: number): RotationInfo {
  return rotationInfo({
    createdMs: item.createdMs, rotatedMs: item.rotatedMs, rotateTtlDays: item.rotateTtlDays,
    flaggedMs: item.flaggedMs, flaggedEpoch: item.flaggedEpoch, keyEpoch: item.keyEpoch, workflow: item.rotation,
  }, nowMs);
}

function dueText(info: RotationInfo): string {
  if (info.dueMs === null || info.daysUntilDue === null) return '';
  const d = Math.abs(info.daysUntilDue);
  const day = `${d} day${d === 1 ? '' : 's'}`;
  return info.daysUntilDue < 0 ? `due ${fmtDate(info.dueMs)} (${day} ago)` : `due ${fmtDate(info.dueMs)} (in ${day})`;
}

function healthBadge(item: ItemView, info: RotationInfo): HTMLElement {
  const extra = info.health === 'needs_rotate'
    ? 'A removed member or device could read this value. Rekeying cannot recall it: replace it at the provider.'
    : info.health === 'unknown'
      ? 'No rotation interval is set, or no created or rotated date is recorded.'
      : '';
  return h('span', { class: `badge badge-rot-${info.health}`, title: extra, 'data-testid': 'rotation-health' }, [HEALTH_LABEL[info.health]]);
}

/** Guided rotation. The provider credential is made outside the dashboard; the Vault write and the old key's revocation are separate steps. */
function rotationPanel(c: AppController, item: ItemView, info: RotationInfo, s: Extract<Screen, { kind: 'vault' }>, vs: ViewState, rerender: () => void): HTMLElement {
  const wf = item.rotation;
  const can = s.canWrite && !s.rekeyRequired && !s.busy;
  const active = wf?.state === 'active';
  const valueInput = h('input', { id: `rot-value-${item.itemId}`, type: 'text', class: 'masked', required: true, 'data-testid': 'rotate-value', ...NO_CAPTURE }) as HTMLInputElement;
  const ttlInput = h('input', { id: `rot-ttl-${item.itemId}`, type: 'number', min: '1', max: String(MAX_ROTATE_TTL_DAYS), step: '1', inputmode: 'numeric', 'data-testid': 'ttl-input', autocomplete: 'off' }) as HTMLInputElement;
  ttlInput.value = item.rotateTtlDays === null ? '' : String(Math.min(item.rotateTtlDays, MAX_ROTATE_TTL_DAYS));

  const step = (done: boolean, label: string, detail: string, testId: string): HTMLElement =>
    h('li', { class: done ? 'step step-done' : 'step', 'data-testid': testId }, [h('strong', {}, [`${label}: `]), done ? `done. ${detail}` : 'not done yet.']);

  const done = info.providerRevoked && active;
  const stateLine = wf
    ? done ? `Rotation complete (started ${fmtDate(wf.startedMs)}).` : `Rotation ${wf.state === 'active' ? 'in progress' : wf.state} since ${fmtDate(wf.startedMs)}.`
    : 'No rotation in progress.';
  const stateButtons: Child[] = [];
  if (!wf || done || wf.state === 'cancelled' || wf.state === 'failed') {
    stateButtons.push(h('button', { type: 'button', disabled: !can, 'data-testid': 'rotation-start' }, [wf ? 'Start again' : 'Start rotation'], { click: () => void c.startRotation(item.itemId) }));
  }
  if (wf?.state === 'active' && !done) {
    stateButtons.push(h('button', { type: 'button', class: 'secondary', disabled: !can, 'data-testid': 'rotation-pause' }, ['Pause'], { click: () => void c.setRotationState(item.itemId, 'paused') }));
    stateButtons.push(h('button', { type: 'button', class: 'secondary', disabled: !can, 'data-testid': 'rotation-fail' }, ['Mark failed'], { click: () => void c.setRotationState(item.itemId, 'failed') }));
  }
  if (wf?.state === 'paused') {
    stateButtons.push(h('button', { type: 'button', disabled: !can, 'data-testid': 'rotation-resume' }, ['Resume'], { click: () => void c.setRotationState(item.itemId, 'active') }));
  }
  if (wf && !done && (wf.state === 'active' || wf.state === 'paused')) {
    stateButtons.push(h('button', { type: 'button', class: 'secondary', disabled: !can, 'data-testid': 'rotation-cancel' }, ['Cancel rotation'], { click: () => void c.setRotationState(item.itemId, 'cancelled') }));
  }

  return h('section', { class: 'rotation', 'aria-label': `Rotation for ${item.name}`, 'data-testid': 'rotation-panel' }, [
    h('h3', {}, ['Rotate this provider credential']),
    h('p', { class: 'muted' }, [
      'This replaces the credential at the provider. It is not a vault rekey: a rekey changes which devices can read the vault and replaces no provider credential. The old value cannot be shown here, and anyone who already had it still knows it until it is revoked at the provider.',
    ]),
    !s.canWrite ? h('p', { class: 'notice notice-error', role: 'status' }, ['This device cannot write to the vault, so it cannot rotate.']) : null,
    s.rekeyRequired ? h('p', { class: 'notice notice-error', role: 'status' }, [messageFor('rekey_required')]) : null,
    h('p', { 'data-testid': 'rotation-state' }, [stateLine]),
    h('div', { class: 'row' }, stateButtons),
    h('ol', { class: 'steps' }, [
      h('li', { class: 'step' }, [h('strong', {}, ['1. Create the new credential at the provider yourself. ']), 'Do it in the provider’s own console, not in an AI chat or a URL.']),
      step(info.vaultUpdated, '2. Vault updated', info.vaultUpdated ? `new value saved ${fmtDate(item.rotatedMs)}.` : '', 'step-vault'),
      step(info.providerRevoked, '3. Old provider credential revoked', info.providerRevoked && wf?.revokedMs ? `a vault member confirmed it on ${fmtDate(wf.revokedMs)}. The dashboard cannot verify this with the provider.` : '', 'step-revoked'),
    ]),
    h('form', { class: 'set' }, [
      h('label', { for: valueInput.id }, ['New value (write-only: encrypted here, never shown again)']),
      valueInput,
      h('button', { type: 'submit', disabled: !can || !active, 'data-testid': 'rotate-save' }, ['Save new value']),
    ], {
      submit: (ev) => {
        ev.preventDefault();
        const value = valueInput.value;
        valueInput.value = '';
        void c.rotate(item.itemId, value);
      },
    }),
    h('div', { class: 'row' }, [
      h('button', { type: 'button', class: 'secondary', disabled: !can || !active || !info.vaultUpdated || info.providerRevoked, 'data-testid': 'rotation-revoked' }, ['I revoked the old credential at the provider'], { click: () => void c.confirmRevoked(item.itemId) }),
    ]),
    h('form', { class: 'ttl' }, [
      h('label', { for: ttlInput.id }, ['Rotate every (days)']),
      h('div', { class: 'row' }, [
        ttlInput,
        h('button', { type: 'submit', class: 'secondary', disabled: !can, 'data-testid': 'ttl-save' }, ['Save interval']),
      ]),
    ], {
      submit: (ev) => {
        ev.preventDefault();
        const raw = ttlInput.value.trim();
        void c.setRotateTtl(item.itemId, raw === '' ? null : Number(raw));
      },
    }),
    h('button', { type: 'button', class: 'secondary', 'data-testid': 'rotation-close' }, ['Close'], { click: () => { vs.rotating = null; rerender(); } }),
  ]);
}

function itemRow(c: AppController, item: ItemView, s: Extract<Screen, { kind: 'vault' }>, vs: ViewState, rerender: () => void): HTMLElement {
  const busy = s.busy;
  const info = infoOf(item, s.nowMs);
  const rotating = vs.rotating === item.itemId;
  const confirming = vs.confirmDelete === item.itemId;
  const meta: Child[] = [
    h('span', { class: `badge badge-${item.sensitivity}` }, [item.sensitivity === 'high' ? 'high sensitivity' : 'normal']),
    item.createdMs !== null ? h('span', {}, [`created ${fmtDate(item.createdMs)}`]) : null,
    item.rotatedMs !== null ? h('span', {}, [`value written ${fmtDate(item.rotatedMs)}`]) : null,
    item.creator ? h('span', {}, [`by ${item.creator}`]) : null,
    item.rotateTtlDays !== null ? h('span', {}, [`rotate every ${item.rotateTtlDays} days`]) : null,
    info.dueMs !== null ? h('span', { 'data-testid': 'rotation-due' }, [dueText(info)]) : null,
    item.rotation ? h('span', { 'data-testid': 'rotation-flow' }, [`rotation ${item.rotation.state}${info.vaultUpdated ? ', vault updated' : ''}${info.providerRevoked ? ', old key revoked (member-confirmed)' : info.vaultUpdated ? ', old key not confirmed revoked' : ''}`]) : null,
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
  return h('li', { class: 'item', 'data-testid': 'item' }, [
    h('div', { class: 'item-head' }, [
      h('span', { class: 'name', 'data-testid': 'item-name' }, [item.name]),
      h('div', { class: 'row' }, [
        healthBadge(item, info),
        h('button', { type: 'button', class: 'secondary', 'aria-expanded': rotating ? 'true' : 'false', 'data-testid': 'rotate' }, [rotating ? 'Hide rotation' : 'Rotation'], { click: () => { vs.rotating = rotating ? null : item.itemId; rerender(); } }),
        actions,
      ]),
    ]),
    h('div', { class: 'meta' }, meta),
    profile,
    rotating ? rotationPanel(c, item, info, s, vs, rerender) : null,
  ]);
}

/** Counts per health state, and the rekey versus provider-rotation distinction. */
function rotationSummary(s: Extract<Screen, { kind: 'vault' }>): HTMLElement {
  const counts: Record<RotationHealth, number> = { needs_rotate: 0, awaiting_revoke: 0, overdue: 0, due_soon: 0, ok: 0, unknown: 0 };
  for (const i of s.items) counts[infoOf(i, s.nowMs).health]++;
  const order: RotationHealth[] = ['needs_rotate', 'awaiting_revoke', 'overdue', 'due_soon', 'unknown', 'ok'];
  return h('section', { class: 'rotation-summary', 'aria-label': 'Rotation health', 'data-testid': 'rotation-summary' }, [
    h('h2', {}, ['Rotation health']),
    h('ul', { class: 'row health-list' }, order.map((k) => h('li', { class: `badge badge-rot-${k}`, 'data-testid': `health-${k}` }, [`${counts[k]} ${HEALTH_LABEL[k]}`]))),
    h('p', { class: 'muted' }, [
      'Two different things are called rotation. A vault rekey (key epoch) re-wraps the vault key for the devices that remain after a removal and replaces no credential. Provider credential rotation replaces the secret at its provider. Items marked needs rotation were readable by a removed member or device; the mark stays until a member confirms the old provider credential is revoked after a new value was saved.',
    ]),
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
      rotationSummary(s),
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
        h('ul', { class: 'items' }, shown.map((i) => itemRow(c, i, s, vs, rerender))),
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
