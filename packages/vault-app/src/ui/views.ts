/**
 * Screens. Every string from an item, a profile, a write request or a code is
 * inserted as text. Values are write-only: the vault screen's value field is a
 * CSS-masked text input (never a password input, so a name field beside it does
 * not read as a login form), the write-request field, which has no name field
 * beside it, is a password input; both have autofill, spellcheck and manager
 * capture off and are cleared on submit, and no screen has a reveal or copy action.
 */
import type { AppController, Notice, Screen } from '../app-controller.js';
import type { HistoryEntry } from '../sync/history.js';
import type { ItemView } from '../sync/vault-sync.js';
import { h, replaceChildren, type Child } from './dom.js';
import { membersScreen } from './members-view.js';
import { messageFor } from './messages.js';
import { MAX_ROTATE_TTL_DAYS, rotationInfo, type ExpiryHealth, type RotationHealth, type RotationInfo } from '../sync/rotation.js';

/** Keep the browser and password managers from storing, suggesting or correcting a field. */
export const NO_CAPTURE = {
  autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off',
  'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-bwignore': 'true', 'data-form-type': 'other',
} as const;

/** View-local state that survives a re-render (never a value). */
export interface ViewState {
  filter: string;
  confirmDelete: string | null;
  /** Log position of the revision awaiting restore confirmation. */
  confirmRestore: number | null;
  /** `keep`, or the branch ID to adopt, awaiting resolve confirmation. */
  confirmResolve: string | null;
  /** How many history entries the list shows (pages of {@link HISTORY_PAGE}). */
  historyShown: number;
  /** Item whose rotation panel is open. */
  rotating: string | null;
  tab: 'secrets' | 'members';
}

export const HISTORY_PAGE = 20;

export function newViewState(): ViewState {
  return { filter: '', confirmDelete: null, confirmRestore: null, confirmResolve: null, historyShown: HISTORY_PAGE, rotating: null, tab: 'secrets' };
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

/** Remaining time as text, e.g. `9m 05s`; `expired` once past. */
export function remaining(expiresAt: number, nowMs: number): string {
  const s = Math.floor((expiresAt - nowMs) / 1000);
  if (s <= 0) return 'expired';
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${String(s % 60).padStart(2, '0')}s` : `${s}s`;
}

/** A countdown that ticks while it is in the document and stops once a re-render removes it. */
function countdown(expiresAt: number): HTMLElement {
  const el = h('span', { 'data-testid': 'write-expiry' }, [remaining(expiresAt, Date.now())]);
  const timer = setInterval(() => {
    if (!el.isConnected) {
      clearInterval(timer);
      return;
    }
    el.textContent = remaining(expiresAt, Date.now());
  }, 1000);
  return el;
}

function writeScreen(c: AppController, s: Extract<Screen, { kind: 'write' }>): HTMLElement[] {
  const r = s.request;
  const details = r
    ? h('dl', { class: 'profile', 'data-testid': 'write-request' }, [
      h('dt', {}, ['Secret']), h('dd', { class: 'name', 'data-testid': 'write-name' }, [r.name]),
      r.purpose !== null ? h('dt', {}, ['Purpose']) : null, r.purpose !== null ? h('dd', { 'data-testid': 'write-purpose' }, [r.purpose]) : null,
      h('dt', {}, ['Requested by']), h('dd', { 'data-testid': 'write-client' }, [r.clientId]),
      h('dt', {}, ['Action']), h('dd', { 'data-testid': 'write-operation' }, [r.operation === 'create' ? 'Create a new secret' : 'Replace the value of an existing secret']),
      s.open ? h('dt', {}, ['Expires in']) : null, s.open ? h('dd', {}, [countdown(r.expiresAt)]) : null,
    ])
    : null;
  let form: HTMLElement | null = null;
  if (s.open && r) {
    const valueInput = h('input', { id: 'write-value', type: 'password', required: true, 'data-testid': 'write-value', ...NO_CAPTURE }) as HTMLInputElement;
    form = h('form', { class: 'set', 'aria-busy': s.busy ? 'true' : 'false' }, [
      h('label', { for: 'write-value' }, ['Value (typed here, encrypted in this browser, never shown again or sent to the assistant)']),
      valueInput,
      h('div', { class: 'row' }, [
        h('button', { type: 'submit', disabled: s.busy, 'data-testid': 'write-save' }, ['Save']),
        h('button', { type: 'button', class: 'secondary', disabled: s.busy, 'data-testid': 'write-cancel' }, ['Cancel request'], {
          click: () => {
            valueInput.value = '';
            void c.cancelWrite();
          },
        }),
      ]),
    ], {
      submit: (ev) => {
        ev.preventDefault();
        const value = valueInput.value;
        // Clear the field before anything else so the value does not linger in the DOM.
        valueInput.value = '';
        void c.submitWrite(value);
      },
    });
  }
  return [
    header(c, s.deviceId),
    h('main', {}, [
      noticeEl(s.notice),
      h('h2', {}, ['Write request']),
      s.busy && !r ? h('p', { 'aria-busy': 'true' }, ['Opening the request…']) : null,
      details,
      form,
      s.receipt ? h('p', { class: 'muted', 'data-testid': 'write-receipt' }, [`Receipt ${s.receipt.slice(0, 8)}`]) : null,
      s.retry ? h('button', { type: 'button', 'data-testid': 'write-retry' }, ['Try again'], { click: () => void c.retryWrite() }) : null,
      !s.open && !s.busy ? h('button', { type: 'button', class: 'secondary', 'data-testid': 'write-done' }, ['Back to the vault'], { click: () => void c.leaveWrite() }) : null,
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

/** Expiry warnings only; a far-off expiry needs no badge. */
const EXPIRY_LABEL: Record<Exclude<ExpiryHealth, 'ok'>, string> = {
  expired: 'expired',
  expiring_soon: 'expires soon',
};

function infoOf(item: ItemView, nowMs: number): RotationInfo {
  return rotationInfo({
    createdMs: item.createdMs, rotatedMs: item.rotatedMs, rotateTtlDays: item.rotateTtlDays,
    flaggedMs: item.flaggedMs, flaggedEpoch: item.flaggedEpoch, keyEpoch: item.keyEpoch, workflow: item.rotation,
    expiresMs: item.expiresMs,
  }, nowMs);
}

function relativeDays(days: number): string {
  const d = Math.abs(days);
  const day = `${d} day${d === 1 ? '' : 's'}`;
  return days < 0 ? `${day} ago` : `in ${day}`;
}

export function dueText(info: RotationInfo): string {
  if (info.dueMs === null || info.daysUntilDue === null) return '';
  if (info.daysUntilDue === 0) return `due ${fmtDate(info.dueMs)} (today)`;
  return `due ${fmtDate(info.dueMs)} (${relativeDays(info.daysUntilDue)})`;
}

/** The date is the UTC calendar day of `expires_at`; 0 whole days either side reads "today". */
function expiryText(info: RotationInfo): string {
  if (info.expiresMs === null || info.daysUntilExpiry === null) return '';
  const verb = info.expiry === 'expired' ? 'expired' : 'expires';
  const date = `${fmtDate(info.expiresMs)} UTC`;
  return info.daysUntilExpiry === 0 ? `${verb} today (${date})` : `${verb} ${date} (${relativeDays(info.daysUntilExpiry)})`;
}

/** Informational: the warning changes no grant and blocks no action. */
function expiryBadge(info: RotationInfo): HTMLElement | null {
  if (info.expiry === null || info.expiry === 'ok') return null;
  return h('span', {
    class: `badge badge-exp-${info.expiry}`,
    title: 'From the expires_at date in this secret’s verified profile. Replace it at the provider; this warning does not change access.',
    'data-testid': 'expiry-health',
  }, [EXPIRY_LABEL[info.expiry]]);
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
  // A role change can land while a delete awaits its confirm: stop offering it.
  const canWrite = s.canWrite && !s.rekeyRequired;
  const confirming = vs.confirmDelete === item.itemId && canWrite;
  const meta: Child[] = [
    h('span', { class: `badge badge-${item.sensitivity}` }, [item.sensitivity === 'high' ? 'high sensitivity' : 'normal']),
    item.createdMs !== null ? h('span', {}, [`created ${fmtDate(item.createdMs)}`]) : null,
    item.rotatedMs !== null ? h('span', {}, [`value written ${fmtDate(item.rotatedMs)}`]) : null,
    item.creator ? h('span', {}, [`by ${item.creator}`]) : null,
    item.rotateTtlDays !== null ? h('span', {}, [`rotate every ${item.rotateTtlDays} days`]) : null,
    info.dueMs !== null ? h('span', { 'data-testid': 'rotation-due' }, [dueText(info)]) : null,
    info.expiresMs !== null ? h('span', { 'data-testid': 'expiry-due' }, [expiryText(info)]) : null,
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
    : h('button', { type: 'button', class: 'secondary', disabled: busy || !canWrite, 'data-testid': 'delete' }, ['Delete'], { click: () => { vs.confirmDelete = item.itemId; rerender(); } });
  const history = h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'history' }, ['History'], {
    click: () => {
      vs.confirmRestore = null;
      vs.confirmResolve = null;
      vs.historyShown = HISTORY_PAGE;
      c.openHistory(item.itemId);
    },
  });
  return h('li', { class: 'item', 'data-testid': 'item' }, [
    h('div', { class: 'item-head' }, [
      h('span', { class: 'name', 'data-testid': 'item-name' }, [item.name]),
      h('div', { class: 'row' }, [
        healthBadge(item, info),
        expiryBadge(info),
        history,
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
  const expiryCounts: Record<Exclude<ExpiryHealth, 'ok'>, number> = { expired: 0, expiring_soon: 0 };
  for (const i of s.items) {
    const info = infoOf(i, s.nowMs);
    counts[info.health]++;
    if (info.expiry === 'expired' || info.expiry === 'expiring_soon') expiryCounts[info.expiry]++;
  }
  const order: RotationHealth[] = ['needs_rotate', 'awaiting_revoke', 'overdue', 'due_soon', 'unknown', 'ok'];
  const expiryOrder: Exclude<ExpiryHealth, 'ok'>[] = ['expired', 'expiring_soon'];
  return h('section', { class: 'rotation-summary', 'aria-label': 'Rotation health', 'data-testid': 'rotation-summary' }, [
    h('h2', {}, ['Rotation health']),
    h('ul', { class: 'row health-list' }, order.map((k) => h('li', { class: `badge badge-rot-${k}`, 'data-testid': `health-${k}` }, [`${counts[k]} ${HEALTH_LABEL[k]}`]))),
    // Expiry is its own dimension: listed apart so it never reads as a rotation state.
    h('ul', { class: 'row health-list', 'aria-label': 'Credential expiry', 'data-testid': 'expiry-summary' }, expiryOrder.map((k) => h('li', { class: `badge badge-exp-${k}`, 'data-testid': `expiry-${k}` }, [`${expiryCounts[k]} ${EXPIRY_LABEL[k]}`]))),
    h('p', { class: 'muted' }, [
      'Two different things are called rotation. A vault rekey (key epoch) re-wraps the vault key for the devices that remain after a removal and replaces no credential. Provider credential rotation replaces the secret at its provider. Items marked needs rotation were readable by a removed member or device; the mark stays until a member confirms the old provider credential is revoked after a new value was saved.',
    ]),
  ]);
}

function tabs(vs: ViewState, rerender: () => void): HTMLElement {
  const tab = (id: ViewState['tab'], label: string): HTMLElement =>
    h('button', { type: 'button', class: vs.tab === id ? '' : 'secondary', 'aria-pressed': vs.tab === id ? 'true' : 'false', 'data-testid': `tab-${id}` }, [label], {
      click: () => {
        vs.tab = id;
        rerender();
        // The screen is rebuilt: put keyboard focus back on the pressed tab.
        (document.querySelector(`[data-testid="tab-${id}"]`) as HTMLElement | null)?.focus();
      },
    });
  return h('div', { class: 'row', role: 'group', 'aria-label': 'Vault sections' }, [tab('secrets', 'Secrets'), tab('members', 'Members and access')]);
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
    h('button', { type: 'submit', disabled: s.busy || s.rekeyRequired || !s.canWrite }, ['Save']),
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
      !s.canWrite ? h('p', { class: 'notice notice-info', role: 'status', 'data-testid': 'read-only' }, ['Your role in this vault is reader, so this browser can list metadata only.']) : null,
      tabs(vs, rerender),
      vs.tab === 'members' ? membersScreen(s.membership) : null,
      vs.tab === 'secrets' ? rotationSummary(s) : null,
      vs.tab === 'secrets' ? setForm : null,
      vs.tab === 'secrets' ? h('section', {}, [
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
      ]) : null,
    ]),
  ];
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? 'unknown time' : `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

const STANDING: Record<HistoryEntry['authorStanding'], string> = {
  this_browser: 'this browser',
  current_device: 'current device',
  removed_device: 'removed device',
  unknown_device: 'unknown device',
};

function entryLabel(e: HistoryEntry): string {
  if (e.kind === 'conflict') return `Conflicting branch on revision ${e.baseRevision}`;
  return e.tombstone ? `Revision ${e.revision} (deletion)` : `Revision ${e.revision}`;
}

function entryContent(e: HistoryEntry): string {
  if (e.content === 'readable') return 'Signature and chain verified; the value is stored encrypted and never shown';
  if (e.content === 'none') return 'Signature and chain verified; a deletion carries no value';
  return 'unavailable / unverified content: this browser does not hold the key for epoch ' + e.keyEpoch + ', so only the signed metadata is shown';
}

function entryRow(c: AppController, itemId: string, e: HistoryEntry, canWrite: boolean, busy: boolean, vs: ViewState, rerender: () => void): HTMLElement {
  const status = e.status === 'current' ? 'current' : e.status === 'superseded' ? 'earlier' : e.status === 'open' ? 'unresolved' : e.resolvedAtRevision !== null ? `resolved at revision ${e.resolvedAtRevision}` : 'resolved';
  const confirming = vs.confirmRestore === e.logSeq;
  const actions: Child[] = [];
  if (e.restorable && canWrite) {
    actions.push(confirming
      ? h('div', { class: 'warn', 'data-testid': 'restore-confirm' }, [
        h('p', {}, ['This writes the value of this revision as a new revision for every device. It does not undo anything at the provider: the restored credential may already be revoked, expired or exposed, and you may need to rotate or revoke it there.']),
        h('div', { class: 'row' }, [
          h('button', { type: 'button', class: 'danger', disabled: busy, 'data-testid': 'confirm-restore' }, ['Restore as new revision'], { click: () => { vs.confirmRestore = null; void c.restore(itemId, e.logSeq); } }),
          h('button', { type: 'button', class: 'secondary' }, ['Cancel'], { click: () => { vs.confirmRestore = null; rerender(); } }),
        ]),
      ])
      : h('button', { type: 'button', class: 'secondary', disabled: busy, 'data-testid': 'restore' }, ['Restore this value'], { click: () => { vs.confirmRestore = e.logSeq; vs.confirmResolve = null; rerender(); } }));
  }
  return h('li', { class: 'history-entry', 'data-testid': 'history-entry' }, [
    h('div', { class: 'item-head' }, [
      h('span', { class: 'name', 'data-testid': 'entry-title' }, [entryLabel(e)]),
      h('span', { class: `badge ${e.status === 'open' ? 'badge-conflict' : ''}` }, [status]),
    ]),
    h('div', { class: 'meta' }, [
      h('span', {}, [fmtTime(e.ts)]),
      h('span', {}, [`device ${e.author} (${STANDING[e.authorStanding]})`]),
      h('span', {}, [`key epoch ${e.keyEpoch}`]),
      e.resolves > 0 ? h('span', {}, [`resolves ${e.resolves} branch${e.resolves > 1 ? 'es' : ''}`]) : null,
    ]),
    h('p', { class: 'muted', 'data-testid': 'entry-content' }, [entryContent(e)]),
    ...actions,
  ]);
}

function conflictPanel(c: AppController, s: Extract<Screen, { kind: 'history' }>, vs: ViewState, rerender: () => void): Child {
  const open = s.history.entries.filter((e) => e.status === 'open');
  const total = s.history.openConflicts;
  if (total === 0) return null;
  const choices = [{ id: 'keep', label: 'Keep the current value' }, ...open.filter((e) => e.adoptable).map((e) => ({ id: e.conflictId!, label: `Use the value of the branch from device ${e.author}, ${fmtTime(e.ts)}` }))];
  const confirming = vs.confirmResolve !== null ? choices.find((x) => x.id === vs.confirmResolve) ?? null : null;
  return h('section', { class: 'warn', 'data-testid': 'conflicts' }, [
    h('h2', {}, [`${total} unresolved conflict${total > 1 ? 's' : ''}`]),
    h('p', {}, ['Another device wrote at the same time, and the server kept its record as a branch instead of overwriting either. Nothing is lost: every branch stays in the signed history. Resolving writes one new revision that lists all open branches as resolved. The CLI offers the same through ', h('code', {}, ['ak secrets sync settle']), '.']),
    s.canWrite && s.history.resolvable
      ? confirming
        ? h('div', {}, [
          h('p', { 'data-testid': 'resolve-confirm' }, [`${confirming.label}, and mark all ${total} open branch${total > 1 ? 'es' : ''} resolved for every device?`]),
          h('div', { class: 'row' }, [
            h('button', { type: 'button', class: 'danger', disabled: s.busy, 'data-testid': 'confirm-resolve' }, ['Resolve'], { click: () => { const adopt = confirming.id === 'keep' ? null : confirming.id; vs.confirmResolve = null; void c.resolve(s.history.itemId, adopt); } }),
            h('button', { type: 'button', class: 'secondary' }, ['Cancel'], { click: () => { vs.confirmResolve = null; rerender(); } }),
          ]),
        ])
        : h('div', { class: 'row' }, choices.map((x) => h('button', { type: 'button', class: 'secondary', disabled: s.busy, 'data-testid': 'resolve-choice' }, [x.label], { click: () => { vs.confirmResolve = x.id; vs.confirmRestore = null; rerender(); } })))
      : null,
    !s.history.resolvable ? h('p', { class: 'notice notice-error', 'data-testid': 'resolve-blocked' }, ['At least one open branch is a deletion or cannot be read by this browser, so it cannot be resolved here and nothing is dismissed. Use ', h('code', {}, ['ak secrets sync settle']), ' on a device that can read it.']) : null,
    open.some((e) => !e.adoptable) && s.history.resolvable ? h('p', { class: 'muted' }, ['A branch that predates a device removal or key rotation cannot be adopted here; use the CLI for it.']) : null,
  ]);
}

function historyScreen(c: AppController, s: Extract<Screen, { kind: 'history' }>, vs: ViewState, rerender: () => void): HTMLElement[] {
  const shown = s.history.entries.slice(0, vs.historyShown);
  return [
    header(c, s.deviceId),
    h('main', {}, [
      noticeEl(s.notice),
      h('div', { class: 'row' }, [h('button', { type: 'button', class: 'secondary', 'data-testid': 'history-back' }, ['Back to items'], { click: () => { vs.confirmRestore = null; vs.confirmResolve = null; c.closeHistory(); } })]),
      h('h2', { 'data-testid': 'history-title' }, [`History of ${s.history.name}`]),
      h('p', { class: 'muted' }, ['Each entry is signed by a device of this vault and chained into the vault log this browser verified. Values are never shown; a restore writes an earlier value as a new revision.']),
      !s.canWrite ? h('p', { class: 'notice notice-error', role: 'status' }, [messageFor('rekey_required')]) : null,
      conflictPanel(c, s, vs, rerender),
      h('ul', { class: 'items', 'data-testid': 'history-list' }, shown.map((e) => entryRow(c, s.history.itemId, e, s.canWrite, s.busy, vs, rerender))),
      s.history.entries.length > shown.length
        ? h('button', { type: 'button', class: 'secondary', 'data-testid': 'history-more' }, [`Show ${Math.min(HISTORY_PAGE, s.history.entries.length - shown.length)} more`], { click: () => { vs.historyShown += HISTORY_PAGE; rerender(); } })
        : null,
      s.history.omitted > 0 ? h('p', { class: 'muted', 'data-testid': 'history-omitted' }, [`${s.history.omitted} older entr${s.history.omitted > 1 ? 'ies are' : 'y is'} in the signed log but not listed here.`]) : null,
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
    case 'write':
      nodes = writeScreen(c, screen);
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
