/**
 * Rotation screens: the health summary, the per-item health badge and the
 * guided rotation panel. Text only, from fixed strings plus escaped item
 * metadata. The replacement value goes through the same write-only masked field
 * as any other set and is cleared on submit; no screen reads an old value back.
 */
import type { AppController } from '../app-controller.js';
import type { ItemView } from '../sync/vault-sync.js';
import { nextDueMs, parseExpiresAt, revocationConfirmed, rotationHealth, vaultStepDone, type RotationHealth } from '../sync/rotation.js';
import { h, type Child } from './dom.js';
import { NO_CAPTURE } from './views.js';

const LABEL: Record<RotationHealth, string> = {
  needs_rotate: 'Needs rotation',
  rotating: 'Rotation in progress',
  paused: 'Rotation paused',
  failed: 'Rotation failed',
  awaiting_revocation: 'Vault updated, old key not confirmed revoked',
  overdue: 'Overdue',
  expired: 'Expired',
  due_soon: 'Due soon',
  expiring_soon: 'Expires soon',
  ok: 'On schedule',
  untracked: 'No schedule',
};

/** Health that needs a person, most urgent first; the summary lists these. */
export const ATTENTION: readonly RotationHealth[] = ['needs_rotate', 'expired', 'overdue', 'failed', 'awaiting_revocation', 'paused', 'rotating', 'due_soon', 'expiring_soon'];

const BAD = new Set<RotationHealth>(['needs_rotate', 'expired', 'overdue', 'failed']);

function fmtDay(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}

export function healthLabel(health: RotationHealth): string {
  return LABEL[health];
}

/** A badge that carries its meaning in text, not only in colour. */
export function healthBadge(health: RotationHealth): HTMLElement {
  const cls = BAD.has(health) ? 'badge-conflict' : health === 'ok' || health === 'untracked' ? '' : 'badge-warn';
  return h('span', { class: `badge ${cls}`.trim(), 'data-testid': 'rotation-health' }, [LABEL[health]]);
}

/** Epoch rekey versus provider rotation, plus the counts that need attention. */
export function rotationSummary(items: readonly ItemView[], keyEpoch: number, rekeyRequired: boolean, nowMs: number): HTMLElement {
  const counts = new Map<RotationHealth, number>();
  for (const i of items) {
    const hl = rotationHealth(i, nowMs);
    counts.set(hl, (counts.get(hl) ?? 0) + 1);
  }
  const attention = ATTENTION.filter((k) => counts.has(k));
  return h('section', { class: 'rotation-summary', 'aria-label': 'Credential rotation', 'data-testid': 'rotation-summary' }, [
    h('h2', {}, ['Credential rotation']),
    h('p', { class: 'muted', 'data-testid': 'rekey-explainer' }, [
      `Vault rekey: key epoch ${keyEpoch}${rekeyRequired ? ' (a rekey is required before changes are accepted)' : ''}. A rekey re-encrypts items for the devices that remain and changes no provider credential. `,
      'Provider rotation replaces the secret an item holds and revokes the old one at the provider. Only you can do that; the Vault tracks it below.',
    ]),
    attention.length
      ? h('ul', { class: 'rotation-counts', 'data-testid': 'rotation-counts' }, attention.map((k) => h('li', {}, [`${counts.get(k)} ${LABEL[k].toLowerCase()}`])))
      : h('p', { class: 'muted' }, ['No item needs rotation attention.']),
  ]);
}

function dueLine(item: ItemView, nowMs: number): Child {
  const due = nextDueMs(item);
  const expiry = parseExpiresAt(item.expiresAt);
  const parts: string[] = [];
  if (due !== null) parts.push(`${due <= nowMs ? 'was due' : 'due'} ${fmtDay(due)}`);
  if (expiry !== null) parts.push(`${expiry <= nowMs ? 'expired' : 'expires'} ${fmtDay(expiry)}`);
  if (item.exposedSinceMs !== null && item.exposedSinceMs < Number.MAX_SAFE_INTEGER) parts.push(`listed for rotation by a rekey on ${fmtDay(item.exposedSinceMs)}`);
  return parts.length ? h('span', { 'data-testid': 'rotation-due' }, [parts.join(' · ')]) : null;
}

/** The small inline status shown on every row. */
export function rotationMetaChips(item: ItemView, nowMs: number): Child[] {
  return [healthBadge(rotationHealth(item, nowMs)), dueLine(item, nowMs)];
}

function profileList(item: ItemView, key: string): string[] {
  const f = item.profile.find((p) => p.key === key);
  if (!f) return [];
  return Array.isArray(f.value) ? f.value : [f.value];
}

function step(done: boolean, title: string, body: Child[]): HTMLElement {
  return h('li', { class: done ? 'step step-done' : 'step' }, [h('strong', {}, [`${title}${done ? ' (done)' : ''}`]), ...body]);
}

/** The guided rotation panel of one item. */
export function rotationPanel(c: AppController, item: ItemView, busy: boolean, rekeyRequired: boolean, nowMs: number, close: () => void): HTMLElement {
  const hl = rotationHealth(item, nowMs);
  const r = item.rotation;
  const open = r !== null && r.state !== 'revoked';
  const vaultDone = vaultStepDone(item);
  const revoked = revocationConfirmed(item);
  const off = busy || rekeyRequired;
  const valueInput = h('input', { id: `rot-value-${item.itemId}`, type: 'text', class: 'masked', required: true, 'data-testid': 'rotate-value', ...NO_CAPTURE }) as HTMLInputElement;
  const ttlInput = h('input', { id: `rot-ttl-${item.itemId}`, type: 'text', inputmode: 'numeric', maxlength: '4', 'data-testid': 'ttl-input', ...NO_CAPTURE }) as HTMLInputElement;
  ttlInput.value = item.rotateTtlDays === null ? '' : String(item.rotateTtlDays);
  const act = (kind: 'start' | 'pause' | 'resume' | 'fail' | 'cancel' | 'confirm_revoked', label: string, testid: string, secondary = true): HTMLElement =>
    h('button', { type: 'button', class: secondary ? 'secondary' : '', disabled: off, 'data-testid': testid }, [label], { click: () => void c.rotate(item.itemId, { kind }) });

  const provider = [profileList(item, 'provider')[0], profileList(item, 'account')[0], profileList(item, 'environment')[0]].filter((x): x is string => !!x);
  const rotateUrl = profileList(item, 'rotate_url')[0];
  const consumers = [...profileList(item, 'usage_hosts'), ...profileList(item, 'projects')];

  const controls: HTMLElement[] = [];
  if (!open) controls.push(act('start', 'Start rotation', 'rotation-start', false));
  if (open && r.state === 'in_progress') controls.push(act('pause', 'Pause', 'rotation-pause'));
  if (open && r.state !== 'in_progress') controls.push(act('resume', 'Resume', 'rotation-resume', false));
  if (open && r.state !== 'failed') controls.push(act('fail', 'Mark as failed', 'rotation-fail'));
  if (open && !vaultDone) controls.push(act('cancel', 'Cancel rotation', 'rotation-cancel'));

  return h('div', { class: 'rotation-panel', role: 'group', 'aria-label': 'Rotate credential', 'data-testid': 'rotation-panel' }, [
    h('p', { class: 'muted' }, [
      'Create the new credential at the provider yourself, outside any AI chat. Vault never rotates or revokes a provider key for you, and the old value cannot be read back from the dashboard.',
    ]),
    provider.length ? h('p', {}, [`Provider details on this item: ${provider.join(' / ')}`]) : h('p', { class: 'muted' }, ['This item records no provider, account or environment.']),
    h('p', { 'data-testid': 'rotation-status' }, [`Status: ${LABEL[hl]}`]),
    h('ol', { class: 'steps' }, [
      step(open || vaultDone, '1. Start', [h('span', {}, [' Record that you are rotating this credential.', rotateUrl ? ` Provider page, as recorded on the item: ${rotateUrl}` : ''])]),
      step(vaultDone, '2. Store the new value in the Vault', [
        h('form', { class: 'rotate-form', 'aria-busy': busy ? 'true' : 'false' }, [
          h('label', { for: `rot-value-${item.itemId}` }, ['New value (write-only: encrypted here, never shown again)']),
          valueInput,
          h('button', { type: 'submit', disabled: off || !(open && r.state === 'in_progress'), 'data-testid': 'rotate-submit' }, ['Save new value']),
        ], {
          submit: (ev) => {
            ev.preventDefault();
            const value = valueInput.value;
            valueInput.value = '';
            void c.set(item.name, value);
          },
        }),
        h('p', { class: 'muted', 'data-testid': 'vault-step' }, [vaultDone ? 'Confirmed: the verified vault head holds a newer value.' : 'Not confirmed yet: this turns done only after the new revision is read back and verified.']),
      ]),
      step(revoked, '3. Revoke the old key at the provider', [
        h('span', {}, [' Do this at the provider. The Vault cannot check it, so this records only what you confirm.']),
        h('button', { type: 'button', class: 'secondary', disabled: off || !vaultDone || revoked, 'data-testid': 'rotation-confirm-revoked' }, ['I revoked the old key at the provider'], { click: () => void c.rotate(item.itemId, { kind: 'confirm_revoked' }) }),
      ]),
      step(false, '4. Update every consumer', [
        h('span', {}, [consumers.length ? ` Item profile lists: ${consumers.join(', ')}. ` : ' ', 'Machines, agents and CI that still hold the old value stop working once it is revoked; each must pick up the new revision.']),
      ]),
    ]),
    h('div', { class: 'row' }, controls),
    h('form', { class: 'row ttl-form' }, [
      h('label', { for: `rot-ttl-${item.itemId}` }, ['Rotate every (days)']),
      ttlInput,
      h('button', { type: 'submit', class: 'secondary', disabled: off, 'data-testid': 'ttl-save' }, ['Save schedule']),
    ], {
      submit: (ev) => {
        ev.preventDefault();
        const text = ttlInput.value.trim();
        void c.rotate(item.itemId, { kind: 'set_ttl', days: text === '' ? null : /^\d{1,4}$/.test(text) ? Number(text) : NaN });
      },
    }),
    h('p', { class: 'muted' }, [
      'A member or device removed earlier already saw the old value; no step here can take that back, so revoke it at the provider.',
    ]),
    h('button', { type: 'button', class: 'secondary', 'data-testid': 'rotation-close' }, ['Close'], { click: close }),
  ]);
}
