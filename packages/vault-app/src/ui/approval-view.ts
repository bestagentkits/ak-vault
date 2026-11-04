/**
 * Access-approval screen (spec §3.13): one of the person's devices waits to use a
 * secret. Every field shown came out of the request this browser verified and
 * opened; the agent's reason is the agent's own words and is labelled as such.
 * No secret value is involved: the answer is a signed allow or deny.
 */
import type { AppController, Screen } from '../app-controller.js';
import { h, type Child } from './dom.js';

type ApprovalScreen = Extract<Screen, { kind: 'approval' }>;

/** "15 minutes", "1 hour", "8 hours". */
export function ttlLabel(seconds: number): string {
  if (seconds % 3600 === 0) return seconds === 3600 ? '1 hour' : `${seconds / 3600} hours`;
  return `${Math.round(seconds / 60)} minutes`;
}

/** Short IDs are enough to tell devices apart on screen; the full ID is in the title. */
function shortId(id: string): string {
  return id.slice(0, 8);
}

/** The approval screen body; `top` is the shared header and `notice` the shared notice line. */
export function approvalScreen(c: AppController, s: ApprovalScreen, top: HTMLElement, notice: Child, countdown: (expiresAt: number, testId: string) => HTMLElement): HTMLElement[] {
  const r = s.request;
  const row = (label: string, value: string | null, testId: string): Child[] =>
    value === null ? [] : [h('dt', {}, [label]), h('dd', { 'data-testid': testId }, [value])];
  const details = r
    ? h('dl', { class: 'profile', 'data-testid': 'approval-request' }, [
      h('dt', {}, ['Secret']), h('dd', { class: 'name', 'data-testid': 'approval-secret' }, [r.secret]),
      ...row('Agent', r.agent, 'approval-agent'),
      ...row('Agent fingerprint', r.fingerprint, 'approval-fingerprint'),
      ...row('Project', r.project, 'approval-project'),
      ...row('Purpose', r.purpose, 'approval-purpose'),
      ...row("Agent's reason (its own words, unverified)", r.reason, 'approval-reason'),
      h('dt', {}, ['Requesting device']), h('dd', { title: r.requester, 'data-testid': 'approval-requester' }, [shortId(r.requester)]),
      s.open ? h('dt', {}, ['Expires in']) : null, s.open ? h('dd', {}, [countdown(r.expiresAt, 'approval-expiry')]) : null,
    ])
    : null;
  const actions = s.open && r
    ? h('div', { class: 'row', 'aria-busy': s.busy ? 'true' : 'false' }, [
      h('button', { type: 'button', disabled: s.busy, 'data-testid': 'approval-allow-once' }, ['Allow once'], { click: () => void c.decide('allow_once') }),
      ...r.ttlChoices.map((ttl) =>
        h('button', { type: 'button', class: 'secondary', disabled: s.busy, 'data-testid': `approval-allow-${ttl}` }, [`Allow for ${ttlLabel(ttl)}`], {
          click: () => void c.decide('allow_ttl', ttl),
        })),
      h('button', { type: 'button', class: 'danger', disabled: s.busy, 'data-testid': 'approval-deny' }, ['Deny'], { click: () => void c.decide('deny') }),
    ])
    : null;
  return [
    top,
    h('main', {}, [
      notice,
      h('h2', {}, ['Approve secret access']),
      s.busy && !r ? h('p', { 'aria-busy': 'true' }, ['Opening the request…']) : null,
      details,
      s.open ? h('p', { class: 'muted' }, ['Allow only if you started this work. Your answer is signed by this browser; the requesting device checks it before it uses the secret.']) : null,
      actions,
      s.retry ? h('button', { type: 'button', 'data-testid': 'approval-retry' }, ['Try again'], { click: () => void c.retryApproval() }) : null,
      !s.busy ? h('button', { type: 'button', class: 'secondary', 'data-testid': 'approval-back' }, ['Back to the vault'], { click: () => void c.leaveApproval() }) : null,
    ]),
  ];
}

/** The vault list's "waiting for you" panel: one button per pending approval. */
export function pendingApprovalsPanel(c: AppController, approvals: string[]): HTMLElement | null {
  if (approvals.length === 0) return null;
  return h('section', { class: 'notice notice-info', 'data-testid': 'approvals-pending' }, [
    h('p', {}, [`${approvals.length} of your devices ${approvals.length === 1 ? 'is' : 'are'} waiting for your approval to use a secret.`]),
    h('div', { class: 'row' }, approvals.map((id) =>
      h('button', { type: 'button', class: 'secondary', title: id, 'data-testid': 'approval-open' }, [`Review request ${shortId(id)}`], { click: () => void c.openPendingApproval(id) }))),
  ]);
}
