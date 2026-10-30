/**
 * The input form's screens. The name, purpose and client come from the link
 * and the server and are inserted as text only. The value field is a password
 * input with autofill, spellcheck and manager capture off; it is cleared before
 * the value is handed on, and no screen renders, reveals or copies a value.
 */
import type { InputController, InputNotice, InputScreen, InputSummary } from '../input/input-controller.js';
import { h, replaceChildren, type Child } from './dom.js';
import { messageFor } from './messages.js';
import { countdown, NO_CAPTURE } from './views.js';

function noticeEl(notice: InputNotice | null): Child {
  if (!notice) return null;
  return h('p', { class: `notice notice-${notice.kind}`, role: notice.kind === 'error' ? 'alert' : 'status', 'data-testid': 'notice' }, [messageFor(notice.code)]);
}

function header(): HTMLElement {
  return h('header', { class: 'bar' }, [h('h1', {}, ['AgentKit Vault'])]);
}

function summaryRows(s: InputSummary): HTMLElement[] {
  return [
    h('dt', {}, ['Secret']), h('dd', { class: 'name', 'data-testid': 'input-name' }, [s.name]),
    ...(s.purpose !== null ? [h('dt', {}, ['Purpose']), h('dd', { 'data-testid': 'input-purpose' }, [s.purpose])] : []),
  ];
}

function signinScreen(c: InputController, s: Extract<InputScreen, { kind: 'signin' }>): HTMLElement[] {
  return [
    header(),
    h('main', {}, [
      noticeEl(s.notice),
      h('h2', {}, ['Enter a secret value']),
      h('dl', { class: 'profile', 'data-testid': 'input-request' }, summaryRows(s.summary)),
      h('p', { class: 'muted' }, ['The assistant chose this name and purpose. Your device checks them again before it writes anything.']),
      h('button', { type: 'button', 'data-testid': 'input-signin' }, ['Sign in to continue'], { click: () => c.signIn() }),
    ]),
  ];
}

function formScreen(c: InputController, s: Extract<InputScreen, { kind: 'form' }>): HTMLElement[] {
  const r = s.request;
  const valueInput = h('input', { id: 'input-value', type: 'password', required: true, disabled: s.busy, 'data-testid': 'input-value', ...NO_CAPTURE }) as HTMLInputElement;
  return [
    header(),
    h('main', {}, [
      noticeEl(s.notice),
      h('h2', {}, ['Enter a secret value']),
      h('dl', { class: 'profile', 'data-testid': 'input-request' }, [
        ...summaryRows(r),
        h('dt', {}, ['Requested by']), h('dd', { 'data-testid': 'input-client' }, [r.clientId]),
        h('dt', {}, ['Action']), h('dd', { 'data-testid': 'input-operation' }, [r.operation === 'create' ? 'Create a new secret' : 'Replace the value of an existing secret']),
        h('dt', {}, ['Expires in']), h('dd', {}, [countdown(r.expiresAt, 'input-expiry')]),
      ]),
      h('form', { class: 'set', 'aria-busy': s.busy ? 'true' : 'false' }, [
        h('label', { for: 'input-value' }, ['Value (typed here, encrypted in this browser for your device, never shown again or sent to the assistant)']),
        valueInput,
        h('div', { class: 'row' }, [h('button', { type: 'submit', disabled: s.busy, 'data-testid': 'input-save' }, [s.busy ? 'Sending…' : 'Save'])]),
      ], {
        submit: (ev) => {
          ev.preventDefault();
          const value = valueInput.value;
          // Clear the field before anything else so the value does not linger in the DOM.
          valueInput.value = '';
          void c.submit(value);
        },
      }),
    ]),
  ];
}

function closedScreen(c: InputController, s: Extract<InputScreen, { kind: 'closed' }>): HTMLElement[] {
  return [
    header(),
    h('main', {}, [
      noticeEl(s.notice),
      s.summary ? h('dl', { class: 'profile', 'data-testid': 'input-request' }, summaryRows(s.summary)) : null,
      s.receipt ? h('p', { class: 'muted', 'data-testid': 'input-receipt' }, [`Receipt ${s.receipt.slice(0, 8)}`]) : null,
      s.retry ? h('button', { type: 'button', 'data-testid': 'input-retry' }, ['Try again'], { click: () => void c.retryLoad() }) : null,
      h('p', { class: 'muted' }, ['You can close this page.']),
    ]),
  ];
}

export function renderInput(root: Element, c: InputController, screen: InputScreen): void {
  let nodes: HTMLElement[];
  switch (screen.kind) {
    case 'loading':
      nodes = [h('main', { 'aria-busy': 'true' }, [h('p', {}, ['Loading…'])])];
      break;
    case 'signin':
      nodes = signinScreen(c, screen);
      break;
    case 'form':
      nodes = formScreen(c, screen);
      break;
    case 'closed':
      nodes = closedScreen(c, screen);
      break;
  }
  replaceChildren(root, ...nodes);
}
