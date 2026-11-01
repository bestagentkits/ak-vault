/**
 * Entry point. Wires the controller to the browser: sessionStorage for the
 * pending sign-in only, IndexedDB for the device, a 15-minute idle lock, and a
 * keepalive revocation when the page is hidden for good.
 *
 * The same bundle serves the input form (spec §3.11): `/input` redirects here
 * with its fragment, and a page whose fragment is an input link, or which is the
 * callback of a sign-in the input form started, runs the input controller
 * instead of the dashboard.
 */
import { AppController } from './app-controller.js';
import { InputController } from './input/input-controller.js';
import { isInputFragment } from './input/input-link.js';
import { indexedDbDeviceStore } from './keys/device-store.js';
import { INPUT_PENDING_KEY, isAuthorizationResponse, sessionPendingStore } from './oauth/pkce-client.js';
import { renderInput } from './ui/input-view.js';
import { newViewState, render } from './ui/views.js';

export const IDLE_LOCK_MS = 15 * 60 * 1000;

export function startIdleLock(controller: AppController, target: EventTarget, ms = IDLE_LOCK_MS): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const arm = () => {
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(() => {
      const kind = controller.current().kind;
      if (kind !== 'signed_out' && kind !== 'loading' && kind !== 'fatal' && kind !== 'removed') void controller.lock('locked');
    }, ms);
  };
  const events = ['pointerdown', 'keydown', 'input', 'focus'];
  for (const e of events) target.addEventListener(e, arm, { passive: true });
  arm();
  return () => {
    if (timer !== null) clearTimeout(timer);
    for (const e of events) target.removeEventListener(e, arm);
  };
}

/** Whether this page load belongs to the input form rather than the dashboard. */
export function isInputPage(url: URL, storage: Pick<Storage, 'getItem'>): boolean {
  return isInputFragment(url.hash) || (isAuthorizationResponse(url) && storage.getItem(INPUT_PENDING_KEY) !== null);
}

/**
 * Decide which controller a page load runs. A dashboard load that is not a
 * sign-in callback also deletes a pending input sign-in (with its secret name)
 * that this tab started and never finished.
 */
export function dispatchPage(url: URL, storage: Pick<Storage, 'getItem' | 'removeItem'>): 'input' | 'dashboard' {
  if (isInputPage(url, storage)) return 'input';
  if (!isAuthorizationResponse(url)) storage.removeItem(INPUT_PENDING_KEY);
  return 'dashboard';
}

function reloadOnInputLink(): void {
  // Another input link pasted into this tab: start over from a fresh page (the pagehide revokes this one's grant).
  window.addEventListener('hashchange', () => {
    if (isInputFragment(window.location.hash)) window.location.reload();
  });
}

function mainInput(root: HTMLElement): void {
  const controller = new InputController({
    origin: window.location.origin,
    fetchFn: window.fetch.bind(window),
    pending: sessionPendingStore(window.sessionStorage, INPUT_PENDING_KEY),
    navigate: (url) => window.location.assign(url),
    replaceUrl: (url) => window.history.replaceState(null, '', url),
  });
  controller.subscribe((s) => renderInput(root, controller, s));
  reloadOnInputLink();
  window.addEventListener('pagehide', (ev) => {
    if (!(ev as PageTransitionEvent).persisted) controller.revokeOnExit();
  });
  void controller.boot(new URL(window.location.href));
}

function main(): void {
  const root = document.getElementById('app');
  if (!root) return;
  const url = new URL(window.location.href);
  if (dispatchPage(url, window.sessionStorage) === 'input') {
    mainInput(root);
    return;
  }
  const controller = new AppController({
    origin: window.location.origin,
    fetchFn: window.fetch.bind(window),
    pending: sessionPendingStore(window.sessionStorage),
    devices: indexedDbDeviceStore(window.indexedDB),
    subtle: window.crypto.subtle,
    navigate: (url) => window.location.assign(url),
    replaceUrl: (url) => window.history.replaceState(null, '', url),
    // Absent in old browsers and insecure contexts; generation then runs unlocked.
    ...(typeof navigator.locks?.request === 'function' ? { locks: navigator.locks } : {}),
  });
  const vs = newViewState();
  const rerender = () => render(root, controller, controller.current(), vs, rerender);
  controller.subscribe(() => rerender());
  startIdleLock(controller, window);
  // A write-request link opened in this tab while it is running changes only the fragment.
  window.addEventListener('hashchange', () => void controller.openLink(new URL(window.location.href)));
  reloadOnInputLink();
  window.addEventListener('pagehide', (ev) => {
    if (!(ev as PageTransitionEvent).persisted) controller.revokeOnExit();
  });
  void controller.boot(url);
}

if (typeof window !== 'undefined' && typeof document !== 'undefined' && document.getElementById('app')) main();
