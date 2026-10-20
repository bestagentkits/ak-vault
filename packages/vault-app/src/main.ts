/**
 * Entry point. Wires the controller to the browser: sessionStorage for the
 * pending sign-in only, IndexedDB for the device, a 15-minute idle lock, and a
 * keepalive revocation when the page is hidden for good.
 */
import { AppController } from './app-controller.js';
import { indexedDbDeviceStore } from './keys/device-store.js';
import { sessionPendingStore } from './oauth/pkce-client.js';
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

function main(): void {
  const root = document.getElementById('app');
  if (!root) return;
  const controller = new AppController({
    origin: window.location.origin,
    fetchFn: window.fetch.bind(window),
    pending: sessionPendingStore(window.sessionStorage),
    devices: indexedDbDeviceStore(window.indexedDB),
    subtle: window.crypto.subtle,
    navigate: (url) => window.location.assign(url),
    replaceUrl: (url) => window.history.replaceState(null, '', url),
  });
  const vs = newViewState();
  const rerender = () => render(root, controller, controller.current(), vs, rerender);
  controller.subscribe(() => rerender());
  startIdleLock(controller, window);
  window.addEventListener('pagehide', (ev) => {
    if (!(ev as PageTransitionEvent).persisted) controller.revokeOnExit();
  });
  void controller.boot(new URL(window.location.href));
}

if (typeof window !== 'undefined' && typeof document !== 'undefined' && document.getElementById('app')) main();
