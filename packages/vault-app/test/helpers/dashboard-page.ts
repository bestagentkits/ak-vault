/** Drive the real controller and views against a FakeWorld, one "page load" at a time. */
import { AppController } from '../../src/app-controller.js';
import { memoryDeviceStore } from '../../src/keys/device-store.js';
import { newViewState, render } from '../../src/ui/views.js';
import { FakeWorld, ORIGIN, memoryPendingStore } from './fake-world.js';

export interface Page {
  controller: AppController;
  root: HTMLElement;
  navigated: string[];
  replaced: string[];
}

export class Browser {
  readonly pending = memoryPendingStore();
  readonly devices = memoryDeviceStore();
  page: Page | null = null;

  constructor(readonly world: FakeWorld) {}

  /** Load /app (or a callback URL) in a fresh page that shares storage with earlier loads. */
  async load(url: string | URL = `${ORIGIN}/app/`): Promise<Page> {
    document.body.textContent = '';
    const root = document.createElement('div');
    root.id = 'app';
    document.body.appendChild(root);
    const navigated: string[] = [];
    const replaced: string[] = [];
    const controller = new AppController({
      origin: ORIGIN,
      fetchFn: this.world.fetch as typeof fetch,
      pending: this.pending,
      devices: this.devices,
      subtle: crypto.subtle,
      navigate: (u) => navigated.push(u),
      replaceUrl: (u) => replaced.push(u),
    });
    const vs = newViewState();
    const rerender = (): void => render(root, controller, controller.current(), vs, rerender);
    controller.subscribe(rerender);
    await controller.boot(new URL(url));
    this.page = { controller, root, navigated, replaced };
    return this.page;
  }

  /** Full sign-in round trip through the authorization server; returns the callback page. */
  async signIn(opts: { state?: string; iss?: string } = {}): Promise<Page> {
    const start = this.page ?? (await this.load());
    await start.controller.signIn();
    const authUrl = start.navigated.at(-1);
    if (!authUrl) throw new Error('no navigation');
    return this.load(this.world.authorize(authUrl, opts));
  }

  /** Sign in, show the join code, have the owner answer and approve it, and reach the vault. */
  async enroll(): Promise<{ page: Page; sas: string; ownerSas: string }> {
    const page = await this.signIn();
    const joinCode = byTestId(page.root, 'join-code').textContent!;
    const offer = this.world.offerFor(joinCode);
    await page.controller.submitOffer(offer.code);
    const sas = byTestId(page.root, 'sas').textContent!.replace(/\s/g, '');
    this.world.approve(joinCode, offer.nonceI);
    await page.controller.checkApproval();
    return { page, sas, ownerSas: offer.sas };
  }
}

export function byTestId(root: ParentNode, id: string): HTMLElement {
  const el = root.querySelector(`[data-testid="${id}"]`);
  if (!el) throw new Error(`missing ${id}`);
  return el as HTMLElement;
}

export function allByTestId(root: ParentNode, id: string): HTMLElement[] {
  return [...root.querySelectorAll(`[data-testid="${id}"]`)] as HTMLElement[];
}
