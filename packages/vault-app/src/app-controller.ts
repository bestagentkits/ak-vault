/**
 * Dashboard controller: sign-in, device, enrollment, sync and writes, behind
 * one observable screen state. It holds every token, vault key and the verified
 * snapshot in memory only; locking, signing out or leaving the page drops them
 * and revokes the sign-in grant. Errors become fixed codes; nothing a server or
 * another device wrote reaches an error message.
 */
import { b64encode, randomId, type DeviceKx, type DeviceSigner } from '@ak-vault/protocol';
import { AppError, appErrorCode, type AppErrorCode } from './app-error.js';
import { loadAppConfig, type AppConfig } from './config.js';
import { isWitnessedOlder, type DeviceStore, type StoredDevice } from './keys/device-store.js';
import { deviceIdOf, deviceKx, deviceSigner, generateDeviceKeys } from './keys/webcrypto-device-keys.js';
import {
  beginSignIn,
  completeSignIn,
  discoverAuthServer,
  isAuthorizationResponse,
  refreshSession,
  revokeSession,
  type AuthServerMetadata,
  type OAuthSession,
  type PendingStore,
} from './oauth/pkce-client.js';
import { createAkvClient, isVaultApiError, type AkvClient } from './sync/akv-client.js';
import { acceptOffer, DEFAULT_DEVICE_LABEL, joinCodeFor, newJoinNonce, sanitizeLabel } from './sync/enroll.js';
import { pullVault, type ItemView, type VaultSnapshot } from './sync/vault-sync.js';
import {
  cancelWriteRequest,
  claimWriteRequest,
  completeWriteRequest,
  failWriteRequest,
  loadWriteRequest,
  requestIdFromHash,
  type WriteRequestStore,
  type WriteRequestView,
} from './sync/write-intent.js';
import { deleteItem, findByName, planWrite, setItem } from './sync/write-ops.js';
import { exchangeSyncToken, type SyncToken } from './vault/token-exchange.js';

export type Notice = { kind: 'info' | 'error'; code: AppErrorCode | 'locked' | 'saved' | 'deleted' | 'signed_out' | 'write_cancelled' };

export type Screen =
  | { kind: 'loading' }
  | { kind: 'fatal'; code: AppErrorCode }
  | { kind: 'signed_out'; notice: Notice | null }
  | { kind: 'join'; joinCode: string; deviceId: string; notice: Notice | null }
  | { kind: 'approve'; sas: string; deviceId: string; notice: Notice | null }
  | { kind: 'vault'; items: ItemView[]; matches: string[] | null; unreadable: number; hidden: number; rekeyRequired: boolean; deviceId: string; notice: Notice | null; busy: boolean }
  | { kind: 'write'; request: WriteRequestView; deviceId: string; notice: Notice | null; busy: boolean }
  | { kind: 'removed' };

export interface ControllerDeps {
  origin: string;
  fetchFn: typeof fetch;
  pending: PendingStore;
  devices: DeviceStore;
  subtle: SubtleCrypto;
  /** Leave the page for the authorization server. */
  navigate(url: string): void;
  /** Replace the current URL without a navigation (drops the code and state). */
  replaceUrl(url: string): void;
  /**
   * Web Locks, shared by every tab of this origin. First-time device key
   * generation runs under a lock so two tabs cannot each create a device.
   * Without it (an old browser) generation runs unlocked.
   */
  locks?: Pick<LockManager, 'request'>;
  /** Keeps a write request's ID across the sign-in redirect; without it a request is lost at sign-in. */
  writeRequest?: WriteRequestStore;
  now?: () => number;
}

/** Web Lock name for creating an account's device. */
export const DEVICE_LOCK_PREFIX = 'akv-device:';

/** Refresh a token this long before it expires (seconds). */
const EXPIRY_MARGIN_S = 30;

export class AppController {
  private screen: Screen = { kind: 'loading' };
  private readonly listeners = new Set<(s: Screen) => void>();
  private config: AppConfig | null = null;
  private as: AuthServerMetadata | null = null;
  private session: OAuthSession | null = null;
  private syncToken: SyncToken | null = null;
  private device: StoredDevice | null = null;
  private signer: DeviceSigner | null = null;
  private kx: DeviceKx | null = null;
  private client: AkvClient | null = null;
  private snapshot: VaultSnapshot | null = null;
  private readonly now: () => number;

  constructor(private readonly deps: ControllerDeps) {
    this.now = deps.now ?? Date.now;
  }

  subscribe(fn: (s: Screen) => void): () => void {
    this.listeners.add(fn);
    fn(this.screen);
    return () => this.listeners.delete(fn);
  }

  current(): Screen {
    return this.screen;
  }

  private show(screen: Screen): void {
    this.screen = screen;
    for (const fn of this.listeners) fn(screen);
  }

  /** Start: load config and AS metadata, then finish a sign-in if this is the callback. */
  async boot(url: URL): Promise<void> {
    try {
      this.config = await loadAppConfig(this.deps.fetchFn, this.deps.origin);
      this.as = await discoverAuthServer(this.deps.fetchFn, this.config.issuer);
    } catch (err) {
      this.show({ kind: 'fatal', code: appErrorCode(err, 'config_invalid') });
      return;
    }
    if (!isAuthorizationResponse(url)) {
      this.deps.pending.take();
      // A write request link carries its ID in the fragment: keep it for after sign-in and
      // take it out of the address bar and history.
      this.acceptWriteFragment(url);
      this.show({ kind: 'signed_out', notice: null });
      return;
    }
    // The code and state leave the address bar and history before anything else runs.
    this.deps.replaceUrl(this.config.redirectUri);
    try {
      this.session = await completeSignIn(url, { config: this.config, as: this.as, store: this.deps.pending, fetchFn: this.deps.fetchFn, now: this.now() });
    } catch (err) {
      this.show({ kind: 'signed_out', notice: { kind: 'error', code: appErrorCode(err, 'signin_refused') } });
      return;
    }
    await this.openDevice();
  }

  /** Remember the request ID in `#write=<id>` and clear the fragment; true when there was one. */
  private acceptWriteFragment(url: URL): boolean {
    const rid = requestIdFromHash(url.hash);
    if (rid === null || !this.config) return false;
    this.deps.writeRequest?.set(rid);
    this.deps.replaceUrl(this.config.redirectUri);
    return true;
  }

  /** A write request link opened in a page that is already running (a fragment-only navigation). */
  async openWriteLink(url: URL): Promise<void> {
    if (!this.acceptWriteFragment(url)) return;
    if (this.screen.kind === 'vault' && !this.screen.busy) await this.openWrite();
  }

  /** Begin a sign-in. A grant still held in memory is revoked first. */
  async signIn(): Promise<void> {
    if (!this.config || !this.as) return;
    await this.dropSession(false);
    this.deps.navigate(beginSignIn(this.config, this.as, this.deps.pending, this.now()));
  }

  /** Lock: forget tokens, keys and the snapshot and revoke the grant. The device stays enrolled. */
  async lock(code: 'locked' | 'signed_out' = 'locked'): Promise<void> {
    await this.dropSession(false);
    this.show({ kind: 'signed_out', notice: { kind: 'info', code } });
  }

  /** Page is going away: revoke with keepalive, without waiting. */
  revokeOnExit(): void {
    void this.dropSession(true);
  }

  private async dropSession(keepalive: boolean): Promise<void> {
    const session = this.session;
    this.session = null;
    this.syncToken = null;
    this.snapshot = null;
    this.client = null;
    this.signer = null;
    this.kx = null;
    this.device = null;
    if (session && this.config && this.as) await revokeSession(session, { config: this.config, as: this.as, fetchFn: this.deps.fetchFn, keepalive });
  }

  /** Load or create this account's device and route to enrollment or the vault. */
  private async openDevice(): Promise<void> {
    const session = this.session!;
    try {
      const device = (await this.deps.devices.get(session.claims.sub)) ?? (await this.createDevice(session.claims.sub));
      this.device = device;
      this.signer = deviceSigner(device.keys, this.deps.subtle);
      this.kx = deviceKx(device.keys, this.deps.subtle);
      this.client = createAkvClient({ origin: this.deps.origin, getToken: (fresh) => this.getSyncToken(fresh), signer: this.signer, fetchFn: this.deps.fetchFn, now: this.now });
      // Bind the device key to this sign-in now, so a mismatch shows before enrollment.
      await this.getSyncToken(true);
    } catch (err) {
      await this.fail(err);
      return;
    }
    await this.route();
  }

  /**
   * Create this account's device under the cross-tab lock, re-reading inside
   * it: a tab that waited finds the device the first tab stored and uses it.
   */
  private async createDevice(account: string): Promise<StoredDevice> {
    const create = async (): Promise<StoredDevice> => {
      const existing = await this.deps.devices.get(account);
      if (existing) return existing;
      const keys = await generateDeviceKeys(this.deps.subtle);
      const device: StoredDevice = { v: 1, account, keys, label: sanitizeLabel(DEFAULT_DEVICE_LABEL), nonceJ: newJoinNonce(), enrollment: null };
      await this.deps.devices.put(device);
      return device;
    };
    const locks = this.deps.locks;
    if (!locks) return create();
    return locks.request(`${DEVICE_LOCK_PREFIX}${account}`, { mode: 'exclusive' }, create);
  }

  private async route(notice: Notice | null = null): Promise<void> {
    const device = this.device!;
    const deviceId = deviceIdOf(device.keys);
    if (!device.enrollment) {
      this.show({ kind: 'join', joinCode: joinCodeFor(device), deviceId, notice });
      return;
    }
    if (!device.enrollment.confirmed) {
      this.show({ kind: 'approve', sas: device.enrollment.sas, deviceId, notice });
      return;
    }
    await this.sync(notice);
  }

  private async getSyncToken(fresh: boolean): Promise<SyncToken> {
    const nowS = Math.floor(this.now() / 1000);
    if (!fresh && this.syncToken && this.syncToken.expiresAt - EXPIRY_MARGIN_S > nowS) return this.syncToken;
    if (!this.session || !this.device || !this.signer || !this.config || !this.as) throw new AppError('signin_required');
    if (this.session.expiresAt - EXPIRY_MARGIN_S <= nowS) {
      this.session = await refreshSession(this.session, { config: this.config, as: this.as, fetchFn: this.deps.fetchFn, now: this.now() });
    }
    this.syncToken = await exchangeSyncToken({
      config: this.config,
      session: this.session,
      deviceId: deviceIdOf(this.device.keys),
      signPub: b64encode(this.device.keys.signPub),
      signer: this.signer,
      fetchFn: this.deps.fetchFn,
      now: this.now(),
    });
    return this.syncToken;
  }

  /** Paste the owner's offer code: verify it answers this device and show the SAS. */
  async submitOffer(code: string): Promise<void> {
    const device = this.device;
    if (!device || !this.config) return;
    try {
      const enrollment = acceptOffer(code, device, this.config.origin);
      const next = { ...device, enrollment };
      await this.deps.devices.put(next);
      this.device = next;
    } catch (err) {
      this.show({ kind: 'join', joinCode: joinCodeFor(device), deviceId: deviceIdOf(device.keys), notice: { kind: 'error', code: appErrorCode(err, 'enroll_code_invalid') } });
      return;
    }
    await this.route();
  }

  /** Discard a pending offer and show the join code again (same device keys). */
  async restartEnrollment(): Promise<void> {
    const device = this.device;
    if (!device || device.enrollment?.confirmed) return;
    const next: StoredDevice = { ...device, nonceJ: newJoinNonce(), enrollment: null };
    await this.deps.devices.put(next);
    this.device = next;
    await this.route();
  }

  async checkApproval(): Promise<void> {
    await this.sync(null);
  }

  async refresh(): Promise<void> {
    await this.sync(null);
  }

  private async sync(notice: Notice | null): Promise<void> {
    const device = this.device;
    if (!device || !this.client || !this.kx) return;
    const pendingApproval = !device.enrollment?.confirmed;
    try {
      const { snapshot, enrollment } = await pullVault(this.client, device, this.kx);
      // Pulls can overlap (a refresh during a write's sync). The device may have
      // been dropped meanwhile, or a later pull may already have finished.
      const latest = this.device;
      if (!latest || latest.account !== device.account || deviceIdOf(latest.keys) !== deviceIdOf(device.keys)) return;
      const floor = latest.enrollment?.witnessed;
      if (this.snapshot && floor && enrollment.witnessed && isWitnessedOlder(enrollment.witnessed, floor)) {
        // Older than what is shown and stored: keep the newer snapshot and position.
        this.showVault(notice, null);
        return;
      }
      const next: StoredDevice = { ...latest, enrollment };
      // Never persist a position older than the stored one (another tab may have advanced it).
      const stored = await this.deps.devices.get(device.account);
      const storedFloor = stored && deviceIdOf(stored.keys) === deviceIdOf(next.keys) ? stored.enrollment?.witnessed : null;
      if (!storedFloor || !enrollment.witnessed || !isWitnessedOlder(enrollment.witnessed, storedFloor)) await this.deps.devices.put(next);
      this.device = next;
      this.snapshot = snapshot;
      if (this.deps.writeRequest?.get()) {
        await this.openWrite(notice);
        return;
      }
      this.showVault(notice, null);
    } catch (err) {
      if (pendingApproval) {
        const code = isVaultApiError(err, 'forbidden') ? 'enroll_not_approved' : appErrorCode(err, 'server');
        if (code === 'enroll_not_approved' || code === 'enroll_sas_mismatch' || code === 'network' || code === 'server') {
          this.show({ kind: 'approve', sas: device.enrollment!.sas, deviceId: deviceIdOf(device.keys), notice: { kind: 'error', code } });
          return;
        }
      }
      await this.fail(err);
    }
  }

  private showVault(notice: Notice | null, matches: string[] | null, busy = false): void {
    const s = this.snapshot!;
    this.show({
      kind: 'vault', items: s.items, matches, unreadable: s.unreadable, hidden: s.hidden, rekeyRequired: s.state.rekey_required,
      deviceId: s.self.device_id, notice, busy,
    });
  }

  /** Read the pending write request and show its form, or the vault with the reason it cannot be shown. */
  private async openWrite(notice: Notice | null = null): Promise<void> {
    const store = this.deps.writeRequest;
    const rid = store?.get();
    if (!store || !rid || !this.snapshot || !this.client) return;
    try {
      const request = await loadWriteRequest(this.client, this.snapshot, rid);
      try {
        planWrite(this.snapshot, request.name, request.operation);
      } catch (err) {
        // The vault no longer fits the request (a create of an existing name, a replace of a missing one).
        await failWriteRequest(this.client, rid, 'conflict').catch(() => undefined);
        throw err;
      }
      this.showWrite(request, notice, false);
    } catch (err) {
      store.clear();
      await this.writeRequestFailed(err, 'failed');
    }
  }

  private showWrite(request: WriteRequestView, notice: Notice | null, busy: boolean): void {
    this.show({ kind: 'write', request, deviceId: this.snapshot!.self.device_id, notice, busy });
  }

  /**
   * Type the value for the open write request: bind this device and the item revision
   * to the request, write the sealed and signed record like any other set, then ask
   * the server to confirm. The value is used here and dropped; it is never sent to the
   * request routes.
   */
  async submitWrite(value: string, sensitivity: 'normal' | 'high'): Promise<boolean> {
    const screen = this.screen;
    const store = this.deps.writeRequest;
    if (screen.kind !== 'write' || !store || !this.snapshot || !this.client || !this.signer) return false;
    const { request } = screen;
    this.showWrite(request, null, true);
    let claimed = false;
    try {
      const plan = planWrite(this.snapshot, request.name, request.operation);
      const itemId = plan.itemId ?? randomId();
      await claimWriteRequest(this.client, request.requestId, itemId, plan.baseRevision);
      claimed = true;
      await setItem({
        client: this.client, snapshot: this.snapshot, signer: this.signer, name: request.name, value, nowMs: this.now(),
        ...(plan.itemId === null ? { newItemId: itemId, sensitivity } : {}),
      });
      await completeWriteRequest(this.client, request.requestId);
    } catch (err) {
      const reason = appErrorCode(err, 'server') === 'conflict' ? 'conflict' : 'failed';
      if (claimed) await failWriteRequest(this.client, request.requestId, reason).catch(() => undefined);
      store.clear();
      await this.writeRequestFailed(err, reason);
      return false;
    }
    store.clear();
    await this.sync({ kind: 'info', code: 'saved' });
    return true;
  }

  /** The user declined: close the request so the assistant sees `cancelled`. */
  async cancelWrite(): Promise<void> {
    const screen = this.screen;
    const store = this.deps.writeRequest;
    if (screen.kind !== 'write' || !store || !this.client || !this.snapshot) return;
    this.showWrite(screen.request, null, true);
    try {
      await cancelWriteRequest(this.client, screen.request.requestId);
    } catch {
      /* an expired or settled request is already closed */
    }
    store.clear();
    this.showVault({ kind: 'info', code: 'write_cancelled' }, null);
  }

  private async writeRequestFailed(err: unknown, reason: 'conflict' | 'failed'): Promise<void> {
    if (isVaultApiError(err)) {
      // unauthorized is a lost sign-in; every other refusal means the request cannot be used.
      if (err.code === 'unauthorized') return this.fail(err);
      const gone = ['not_found', 'conflict', 'forbidden', 'bad_request'].includes(err.code);
      this.showVault({ kind: 'error', code: gone ? 'write_request_gone' : 'server' }, null);
      return;
    }
    const code = appErrorCode(err, 'server');
    // A stale snapshot is the usual cause of a conflict: pull again so the vault view is current.
    if (code === 'conflict' || reason === 'conflict') {
      await this.sync({ kind: 'error', code });
      return;
    }
    await this.writeFailed(err);
  }

  /** Exact-name search over the verified snapshot, with no server request; an empty query clears it. */
  async search(name: string): Promise<void> {
    if (!this.snapshot) return;
    if (name === '') {
      this.showVault(null, null);
      return;
    }
    try {
      this.showVault(null, findByName(this.snapshot, name));
    } catch (err) {
      await this.writeFailed(err);
    }
  }

  async set(name: string, value: string): Promise<boolean> {
    return this.write('saved', () => setItem({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, name, value, nowMs: this.now() }));
  }

  async remove(itemId: string): Promise<boolean> {
    return this.write('deleted', () => deleteItem({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, nowMs: this.now() }));
  }

  private async write(done: 'saved' | 'deleted', op: () => Promise<unknown>): Promise<boolean> {
    if (!this.snapshot || !this.client || !this.signer) return false;
    this.showVault(null, null, true);
    try {
      await op();
    } catch (err) {
      await this.writeFailed(err);
      return false;
    }
    await this.sync({ kind: 'info', code: done });
    return true;
  }

  private async writeFailed(err: unknown): Promise<void> {
    const code = appErrorCode(err, 'server');
    const recoverable: AppErrorCode[] = ['conflict', 'rekey_required', 'invalid_name', 'value_too_large', 'duplicate_name', 'not_found', 'item_unreadable', 'quota_exceeded', 'write_request_gone', 'network', 'server'];
    if (!isVaultApiError(err) && recoverable.includes(code)) {
      // A conflict means the verified head is stale: pull again, then say why the write did not land.
      if (code === 'conflict') await this.sync({ kind: 'error', code });
      else this.showVault({ kind: 'error', code }, null);
      return;
    }
    await this.fail(err);
  }

  /** Terminal handling: a removed device wipes its local state; a lost sign-in returns to the start. */
  private async fail(err: unknown): Promise<void> {
    let code = appErrorCode(err, 'server');
    if (isVaultApiError(err)) code = err.code === 'forbidden' ? 'device_removed' : err.code === 'unauthorized' ? 'signin_required' : err.code === 'rekey_required' ? 'rekey_required' : 'server';
    if (code === 'device_removed') {
      const account = this.device?.account ?? this.session?.claims.sub;
      if (account) await this.deps.devices.delete(account).catch(() => undefined);
      await this.dropSession(false);
      this.show({ kind: 'removed' });
      return;
    }
    if (code === 'signin_required' || code === 'signin_refused') {
      await this.dropSession(false);
      this.show({ kind: 'signed_out', notice: { kind: 'error', code } });
      return;
    }
    if (this.snapshot && (code === 'network' || code === 'server' || code === 'rekey_required')) {
      this.showVault({ kind: 'error', code }, null);
      return;
    }
    await this.dropSession(false);
    this.show({ kind: 'fatal', code });
  }
}
