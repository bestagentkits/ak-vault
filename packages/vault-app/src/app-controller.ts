/**
 * Dashboard controller: sign-in, device, enrollment, sync and writes, behind
 * one observable screen state. It holds every token, vault key and the verified
 * snapshot in memory only; locking, signing out or leaving the page drops them
 * and revokes the sign-in grant. Errors become fixed codes; nothing a server or
 * another device wrote reaches an error message.
 */
import { b64encode, type DeviceKx, type DeviceSigner } from '@ak-vault/protocol';
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
import { loadItemHistory, type ItemHistory } from './sync/item-history.js';
import { restoreRevision, settleConflicts, type SettleChoice } from './sync/restore-ops.js';
import { pullVault, type ItemView, type VaultSnapshot } from './sync/vault-sync.js';
import { deleteItem, findByName, setItem } from './sync/write-ops.js';
import { exchangeSyncToken, type SyncToken } from './vault/token-exchange.js';

export type Notice = { kind: 'info' | 'error'; code: AppErrorCode | 'locked' | 'saved' | 'deleted' | 'restored' | 'resolved' | 'signed_out' };

export type Screen =
  | { kind: 'loading' }
  | { kind: 'fatal'; code: AppErrorCode }
  | { kind: 'signed_out'; notice: Notice | null }
  | { kind: 'join'; joinCode: string; deviceId: string; notice: Notice | null }
  | { kind: 'approve'; sas: string; deviceId: string; notice: Notice | null }
  | { kind: 'vault'; items: ItemView[]; matches: string[] | null; unreadable: number; hidden: number; rekeyRequired: boolean; deviceId: string; notice: Notice | null; busy: boolean }
  | { kind: 'history'; item: ItemView; history: ItemHistory | null; canWrite: boolean; deviceId: string; notice: Notice | null; busy: boolean }
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
  /** The item whose history is open, and its verified history once loaded. */
  private historyItem: ItemView | null = null;
  private history: ItemHistory | null = null;
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
    this.historyItem = null;
    this.history = null;
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
    this.historyItem = null;
    this.history = null;
    this.show({
      kind: 'vault', items: s.items, matches, unreadable: s.unreadable, hidden: s.hidden, rekeyRequired: s.state.rekey_required,
      deviceId: s.self.device_id, notice, busy,
    });
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

  private showHistory(notice: Notice | null, busy = false): void {
    const s = this.snapshot!;
    const self = s.self;
    this.show({
      kind: 'history', item: this.historyItem!, history: this.history, deviceId: self.device_id, notice, busy,
      canWrite: self.kind === 'human' && (self.role === 'owner' || self.role === 'editor') && !s.state.rekey_required,
    });
  }

  /**
   * Open one item's history: the whole change log is fetched again and verified
   * before anything is listed, so a server cannot invent or reorder revisions.
   */
  async openHistory(itemId: string): Promise<void> {
    const snapshot = this.snapshot;
    const item = snapshot?.items.find((i) => i.itemId === itemId);
    if (!snapshot || !item || !this.client) return;
    this.historyItem = item;
    this.history = null;
    this.showHistory(null, true);
    try {
      const history = await loadItemHistory(this.client, snapshot, itemId);
      if (this.snapshot !== snapshot || this.historyItem !== item) return;
      this.history = history;
      this.showHistory(null);
    } catch (err) {
      await this.fail(err);
    }
  }

  closeHistory(): void {
    if (this.snapshot) this.showVault(null, null);
  }

  /** Re-load the open history (after a stale notice or a failed restore). */
  async refreshHistory(): Promise<void> {
    if (this.historyItem) await this.openHistory(this.historyItem.itemId);
  }

  /** Write a verified earlier revision as a new revision; the value never reaches the page. */
  async restore(logSeq: number): Promise<boolean> {
    const history = this.history;
    if (!history) return false;
    return this.write('restored', () => restoreRevision({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, history, logSeq, nowMs: this.now() }));
  }

  /** Settle the open conflict branches of the open item with one new revision. */
  async settle(choice: SettleChoice): Promise<boolean> {
    const history = this.history;
    if (!history) return false;
    return this.write('resolved', () => settleConflicts({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, history, choice, nowMs: this.now() }));
  }

  async set(name: string, value: string): Promise<boolean> {
    return this.write('saved', () => setItem({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, name, value, nowMs: this.now() }));
  }

  async remove(itemId: string): Promise<boolean> {
    return this.write('deleted', () => deleteItem({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, nowMs: this.now() }));
  }

  private async write(done: 'saved' | 'deleted' | 'restored' | 'resolved', op: () => Promise<unknown>): Promise<boolean> {
    if (!this.snapshot || !this.client || !this.signer) return false;
    if (this.historyItem) this.showHistory(null, true);
    else this.showVault(null, null, true);
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
    const recoverable: AppErrorCode[] = [
      'conflict', 'rekey_required', 'invalid_name', 'value_too_large', 'duplicate_name', 'not_found', 'item_unreadable', 'quota_exceeded',
      'restore_unavailable', 'restore_unchanged', 'nothing_to_resolve', 'network', 'server',
    ];
    if (!isVaultApiError(err) && recoverable.includes(code)) {
      // A conflict means the verified head is stale: pull again, then say why the write did not land.
      if (code === 'conflict') await this.sync({ kind: 'error', code });
      else if (this.historyItem) this.showHistory({ kind: 'error', code });
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
