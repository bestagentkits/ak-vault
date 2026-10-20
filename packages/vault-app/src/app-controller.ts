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
import { isWitnessedOlder, mergeWitnessed, type DeviceStore, type StoredDevice, type WitnessedState } from './keys/device-store.js';
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
import { deleteItem, findByName, setItem } from './sync/write-ops.js';
import { exchangeSyncToken, type SyncToken } from './vault/token-exchange.js';

export type Notice = { kind: 'info' | 'error'; code: AppErrorCode | 'locked' | 'saved' | 'deleted' | 'signed_out' };

export type Screen =
  | { kind: 'loading' }
  | { kind: 'fatal'; code: AppErrorCode }
  | { kind: 'signed_out'; notice: Notice | null }
  | { kind: 'join'; joinCode: string; deviceId: string; notice: Notice | null }
  | { kind: 'approve'; sas: string; deviceId: string; notice: Notice | null }
  | { kind: 'vault'; items: ItemView[]; matches: string[] | null; unreadable: number; hidden: number; rekeyRequired: boolean; deviceId: string; notice: Notice | null; busy: boolean }
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

/** The server's `Date` header and this device's clock may differ by this much (ms) before tokens and proofs fail. */
export const MAX_CLOCK_SKEW_MS = 60_000;

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
  /** `deps.fetchFn` plus a note of the vault origin's clock, read from its `Date` header. */
  private readonly fetchFn: typeof fetch;
  private skewMs = 0;

  constructor(private readonly deps: ControllerDeps) {
    this.now = deps.now ?? Date.now;
    this.fetchFn = async (input, init) => {
      const res = await deps.fetchFn(input, init);
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url.startsWith(`${deps.origin}/`)) {
        const server = Date.parse(res.headers.get('Date') ?? '');
        if (Number.isFinite(server)) this.skewMs = server - this.now();
      }
      return res;
    };
  }

  /** True when the vault origin's clock, as last seen, is far enough from ours to fail time checks. */
  private clockSkewed(): boolean {
    return Math.abs(this.skewMs) > MAX_CLOCK_SKEW_MS;
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
      this.config = await loadAppConfig(this.fetchFn, this.deps.origin);
      this.as = await discoverAuthServer(this.fetchFn, this.config.issuer);
    } catch (err) {
      this.show({ kind: 'fatal', code: appErrorCode(err, 'config_invalid') });
      return;
    }
    if (!isAuthorizationResponse(url)) {
      this.deps.pending.take();
      this.show({ kind: 'signed_out', notice: this.clockSkewed() ? { kind: 'error', code: 'clock_skew' } : null });
      return;
    }
    // The code and state leave the address bar and history before anything else runs.
    this.deps.replaceUrl(this.config.redirectUri);
    try {
      this.session = await completeSignIn(url, { config: this.config, as: this.as, store: this.deps.pending, fetchFn: this.fetchFn, now: this.now() });
    } catch (err) {
      const code = appErrorCode(err, 'signin_refused');
      this.show({ kind: 'signed_out', notice: { kind: 'error', code: this.clockSkewed() && (code === 'signin_refused' || code === 'token_exchange_failed') ? 'clock_skew' : code } });
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
    this.client = null;
    this.signer = null;
    this.kx = null;
    this.device = null;
    if (session && this.config && this.as) await revokeSession(session, { config: this.config, as: this.as, fetchFn: this.fetchFn, keepalive });
  }

  /** Load or create this account's device and route to enrollment or the vault. */
  private async openDevice(): Promise<void> {
    const session = this.session!;
    try {
      const device = (await this.deps.devices.get(session.claims.sub)) ?? (await this.createDevice(session.claims.sub));
      this.device = device;
      this.signer = deviceSigner(device.keys, this.deps.subtle);
      this.kx = deviceKx(device.keys, this.deps.subtle);
      this.client = createAkvClient({ origin: this.deps.origin, getToken: (fresh) => this.getSyncToken(fresh), signer: this.signer, fetchFn: this.fetchFn, now: this.now });
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
      this.session = await refreshSession(this.session, { config: this.config, as: this.as, fetchFn: this.fetchFn, now: this.now() });
    }
    this.syncToken = await exchangeSyncToken({
      config: this.config,
      session: this.session,
      deviceId: deviceIdOf(this.device.keys),
      signPub: b64encode(this.device.keys.signPub),
      signer: this.signer,
      fetchFn: this.fetchFn,
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
    // Everything the pull needs is captured now: a lock or sign-out during an await drops the fields.
    const start = this.device;
    const client = this.client;
    const kx = this.kx;
    if (!start || !client || !kx) return;
    const pendingApproval = !start.enrollment?.confirmed;
    try {
      // Another tab may have stored a newer position since this one last pulled.
      const device = await this.withStoredPosition(start);
      if (!this.sameDevice(device)) return;
      const { snapshot, enrollment } = await pullVault(client, device, kx, this.snapshot);
      // Pulls can overlap (a refresh during a write's sync): the device may have been dropped, or a
      // later pull may already have finished and advanced the position this one must not undo.
      const latest = this.device;
      if (!latest || !this.sameDevice(device)) return;
      const floor = this.floorOf(latest, device);
      if (floor === 'fork') throw new AppError('fork');
      if (floor && enrollment.witnessed) {
        if (mergeWitnessed(floor, enrollment.witnessed) === null) throw new AppError('fork');
        if (this.snapshot && isWitnessedOlder(enrollment.witnessed, floor)) {
          // Older than what is shown and stored: keep the newer snapshot and position.
          this.showVault(notice, null);
          return;
        }
      }
      // One transaction merges with the stored position and writes, so an older pull never lands.
      const saved = await this.deps.devices.advance({ ...latest, enrollment });
      if (!this.sameDevice(device)) return;
      if (saved.outcome === 'fork') throw new AppError('fork');
      // The entry is gone or re-enrolled elsewhere: this view no longer matches what is stored.
      if (saved.outcome === 'stale') throw new AppError('signin_required');
      const position = saved.position ?? enrollment.witnessed;
      this.device = { ...latest, enrollment: { ...enrollment, witnessed: position } };
      // Another tab is further along: keep the newer view already shown, if any.
      if (!(saved.outcome === 'older' && this.snapshot)) this.snapshot = snapshot;
      this.showVault(notice, null);
    } catch (err) {
      // Locked, signed out or replaced while the pull was in flight: that state stands, not this pull's error.
      if (!this.sameDevice(start)) return;
      if (pendingApproval && this.device) {
        const code = isVaultApiError(err, 'forbidden') ? 'enroll_not_approved' : appErrorCode(err, 'server');
        if (code === 'enroll_not_approved' || code === 'enroll_sas_mismatch' || code === 'network' || code === 'server') {
          this.show({ kind: 'approve', sas: start.enrollment!.sas, deviceId: deviceIdOf(start.keys), notice: { kind: 'error', code } });
          return;
        }
      }
      await this.fail(err);
    }
  }

  /** True while the device this pull started with is still the one held (not dropped, not another account's). */
  private sameDevice(device: StoredDevice): boolean {
    const held = this.device;
    return held !== null && held.account === device.account && deviceIdOf(held.keys) === deviceIdOf(device.keys);
  }

  /** The furthest position this tab holds: the pull's starting device and whatever a finished pull stored since. */
  private floorOf(latest: StoredDevice, started: StoredDevice): WitnessedState | 'fork' | null {
    const a = latest.enrollment?.witnessed;
    const b = started.enrollment?.witnessed;
    if (!a || !b) return a ?? b ?? null;
    return mergeWitnessed(a, b) ?? 'fork';
  }

  /** The device with the furthest verified position of this tab's and the store's (same device and enrollment only). */
  private async withStoredPosition(device: StoredDevice): Promise<StoredDevice> {
    const stored = await this.deps.devices.get(device.account);
    const have = device.enrollment;
    const there = stored?.enrollment;
    if (!stored || !have || !there?.witnessed) return device;
    if (deviceIdOf(stored.keys) !== deviceIdOf(device.keys) || there.vaultId !== have.vaultId || there.nonceI !== have.nonceI || stored.nonceJ !== device.nonceJ) return device;
    // A counter at the same value with another head is left for the compare-and-save to report as a fork.
    const merged = have.witnessed ? mergeWitnessed(have.witnessed, there.witnessed) : there.witnessed;
    return merged ? { ...device, enrollment: { ...have, witnessed: merged } } : device;
  }

  private showVault(notice: Notice | null, matches: string[] | null, busy = false): void {
    const s = this.snapshot!;
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
    const recoverable: AppErrorCode[] = ['conflict', 'rekey_required', 'invalid_name', 'value_too_large', 'duplicate_name', 'not_found', 'item_unreadable', 'quota_exceeded', 'network', 'server'];
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
    // Time-bound checks fail on a skewed clock and look like a lost sign-in: say so instead of looping.
    if (this.clockSkewed() && (code === 'signin_required' || code === 'signin_refused' || code === 'token_exchange_failed')) code = 'clock_skew';
    if (code === 'device_removed') {
      const account = this.device?.account ?? this.session?.claims.sub;
      if (account) await this.deps.devices.delete(account).catch(() => undefined);
      await this.dropSession(false);
      this.show({ kind: 'removed' });
      return;
    }
    if (code === 'signin_required' || code === 'signin_refused' || code === 'clock_skew') {
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
