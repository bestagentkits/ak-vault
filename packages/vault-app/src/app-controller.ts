/**
 * Dashboard controller: sign-in, device, enrollment, sync, writes and human
 * write requests, behind one observable screen state. It holds every token, vault key and the verified
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
import { buildItemHistory, type ItemHistory } from './sync/history.js';
import { buildMembershipView, roleCanWrite, type MembershipView } from './sync/membership-view.js';
import { openRecord, pullVault, type ItemView, type VaultSnapshot } from './sync/vault-sync.js';
import { appendRotationAudit, type RotationAuditAction } from './sync/audit.js';
import { deleteItem, findByName, requestTarget, restoreRevision, resolveConflicts, rotateValue, setItem, updateRotation, type RotationPatch } from './sync/write-ops.js';
import type { RotationWorkflow } from './sync/rotation.js';
import {
  closeWriteRequest,
  fetchWriteRequest,
  isWriteFragment,
  openWriteRequest,
  parseWriteLink,
  type OpenedWriteRequest,
  type WriteCloseOutcome,
  type WriteLink,
} from './sync/write-request.js';
import { exchangeSyncToken, type SyncToken } from './vault/token-exchange.js';

const STATE_AUDIT_ACTION: Record<RotationWorkflow['state'] | 'cleared', RotationAuditAction> = {
  active: 'rotation_resumed',
  paused: 'rotation_paused',
  failed: 'rotation_failed',
  cancelled: 'rotation_cancelled',
  cleared: 'rotation_cleared',
};

export type WriteNoticeCode =
  | 'write_signin'
  | 'write_enroll'
  | 'write_wrong_vault'
  | 'write_unavailable'
  | 'write_saved'
  | 'write_conflict'
  | 'write_cancelled'
  | 'write_exists'
  | 'write_missing'
  | 'write_device_error';

export type Notice = { kind: 'info' | 'error'; code: AppErrorCode | WriteNoticeCode | 'locked' | 'saved' | 'deleted' | 'restored' | 'resolved' | 'signed_out' | 'rotation_started' | 'rotation_updated' | 'rotation_saved' | 'rotation_revoked' | 'settings_saved' };

/** The write request on screen: its link and, once fetched and opened, its target. */
interface WriteInFlight {
  link: WriteLink;
  opened: OpenedWriteRequest | null;
}

/** What the write-request screen shows about the request. Never a value. */
export interface WriteRequestView {
  name: string;
  purpose: string | null;
  clientId: string;
  operation: 'create' | 'replace';
  /** Unix ms. */
  expiresAt: number;
}

export type Screen =
  | { kind: 'loading' }
  | { kind: 'fatal'; code: AppErrorCode }
  | { kind: 'signed_out'; notice: Notice | null }
  | { kind: 'join'; joinCode: string; deviceId: string; notice: Notice | null }
  | { kind: 'approve'; sas: string; deviceId: string; notice: Notice | null }
  | { kind: 'vault'; items: ItemView[]; matches: string[] | null; unreadable: number; hidden: number; rekeyRequired: boolean; canWrite: boolean; membership: MembershipView; nowMs: number; deviceId: string; notice: Notice | null; busy: boolean }
  | { kind: 'history'; history: ItemHistory; canWrite: boolean; deviceId: string; notice: Notice | null; busy: boolean }
  | { kind: 'write'; deviceId: string; request: WriteRequestView | null; open: boolean; busy: boolean; retry: boolean; receipt: string | null; notice: Notice | null }
  | { kind: 'removed' };

interface WriteScreenState {
  open?: boolean;
  busy?: boolean;
  retry?: boolean;
  receipt?: string | null;
  notice?: Notice | null;
}

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
  /** The item whose history is open; the screen follows it across pulls. */
  private historyItemId: string | null = null;
  /** A write-request link waiting for sign-in, enrollment and sync. */
  private writeLink: WriteLink | null = null;
  /** The write request on screen. */
  private writeReq: WriteInFlight | null = null;
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
      this.writeLink = this.takeWriteLink(url);
      this.show({ kind: 'signed_out', notice: this.writeLink ? { kind: 'info', code: 'write_signin' } : null });
      return;
    }
    // The code and state leave the address bar and history before anything else runs.
    this.deps.replaceUrl(this.config.redirectUri);
    try {
      const done = await completeSignIn(url, { config: this.config, as: this.as, store: this.deps.pending, fetchFn: this.deps.fetchFn, now: this.now() });
      this.session = done.session;
      this.writeLink = done.writeLink;
    } catch (err) {
      this.show({ kind: 'signed_out', notice: { kind: 'error', code: appErrorCode(err, 'signin_refused') } });
      return;
    }
    await this.openDevice();
  }

  /**
   * Read a write-request link from the URL fragment. Any `#write=` fragment
   * leaves the address bar and history at once; only an exact one is kept.
   */
  private takeWriteLink(url: URL): WriteLink | null {
    if (!this.config || !isWriteFragment(url.hash)) return null;
    this.deps.replaceUrl(this.config.redirectUri);
    return parseWriteLink(url.hash);
  }

  /** A write-request link opened in a page that is already running (the fragment changed). */
  async openLink(url: URL): Promise<void> {
    const link = this.takeWriteLink(url);
    if (!link) return;
    const kind = this.screen.kind;
    // A save or close in flight keeps its request; the new link opens once the person leaves that screen.
    if (kind === 'write' && this.screen.busy) {
      this.writeLink = link;
      return;
    }
    if (this.snapshot && (kind === 'vault' || kind === 'write')) {
      await this.openWrite(link);
      return;
    }
    this.writeLink = link;
    if (kind === 'signed_out') this.show({ kind: 'signed_out', notice: { kind: 'info', code: 'write_signin' } });
    else if (kind === 'join' || kind === 'approve') await this.route();
  }

  /** Begin a sign-in. A grant still held in memory is revoked first; a pending write-request link carries over. */
  async signIn(): Promise<void> {
    if (!this.config || !this.as) return;
    const link = this.writeLink ?? this.writeReq?.link ?? null;
    await this.dropSession(false);
    this.deps.navigate(beginSignIn(this.config, this.as, this.deps.pending, this.now(), link));
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
    this.historyItemId = null;
    this.client = null;
    this.signer = null;
    this.kx = null;
    this.device = null;
    this.writeLink = null;
    this.writeReq = null;
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
    if (!device.enrollment?.confirmed && this.writeLink) notice ??= { kind: 'info', code: 'write_enroll' };
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
      const link = this.writeLink;
      if (link) {
        this.writeLink = null;
        await this.openWrite(link);
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
    const history = this.historyItemId === null ? null : this.historyOf(this.historyItemId);
    if (history) {
      this.show({ kind: 'history', history, canWrite: this.canWrite(), deviceId: s.self.device_id, notice, busy });
      return;
    }
    this.historyItemId = null;
    const membership = buildMembershipView(s.state, s.self.device_id, new Map(s.items.map((i) => [i.itemId, i.name])));
    this.show({
      kind: 'vault', items: s.items, matches, unreadable: s.unreadable, hidden: s.hidden, rekeyRequired: s.state.rekey_required,
      canWrite: roleCanWrite(membership.selfRole), membership, nowMs: this.now(), deviceId: s.self.device_id, notice, busy,
    });
  }

  private canWrite(): boolean {
    const s = this.snapshot!;
    return !s.state.rekey_required && s.self.kind === 'human' && roleCanWrite(s.self.role);
  }

  /** The metadata-only history of a live, listed item, from the log this device verified. */
  private historyOf(itemId: string): ItemHistory | null {
    const s = this.snapshot!;
    const item = s.items.find((i) => i.itemId === itemId);
    const itemState = s.itemStates.get(itemId);
    if (!item || !itemState) return null;
    return buildItemHistory({
      itemId, name: item.name, itemState, log: s.log.get(itemId) ?? [], state: s.state, vaultKeys: s.vaultKeys,
      selfDeviceId: s.self.device_id, open: openRecord,
    });
  }

  openHistory(itemId: string): void {
    if (!this.snapshot || !this.historyOf(itemId)) return;
    this.historyItemId = itemId;
    this.showVault(null, null);
  }

  closeHistory(): void {
    if (!this.snapshot) return;
    this.historyItemId = null;
    this.showVault(null, null);
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
    return this.write('saved', (nowMs) => setItem({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, name, value, nowMs }));
  }

  async remove(itemId: string): Promise<boolean> {
    return this.write('deleted', (nowMs) => deleteItem({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, nowMs }));
  }

  /** Write a verified earlier revision's value as a new revision of the item. */
  async restore(itemId: string, logSeq: number): Promise<boolean> {
    return this.write('restored', (nowMs) => restoreRevision({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, logSeq, nowMs }));
  }

  /** Mark every open conflict branch of the item resolved, keeping the current value or adopting one branch's. */
  async resolve(itemId: string, adopt: string | null): Promise<boolean> {
    return this.write('resolved', (nowMs) => resolveConflicts({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, adopt, nowMs }));
  }

  /** Start a rotation: record it in signed metadata. The new credential is created at the provider, not here. */
  async startRotation(itemId: string): Promise<boolean> {
    return this.write('rotation_started', (nowMs) => updateRotation({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, patch: { rotation: { state: 'active', startedMs: nowMs, revokedMs: null } }, nowMs }), { action: 'rotation_started', itemId });
  }

  /** Pause, resume, fail or cancel the workflow, or clear it with `null`. */
  async setRotationState(itemId: string, state: RotationWorkflow['state'] | null): Promise<boolean> {
    const current = this.snapshot?.items.find((i) => i.itemId === itemId)?.rotation ?? null;
    if (!current) return false;
    // Only a paused rotation resumes; a failed or cancelled one starts again from scratch.
    const allowed: Record<RotationWorkflow['state'], RotationWorkflow['state'][]> = {
      active: ['paused', 'failed', 'cancelled'], paused: ['active', 'failed', 'cancelled'], failed: [], cancelled: [],
    };
    if (state !== null && !allowed[current.state].includes(state)) return false;
    const rotation = state === null ? null : { ...current, state };
    const action = state === null ? STATE_AUDIT_ACTION.cleared : STATE_AUDIT_ACTION[state];
    return this.write('rotation_updated', (nowMs) => updateRotation({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, patch: { rotation }, nowMs }), { action, itemId });
  }

  /** The operator says the old provider credential is revoked. Allowed only after the vault holds a new value. */
  async confirmRevoked(itemId: string): Promise<boolean> {
    return this.write('rotation_revoked', (nowMs) => updateRotation({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, patch: { confirmRevoked: true }, nowMs }), { action: 'rotation_revoked', itemId });
  }

  /** Set or clear (`null`) the rotation interval in days. */
  async setRotateTtl(itemId: string, days: number | null): Promise<boolean> {
    const patch: RotationPatch = { rotateTtlDays: days };
    return this.write('settings_saved', (nowMs) => updateRotation({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, patch, nowMs }));
  }

  /** Save the replacement value; the Vault step counts as done only once the new revision is pulled and verified. */
  async rotate(itemId: string, value: string): Promise<boolean> {
    return this.write('rotation_saved', (nowMs) => rotateValue({ client: this.client!, snapshot: this.snapshot!, signer: this.signer!, itemId, value, nowMs }), { action: 'rotation_vault_written', itemId });
  }

  private async write(done: Extract<Notice['code'], 'saved' | 'deleted' | 'restored' | 'resolved' | 'rotation_started' | 'rotation_updated' | 'rotation_saved' | 'rotation_revoked' | 'settings_saved'>, op: (nowMs: number) => Promise<unknown>, audit?: { action: RotationAuditAction; itemId: string }): Promise<boolean> {
    if (!this.snapshot || !this.client || !this.signer) return false;
    this.showVault(null, null, true);
    const nowMs = this.now();
    try {
      await op(nowMs);
    } catch (err) {
      await this.writeFailed(err);
      return false;
    }
    // The write has landed and its signed revision is the record; a failed audit append is reported, never undone.
    let auditFailed = false;
    if (audit) {
      try {
        await appendRotationAudit({ client: this.client, snapshot: this.snapshot, action: audit.action, itemId: audit.itemId, nowMs });
      } catch {
        auditFailed = true;
      }
    }
    await this.sync(auditFailed ? { kind: 'error', code: 'audit_failed' } : { kind: 'info', code: done });
    return true;
  }

  private async writeFailed(err: unknown): Promise<void> {
    // A refused write may mean a stale role (an owner demoted this account since the last pull).
    // Pull again before judging: a removed device is found by the pull itself, anything else keeps its keys.
    if (isVaultApiError(err, 'forbidden')) {
      await this.sync(null);
      // The pull showed the vault (a removed device went to `fail`). Judge the refusal by the role it verified.
      if (this.screen.kind === 'vault' && this.snapshot) {
        const role = buildMembershipView(this.snapshot.state, this.snapshot.self.device_id, new Map()).selfRole;
        this.showVault({ kind: 'error', code: roleCanWrite(role) ? 'write_refused' : 'role_forbidden' }, null);
      }
      return;
    }
    const code = appErrorCode(err, 'server');
    const recoverable: AppErrorCode[] = ['conflict', 'rekey_required', 'invalid_name', 'value_too_large', 'duplicate_name', 'not_found', 'item_unreadable', 'history_unavailable', 'restore_current', 'quota_exceeded', 'invalid_rotation', 'rotation_value_unchanged', 'rotation_not_ready', 'network', 'server'];
    if (!isVaultApiError(err) && recoverable.includes(code)) {
      // A conflict means the verified head is stale: pull again, then say why the write did not land.
      // A lost response may hide a write that landed: pull again so the screen shows the real head.
      if (code === 'conflict' || code === 'network') await this.sync({ kind: 'error', code });
      else this.showVault({ kind: 'error', code }, null);
      return;
    }
    await this.fail(err);
  }

  /**
   * Open a write request for this enrolled, synced device. A link for another
   * vault, or a vault that needs a rekey, is refused without calling the
   * write-request routes.
   */
  private async openWrite(link: WriteLink): Promise<void> {
    const snapshot = this.snapshot;
    if (!snapshot) return;
    this.writeReq = null;
    if (link.vaultId !== snapshot.vaultId) {
      this.showVault({ kind: 'error', code: 'write_wrong_vault' }, null);
      return;
    }
    this.writeReq = { link, opened: null };
    if (snapshot.state.rekey_required) {
      this.showWrite({ notice: { kind: 'error', code: 'rekey_required' } });
      return;
    }
    await this.loadWrite();
  }

  /** Fetch and open the request, then check its target against the verified snapshot. */
  private async loadWrite(): Promise<void> {
    const w = this.writeReq;
    const { snapshot, client } = this;
    if (!w || !snapshot || !client) return;
    this.showWrite({ busy: true });
    let raw: unknown;
    try {
      raw = await fetchWriteRequest(client, w.link);
    } catch (err) {
      if (await this.writeRouteFailed(err)) return;
      this.showWrite({ retry: true, notice: { kind: 'error', code: appErrorCode(err, 'server') === 'network' ? 'network' : 'server' } });
      return;
    }
    if (this.writeReq !== w) return;
    try {
      w.opened = openWriteRequest(snapshot, w.link, raw);
      requestTarget(snapshot, w.opened.name, w.opened.operation);
    } catch (err) {
      await this.refuseWrite(err);
      return;
    }
    this.showWrite({ open: true });
  }

  /** Try loading the request again after a network or server failure. */
  async retryWrite(): Promise<void> {
    const s = this.screen;
    if (s.kind !== 'write' || !s.retry || s.busy) return;
    await this.loadWrite();
  }

  /**
   * Seal, sign and send the value the person typed, completing the request.
   * The value is passed straight to the write and never kept.
   */
  async submitWrite(value: string): Promise<boolean> {
    const s = this.screen;
    const w = this.writeReq;
    const { snapshot, client, signer } = this;
    if (s.kind !== 'write' || !s.open || s.busy || !w?.opened || !snapshot || !client || !signer) return false;
    const o = w.opened;
    this.showWrite({ open: true, busy: true });
    let receipt: string | undefined;
    try {
      receipt = (await setItem({
        client, snapshot, signer, name: o.name, value, nowMs: this.now(),
        request: { requestId: o.requestId, operation: o.operation, sensitivity: o.sensitivity },
      })).receipt;
    } catch (err) {
      if (this.writeReq === w) await this.submitFailed(err, w);
      return false;
    }
    if (this.writeReq !== w) return true;
    this.showWrite({ receipt: receipt ?? null, notice: { kind: 'info', code: 'write_saved' } });
    return true;
  }

  /** Cancel the request: nothing is written and the requesting client sees `cancelled`. */
  async cancelWrite(): Promise<void> {
    const s = this.screen;
    if (s.kind !== 'write' || !s.open || s.busy) return;
    await this.closeWrite({ outcome: 'cancelled', reason: 'user_cancelled' }, { kind: 'info', code: 'write_cancelled' }, true);
  }

  /** Leave the write-request screen for the vault list, refreshed. */
  async leaveWrite(): Promise<void> {
    if (this.screen.kind !== 'write' || this.screen.busy) return;
    this.writeReq = null;
    await this.sync(null);
  }

  private showWrite(st: WriteScreenState): void {
    const o = this.writeReq?.opened ?? null;
    this.show({
      kind: 'write',
      deviceId: this.snapshot!.self.device_id,
      request: o ? { name: o.name, purpose: o.purpose, clientId: o.clientId, operation: o.operation, expiresAt: o.expiresAt } : null,
      open: st.open ?? false,
      busy: st.busy ?? false,
      retry: st.retry ?? false,
      receipt: st.receipt ?? null,
      notice: st.notice ?? null,
    });
  }

  /**
   * Route failures shared by every write-request call. A removed device or a
   * lost sign-in is terminal; a request that is no longer open (closed, expired,
   * revoked or unknown) gets the stale-link message. Returns false when the
   * caller should offer a retry instead.
   */
  private async writeRouteFailed(err: unknown): Promise<boolean> {
    if (isVaultApiError(err, 'forbidden') || isVaultApiError(err, 'unauthorized')) {
      await this.fail(err);
      return true;
    }
    if (isVaultApiError(err) && (err.status === 400 || err.status === 404)) {
      this.showWrite({ notice: { kind: 'error', code: 'write_unavailable' } });
      return true;
    }
    return false;
  }

  /** The device cannot complete the request: close it with the matching closed reason. */
  private async refuseWrite(err: unknown, w = this.writeReq): Promise<void> {
    const code = appErrorCode(err, 'server');
    if (code === 'already_exists') await this.closeWrite({ outcome: 'failed', reason: 'already_exists' }, { kind: 'error', code: 'write_exists' }, false, w);
    else if (code === 'not_found') await this.closeWrite({ outcome: 'failed', reason: 'not_found' }, { kind: 'error', code: 'write_missing' }, false, w);
    else await this.closeWrite({ outcome: 'failed', reason: 'device_error' }, { kind: 'error', code: 'write_device_error' }, false, w);
  }

  /**
   * Report the outcome. A cancel that does not reach the server keeps the form
   * open to try again; a refusal is shown either way, since the request also
   * lapses on its own at expiry.
   */
  private async closeWrite(close: WriteCloseOutcome, done: Notice, retryable: boolean, w = this.writeReq): Promise<void> {
    if (!w || !this.client) return;
    this.showWrite({ open: retryable, busy: true });
    try {
      await closeWriteRequest(this.client, w.link, close);
    } catch (err) {
      if (await this.writeRouteFailed(err)) return;
      if (retryable) {
        this.showWrite({ open: true, notice: { kind: 'error', code: appErrorCode(err, 'server') === 'network' ? 'network' : 'server' } });
        return;
      }
    }
    this.showWrite({ notice: done });
  }

  /** Handle a refused completion of `w`, the request the save started with. */
  private async submitFailed(err: unknown, w: WriteInFlight): Promise<void> {
    const code = appErrorCode(err, 'server');
    if (isVaultApiError(err)) {
      if (err.status === 400 || err.status === 404) {
        // The request may have closed or expired meanwhile: ask before offering a retry.
        try {
          await fetchWriteRequest(this.client!, w.link);
        } catch (again) {
          if (await this.writeRouteFailed(again)) return;
        }
        // Still open yet refused (the target changed after the last sync): retrying the same record cannot succeed.
        // The screen moved on (signed out or locked) while asking: nothing left to report.
        if (this.writeReq !== w) return;
        if (err.status === 400) {
          await this.refuseWrite(err, w);
          return;
        }
      } else if (await this.writeRouteFailed(err)) {
        return;
      }
      this.showWrite({ open: true, notice: { kind: 'error', code: 'server' } });
      return;
    }
    if (code === 'conflict') this.showWrite({ notice: { kind: 'error', code: 'write_conflict' } });
    else if (code === 'rekey_required') this.showWrite({ notice: { kind: 'error', code: 'rekey_required' } });
    else if (code === 'value_too_large' || code === 'quota_exceeded' || code === 'network' || code === 'server') this.showWrite({ open: true, notice: { kind: 'error', code } });
    else await this.refuseWrite(err, w);
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
