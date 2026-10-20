/**
 * Pull, verify and index the vault, all in memory. A session's first pull replays
 * from the start: the membership chain from the offer's trust anchor, the offer
 * checkpoint (signature, membership head, state digest at its log position),
 * this device's `device_add` with the SAS digest, the wraps delivered to it and
 * every later rekey's wraps against their signed digests, then the whole change
 * log against the removal fences and the heads this device kept. Later pulls in
 * the same session continue from the snapshot's own cursor and fetch only the new
 * log entries; they fall back to the full replay whenever that cannot be proved
 * equivalent (a rekey, a removal fence below the cursor, any verification failure).
 *
 * The index is a metadata projection: each live head is decrypted, its `value`
 * is dropped on the spot, and only name, metadata and the provenance-checked
 * profile are kept. Values never reach the UI, storage or the console.
 */
import {
  applyRecord,
  checkProfileProvenance,
  cjson,
  computeStateDigest,
  isAkvError,
  membershipEventHash,
  openItem,
  parseMembershipEvent,
  sasDigest,
  unwrapFromDeviceAsync,
  validateProfile,
  verifyChangeLog,
  verifyCheckpoint,
  verifyDeviceWraps,
  verifyMembershipChain,
  verifyRekeyWraps,
  type DeviceKx,
  type DeviceRecord,
  type ItemPayload,
  type ItemState,
  type JsonObject,
  type MembershipEvent,
  type MembershipState,
  type Profile,
  type ProfileKey,
  type ProfileOrigin,
  type Sensitivity,
  type SignedRecord,
  type TombstonePayload,
} from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { Enrollment, StoredDevice, WitnessedState } from '../keys/device-store.js';
import { deviceIdOf } from '../keys/webcrypto-device-keys.js';
import type { AkvClient } from './akv-client.js';
import { deviceRecordOf, sasInputOf } from './enroll.js';
import { validItemName, validMetaText } from './item-names.js';

export const ITEM_META_SCHEMA = 'agentkit.secret/v1';
const MEMBERSHIP_PAGE = 1000;
const CHANGES_PAGE = 500;
/** Upper bound on pages per pull, so a misbehaving server cannot keep the tab busy forever. */
const MAX_PAGES = 2000;

export interface ProfileFieldView {
  key: ProfileKey;
  value: string | string[];
  origin: ProfileOrigin;
}

/** What the dashboard knows about one live item. There is deliberately no value field. */
export interface ItemView {
  itemId: string;
  name: string;
  revision: number;
  keyEpoch: number;
  sensitivity: Sensitivity;
  author: string;
  ts: number;
  createdMs: number | null;
  rotatedMs: number | null;
  creator: string | null;
  rotateTtlDays: number | null;
  profile: ProfileFieldView[];
  openConflicts: number;
}

export interface VaultSnapshot {
  vaultId: string;
  self: DeviceRecord;
  state: MembershipState;
  /** Vault keys by epoch, in memory only. */
  vaultKeys: Map<number, Uint8Array>;
  itemStates: Map<string, ItemState>;
  heads: Map<string, SignedRecord>;
  items: ItemView[];
  /** Live items this device cannot open (an epoch it never held, or a bad ciphertext). */
  unreadable: number;
  /** Live items the dashboard does not list (policy items, other schemas, invalid names). */
  hidden: number;
  witnessed: WitnessedState;
  /** Replay state a later pull continues from. In memory only, like the rest of the snapshot. */
  replay: ReplayBase;
}

/** What a replay leaves behind: enough to verify and apply only the entries after `head`. */
export interface ReplayBase {
  head: { log_seq: number; log_head: string };
  /** Membership the log was verified against; its removals' signed heads are the kept heads. */
  state: MembershipState;
  profiles: Map<string, Map<number, ProfileAt>>;
}

/** An incremental pull cannot be proved equivalent to a full replay; the caller replays in full. */
export class FullPullNeeded extends Error {
  constructor() {
    super('full pull needed');
    this.name = 'FullPullNeeded';
  }
}

/** Map a protocol failure to the dashboard's codes (rollback is reported on its own). */
function verificationError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  if (isAkvError(err) && err.code === 'rollback') return new AppError('rollback');
  return new AppError('vault_verification_failed');
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new AppError('server');
  return value as Record<string, unknown>;
}

async function fetchMembership(client: AkvClient, vaultId: string): Promise<unknown[]> {
  const events: unknown[] = [];
  for (let page = 0; page < MAX_PAGES; page++) {
    const body = asRecord(await client.get(`/v1/vaults/${encodeURIComponent(vaultId)}/membership?from=${events.length}&limit=${MEMBERSHIP_PAGE}`));
    const batch = body['events'];
    if (!Array.isArray(batch)) throw new AppError('server');
    events.push(...(batch as unknown[]));
    if (body['has_more'] !== true) return events;
    if (batch.length === 0) throw new AppError('server');
  }
  throw new AppError('server');
}

interface ChangeEntry {
  log_seq: unknown;
  conflict_id: unknown;
  record: unknown;
}

interface ChangeFeed {
  entries: ChangeEntry[];
  /** The server's claimed tip from the last page. Never trusted: a mismatch only forces a full replay. */
  head: { log_seq: number; log_head: string } | null;
}

async function fetchChanges(client: AkvClient, vaultId: string, from = 0): Promise<ChangeFeed> {
  const entries: ChangeEntry[] = [];
  let cursor = from;
  for (let page = 0; page < MAX_PAGES; page++) {
    const body = asRecord(await client.get(`/v1/vaults/${encodeURIComponent(vaultId)}/changes?cursor=${cursor}&limit=${CHANGES_PAGE}`));
    const batch = body['changes'];
    if (!Array.isArray(batch)) throw new AppError('server');
    for (const raw of batch as unknown[]) {
      const c = asRecord(raw);
      entries.push({ log_seq: c['log_seq'], conflict_id: c['conflict_id'] ?? null, record: c['record'] });
    }
    if (body['has_more'] !== true) {
      const h = body['head'];
      const claimed = typeof h === 'object' && h !== null ? (h as Record<string, unknown>) : null;
      const head = claimed && typeof claimed['log_seq'] === 'number' && typeof claimed['log_head'] === 'string' ? { log_seq: claimed['log_seq'], log_head: claimed['log_head'] } : null;
      return { entries, head };
    }
    const next = body['next_cursor'];
    if (typeof next !== 'number' || !Number.isSafeInteger(next) || next <= cursor) throw new AppError('server');
    cursor = next;
  }
  throw new AppError('server');
}

async function fetchWraps(client: AkvClient, vaultId: string, seq: number): Promise<unknown[]> {
  const body = asRecord(await client.get(`/v1/vaults/${encodeURIComponent(vaultId)}/wraps?membership_seq=${seq}`));
  if (body['membership_seq'] !== seq || !Array.isArray(body['wraps'])) throw new AppError('server');
  return body['wraps'] as unknown[];
}

/**
 * Verify the chain for this enrollment. Returns the state and the parsed events.
 * Cross-vault and cross-account inputs fail here: the trust anchor and vault ID
 * come from the offer this device accepted, and its own record must be a
 * current device of its own account.
 */
export function verifyEnrollmentChain(events: readonly unknown[], device: StoredDevice, enrollment: Enrollment): { state: MembershipState; parsed: MembershipEvent[]; addSeq: number } {
  const cp = enrollment.offerCheckpoint;
  if (cp.vault_id !== enrollment.vaultId) throw new AppError('vault_verification_failed');
  let state: MembershipState;
  let parsed: MembershipEvent[];
  try {
    state = verifyMembershipChain(events, { trustedAnchor: enrollment.trustAnchor, vaultId: enrollment.vaultId, witnessedCheckpoint: cp });
    parsed = events.map((e) => parseMembershipEvent(e));
    const w = enrollment.witnessed;
    if (w) {
      if (w.membership_seq > state.seq || membershipEventHash(parsed[w.membership_seq]!) !== w.membership_head) throw new AppError('rollback');
      if (state.key_epoch < w.key_epoch) throw new AppError('rollback');
    }
    // The offer checkpoint is signed by a device current at its own position.
    verifyCheckpoint(cp, verifyMembershipChain(events.slice(0, cp.membership_seq + 1), { trustedAnchor: enrollment.trustAnchor, vaultId: enrollment.vaultId }));
  } catch (err) {
    throw verificationError(err);
  }

  const selfId = deviceIdOf(device.keys);
  const expected = deviceRecordOf(device.account, device.keys);
  const digest = sasDigest(sasInputOf(device, { vault_id: enrollment.vaultId, initiator: enrollment.initiator, nonce_i: enrollment.nonceI, nonce_j: device.nonceJ }));
  // The device_add that answers this offer: after the offer checkpoint, by the
  // offer's initiator, for exactly this device record, carrying the SAS digest.
  const add = parsed.find(
    (e) =>
      e.type === 'device_add' &&
      e.seq > cp.membership_seq &&
      e.author === enrollment.initiator &&
      e.body['sas'] === digest &&
      cjson(e.body['device'] ?? null) === cjson(expected),
  );
  const current = state.devices.find((d) => d.device_id === selfId);
  if (!add) {
    if (parsed.some((e) => e.type === 'device_add' && (e.body['device'] as JsonObject | undefined)?.['device_id'] === selfId)) throw new AppError('enroll_sas_mismatch');
    throw new AppError('enroll_not_approved');
  }
  if (!current) throw new AppError('device_removed');
  if (current.account !== device.account || current.sign_pub !== expected.sign_pub || current.kx_pub !== expected.kx_pub || current.kind !== 'human') {
    throw new AppError('vault_verification_failed');
  }
  if (!state.members.some((m) => m.account === device.account)) throw new AppError('device_removed');
  return { state, parsed, addSeq: add.seq };
}

/** Unwrap every vault key this device holds: its device_add set and each later rekey set. */
async function loadVaultKeys(client: AkvClient, vaultId: string, selfId: string, parsed: MembershipEvent[], addSeq: number, kx: DeviceKx): Promise<Map<number, Uint8Array>> {
  const keys = new Map<number, Uint8Array>();
  const unwrapOwn = async (wraps: { rcpt: string; key_epoch: number }[], raw: readonly unknown[]) => {
    for (let i = 0; i < wraps.length; i++) {
      if (wraps[i]!.rcpt !== selfId) continue;
      keys.set(wraps[i]!.key_epoch, await unwrapFromDeviceAsync({ wrap: raw[i], vaultId, deviceId: selfId, kx }));
    }
  };
  try {
    const addRaw = await fetchWraps(client, vaultId, addSeq);
    const addWraps = verifyDeviceWraps(parsed[addSeq], addRaw);
    await unwrapOwn(addWraps, addWraps);
    for (const event of parsed) {
      if (event.seq <= addSeq || event.type !== 'rekey') continue;
      const raw = await fetchWraps(client, vaultId, event.seq);
      const wraps = verifyRekeyWraps(event, raw);
      if (!wraps.some((w) => w.rcpt === selfId)) throw new AppError('device_removed');
      await unwrapOwn(wraps, wraps);
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (isAkvError(err)) throw verificationError(err);
    throw err;
  }
  return keys;
}

function metaInt(meta: JsonObject, key: string, min: number): number | null {
  const v = meta[key];
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= min ? v : null;
}

/** Project a decrypted payload to what the dashboard shows. `value` is never read. */
export function projectItem(
  payload: ItemPayload,
  record: SignedRecord,
  profile: { profile: Profile; origins: Partial<Record<ProfileKey, ProfileOrigin>> },
  openConflicts: number,
): ItemView | null {
  const meta = payload.meta;
  if (meta['kind'] !== undefined || meta['schema'] !== ITEM_META_SCHEMA || !validItemName(payload.name)) return null;
  const creator = typeof meta['creator'] === 'string' && meta['creator'] !== '' && validMetaText(meta['creator']) ? meta['creator'] : null;
  return {
    itemId: record.item_id,
    name: payload.name,
    revision: record.base_revision + 1,
    keyEpoch: record.key_epoch,
    sensitivity: payload.sensitivity,
    author: record.author,
    ts: record.ts,
    createdMs: metaInt(meta, 'created_ms', 1),
    rotatedMs: metaInt(meta, 'rotated_ms', 1),
    creator,
    rotateTtlDays: metaInt(meta, 'rotate_ttl_days', 1),
    profile: (Object.keys(profile.profile) as ProfileKey[]).sort().map((key) => ({ key, value: profile.profile[key]!.value, origin: profile.origins[key] ?? 'sync' })),
    openConflicts,
  };
}

function openRecord(record: SignedRecord, vk: Uint8Array | undefined): ItemPayload | TombstonePayload | null {
  if (!vk) return null;
  try {
    return openItem({
      vk, env: record.env, vault_id: record.vault_id, item_id: record.item_id, base_revision: record.base_revision,
      key_epoch: record.key_epoch, author: record.author, tombstone: record.tombstone,
    });
  } catch {
    return null;
  }
}

/** Open the live head of an item for a write. The caller drops `value` as soon as it compared it. */
export function openHead(snapshot: VaultSnapshot, itemId: string): ItemPayload {
  const record = snapshot.heads.get(itemId);
  const state = snapshot.itemStates.get(itemId);
  if (!record || !state || state.tombstone || state.revision === 0) throw new AppError('not_found');
  const payload = openRecord(record, snapshot.vaultKeys.get(record.key_epoch));
  if (!payload || 'deleted' in payload) throw new AppError('item_unreadable');
  return payload;
}

export interface ProfileAt {
  profile: Profile;
  origins: Partial<Record<ProfileKey, ProfileOrigin>>;
}

/**
 * Replay the verified log into item states; check the offer checkpoint's state
 * digest on the way. With `prior`, `entries` continue from `prior.head`: the kept
 * heads are the witnessed position and every removal fence the prior pull had
 * already verified; a removal it had not seen, fenced below the cursor, is
 * {@link FullPullNeeded}, because records past that fence need re-checking.
 */
export function replayLog(
  entries: readonly ChangeEntry[],
  state: MembershipState,
  enrollment: Enrollment,
  vaultKeys: Map<number, Uint8Array>,
  selfId: string,
  prior?: Pick<VaultSnapshot, 'itemStates' | 'heads'> & { replay: ReplayBase },
): Pick<VaultSnapshot, 'itemStates' | 'heads' | 'items' | 'unreadable' | 'hidden' | 'replay'> & { logHead: { log_seq: number; log_head: string } } {
  const kept = new Map<number, string>();
  if (prior) {
    // Records the cursor already passed were checked against the removals known then. A removal
    // this pull learned about, fenced below the cursor, changes what those records may be: replay in full.
    const removalKey = (r: MembershipState['removals'][number]) => `${r.sign_pub}:${r.removed_seq}`;
    const known = new Set(prior.replay.state.removals.map(removalKey));
    for (const r of prior.replay.state.removals) if (r.log_fence > 0) kept.set(r.log_fence, r.log_head);
    for (const r of state.removals) if (!known.has(removalKey(r)) && r.log_fence < prior.replay.head.log_seq) throw new FullPullNeeded();
  }
  if (enrollment.witnessed && enrollment.witnessed.log_seq > 0) kept.set(enrollment.witnessed.log_seq, enrollment.witnessed.log_head);
  let verified;
  try {
    verified = verifyChangeLog(entries, state, { complete: true, keptHeads: kept, ...(prior ? { from: prior.replay.head } : {}) });
  } catch (err) {
    throw verificationError(err);
  }
  const cp = enrollment.offerCheckpoint;
  if (verified.head.log_seq < cp.log_seq) throw new AppError('rollback');

  const itemStates = new Map<string, ItemState>(prior?.itemStates);
  const heads = new Map<string, SignedRecord>(prior?.heads);
  const profiles = new Map<string, Map<number, ProfileAt>>(prior?.replay.profiles);
  const ownedProfiles = new Set<string>();
  const digestAt = (n: number) => {
    // A continuation starts past the offer checkpoint, which the first pull already checked.
    if (!prior && n === cp.log_seq && computeStateDigest(itemStates.values()) !== cp.state_digest) throw new AppError('rollback');
  };
  digestAt(0);
  verified.records.forEach((record, i) => {
    const entry = entries[i]!;
    const conflictId = entry.conflict_id === null ? undefined : (entry.conflict_id as string);
    let applied;
    try {
      applied = applyRecord(itemStates.get(record.item_id), record, conflictId === undefined ? {} : { conflictId });
    } catch {
      throw new AppError('vault_verification_failed');
    }
    // The server's label for the entry must be what the replay derives.
    if ((conflictId === undefined) !== (applied.outcome.status === 'applied')) throw new AppError('vault_verification_failed');
    itemStates.set(record.item_id, applied.state);
    if (applied.outcome.status === 'applied') {
      heads.set(record.item_id, record);
      // Copy on first write so a failed pull leaves the prior snapshot's profiles untouched.
      if (!ownedProfiles.has(record.item_id)) {
        profiles.set(record.item_id, new Map(profiles.get(record.item_id)));
        ownedProfiles.add(record.item_id);
      }
      const byRevision = profiles.get(record.item_id)!;
      const revision = applied.outcome.revision;
      if (record.tombstone) {
        byRevision.set(revision, { profile: {}, origins: {} });
      } else {
        const payload = openRecord(record, vaultKeys.get(record.key_epoch));
        if (payload && !('deleted' in payload)) {
          const prev = record.base_revision === 0 ? null : (byRevision.get(record.base_revision) ?? null);
          let next: unknown = payload.meta['profile'] ?? {};
          try {
            validateProfile(next);
          } catch {
            next = {};
          }
          const checked = checkProfileProvenance(prev?.profile ?? (record.base_revision === 0 ? {} : null), next, record, { selfDeviceId: selfId, prevOrigins: prev?.origins ?? null });
          byRevision.set(revision, { profile: checked.profile, origins: checked.origins });
        }
      }
    }
    digestAt(prior ? prior.replay.head.log_seq + i + 1 : i + 1);
  });

  const items: ItemView[] = [];
  let unreadable = 0;
  let hidden = 0;
  for (const [itemId, itemState] of itemStates) {
    if (itemState.revision === 0 || itemState.tombstone) continue;
    const record = heads.get(itemId)!;
    const payload = openRecord(record, vaultKeys.get(record.key_epoch));
    if (!payload || 'deleted' in payload) {
      unreadable++;
      continue;
    }
    const profile = profiles.get(itemId)?.get(itemState.revision) ?? { profile: {}, origins: {} };
    const view = projectItem(payload, record, profile, itemState.conflicts.length);
    if (view) items.push(view);
    else hidden++;
  }
  items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.itemId < b.itemId ? -1 : 1));
  return { itemStates, heads, items, unreadable, hidden, logHead: verified.head, replay: { head: verified.head, state, profiles } };
}

export interface PullResult {
  snapshot: VaultSnapshot;
  enrollment: Enrollment;
}

/**
 * Pull and verify everything for an enrolled (or awaiting approval) device. With
 * `prior`, the snapshot this session already verified, only the log entries after
 * it are fetched; anything that cannot be proved equivalent, or any verification
 * failure on that path, repeats as the full replay, whose verdict is final.
 */
export async function pullVault(client: AkvClient, device: StoredDevice, kx: DeviceKx, prior?: VaultSnapshot | null): Promise<PullResult> {
  const enrollment = device.enrollment;
  if (!enrollment) throw new AppError('enroll_not_approved');
  const events = await fetchMembership(client, enrollment.vaultId);
  const { state, parsed, addSeq } = verifyEnrollmentChain(events, device, enrollment);
  const selfId = deviceIdOf(device.keys);
  // A kept position below the cursor is not re-checked by a continuation, so replay in full.
  const w = enrollment.witnessed;
  const base = prior && prior.vaultId === enrollment.vaultId && (!w || w.log_seq >= prior.replay.head.log_seq) ? prior : null;
  if (base) {
    try {
      const vaultKeys = state.key_epoch === base.state.key_epoch ? base.vaultKeys : await loadVaultKeys(client, enrollment.vaultId, selfId, parsed, addSeq, kx);
      const feed = await fetchChanges(client, enrollment.vaultId, base.replay.head.log_seq);
      const replay = replayLog(feed.entries, state, enrollment, vaultKeys, selfId, base);
      // Nothing new proves nothing about a server whose log shrank or diverged below the cursor: its tip must be ours.
      if (!feed.head || feed.head.log_seq !== replay.logHead.log_seq || feed.head.log_head !== replay.logHead.log_head) throw new FullPullNeeded();
      return finishPull(enrollment, state, selfId, vaultKeys, replay);
    } catch (err) {
      if (!(err instanceof FullPullNeeded) && !(err instanceof AppError && (err.code === 'vault_verification_failed' || err.code === 'rollback'))) throw err;
    }
  }
  const vaultKeys = await loadVaultKeys(client, enrollment.vaultId, selfId, parsed, addSeq, kx);
  const { entries } = await fetchChanges(client, enrollment.vaultId);
  return finishPull(enrollment, state, selfId, vaultKeys, replayLog(entries, state, enrollment, vaultKeys, selfId));
}

function finishPull(enrollment: Enrollment, state: MembershipState, selfId: string, vaultKeys: Map<number, Uint8Array>, replay: ReturnType<typeof replayLog>): PullResult {
  const witnessed: WitnessedState = {
    membership_seq: state.seq,
    membership_head: state.head,
    log_seq: replay.logHead.log_seq,
    log_head: replay.logHead.log_head,
    key_epoch: state.key_epoch,
  };
  const self = state.devices.find((d) => d.device_id === selfId)!;
  return {
    snapshot: {
      vaultId: enrollment.vaultId, self, state, vaultKeys,
      itemStates: replay.itemStates, heads: replay.heads, items: replay.items, unreadable: replay.unreadable, hidden: replay.hidden, witnessed, replay: replay.replay,
    },
    enrollment: { ...enrollment, confirmed: true, witnessed },
  };
}
