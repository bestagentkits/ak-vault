/**
 * Pull, verify and index the vault, all in memory. Every session replays from
 * the start: the membership chain from the offer's trust anchor, the offer
 * checkpoint (signature, membership head, state digest at its log position),
 * this device's `device_add` with the SAS digest, the wraps delivered to it and
 * every later rekey's wraps against their signed digests, then the whole change
 * log against the removal fences and the heads this device kept.
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
import type { LoggedRecord } from './history.js';
import { validItemName, validMetaText } from './item-names.js';
import { parseRotationWorkflow, type RotationWorkflow } from './rotation.js';

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
  /** Rotation workflow an operator started (signed metadata), or null. */
  rotation: RotationWorkflow | null;
  /** Time and key epoch of the latest rekey that listed this item in `needs_rotate`; null when never listed. */
  flaggedMs: number | null;
  flaggedEpoch: number | null;
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
  /** Every verified log entry of each item (applied and preserved), in log order. Ciphertext only. */
  log: Map<string, LoggedRecord[]>;
  /** Each live item's profile at its head as this device verified it (fields the provenance check kept). A write carries this, never the raw payload. Absent when the base of the head could not be verified. */
  profiles: Map<string, Profile>;
  items: ItemView[];
  /** Live items this device cannot open (an epoch it never held, or a bad ciphertext). */
  unreadable: number;
  /** Live items the dashboard does not list (policy items, other schemas, invalid names). */
  hidden: number;
  witnessed: WitnessedState;
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

async function fetchChanges(client: AkvClient, vaultId: string): Promise<ChangeEntry[]> {
  const entries: ChangeEntry[] = [];
  let cursor = 0;
  for (let page = 0; page < MAX_PAGES; page++) {
    const body = asRecord(await client.get(`/v1/vaults/${encodeURIComponent(vaultId)}/changes?cursor=${cursor}&limit=${CHANGES_PAGE}`));
    const batch = body['changes'];
    if (!Array.isArray(batch)) throw new AppError('server');
    for (const raw of batch as unknown[]) {
      const c = asRecord(raw);
      entries.push({ log_seq: c['log_seq'], conflict_id: c['conflict_id'] ?? null, record: c['record'] });
    }
    if (body['has_more'] !== true) return entries;
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
    rotation: parseRotationWorkflow(meta),
    flaggedMs: null,
    flaggedEpoch: null,
    profile: (Object.keys(profile.profile) as ProfileKey[]).sort().map((key) => ({ key, value: profile.profile[key]!.value, origin: profile.origins[key] ?? 'sync' })),
    openConflicts,
  };
}

export function openRecord(record: SignedRecord, vk: Uint8Array | undefined): ItemPayload | TombstonePayload | null {
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

interface ProfileAt {
  profile: Profile;
  origins: Partial<Record<ProfileKey, ProfileOrigin>>;
  /** False when the device did not hold the base revision, so nothing was actually checked. */
  verified: boolean;
}

/** Replay the verified log into item states; check the offer checkpoint's state digest on the way. */
export function replayLog(
  entries: readonly ChangeEntry[],
  state: MembershipState,
  enrollment: Enrollment,
  vaultKeys: Map<number, Uint8Array>,
  selfId: string,
): Pick<VaultSnapshot, 'itemStates' | 'heads' | 'log' | 'profiles' | 'items' | 'unreadable' | 'hidden'> & { logHead: { log_seq: number; log_head: string } } {
  const kept = new Map<number, string>();
  if (enrollment.witnessed && enrollment.witnessed.log_seq > 0) kept.set(enrollment.witnessed.log_seq, enrollment.witnessed.log_head);
  let verified;
  try {
    verified = verifyChangeLog(entries, state, { complete: true, keptHeads: kept });
  } catch (err) {
    throw verificationError(err);
  }
  const cp = enrollment.offerCheckpoint;
  if (verified.head.log_seq < cp.log_seq) throw new AppError('rollback');

  const itemStates = new Map<string, ItemState>();
  const heads = new Map<string, SignedRecord>();
  const log = new Map<string, LoggedRecord[]>();
  const profiles = new Map<string, Map<number, ProfileAt>>();
  const digestAt = (n: number) => {
    if (n === cp.log_seq && computeStateDigest(itemStates.values()) !== cp.state_digest) throw new AppError('rollback');
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
    const itemLog = log.get(record.item_id) ?? [];
    itemLog.push({ logSeq: i + 1, conflictId: conflictId ?? null, record });
    log.set(record.item_id, itemLog);
    if (applied.outcome.status === 'applied') {
      heads.set(record.item_id, record);
      const byRevision = profiles.get(record.item_id) ?? new Map<number, ProfileAt>();
      profiles.set(record.item_id, byRevision);
      const revision = applied.outcome.revision;
      if (record.tombstone) {
        byRevision.set(revision, { profile: {}, origins: {}, verified: true });
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
          byRevision.set(revision, { profile: checked.profile, origins: checked.origins, verified: record.base_revision === 0 || prev !== null });
        }
      }
    }
    digestAt(i + 1);
  });

  const items: ItemView[] = [];
  const verifiedProfiles = new Map<string, Profile>();
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
    const profile = profiles.get(itemId)?.get(itemState.revision) ?? { profile: {}, origins: {}, verified: false };
    if (profile.verified) verifiedProfiles.set(itemId, profile.profile);
    const view = projectItem(payload, record, profile, itemState.conflicts.length);
    if (view) items.push(view);
    else hidden++;
  }
  items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.itemId < b.itemId ? -1 : 1));
  return { itemStates, heads, log, profiles: verifiedProfiles, items, unreadable, hidden, logHead: verified.head };
}

/** Record, per item, the latest rekey that listed it in `needs_rotate` (a removal's exposure flag). */
export function flagRotations(items: ItemView[], events: readonly MembershipEvent[]): void {
  const latest = new Map<string, { ts: number; epoch: number }>();
  for (const e of events) {
    if (e.type !== 'rekey') continue;
    const ids = e.body['needs_rotate'];
    const epoch = e.body['new_key_epoch'];
    if (!Array.isArray(ids) || typeof epoch !== 'number') continue;
    for (const id of ids) if (typeof id === 'string') latest.set(id, { ts: e.ts, epoch });
  }
  for (const item of items) {
    const flag = latest.get(item.itemId);
    if (flag) {
      item.flaggedMs = flag.ts;
      item.flaggedEpoch = flag.epoch;
    }
  }
}

export interface PullResult {
  snapshot: VaultSnapshot;
  enrollment: Enrollment;
}

/** Pull and verify everything for an enrolled (or awaiting approval) device. */
export async function pullVault(client: AkvClient, device: StoredDevice, kx: DeviceKx): Promise<PullResult> {
  const enrollment = device.enrollment;
  if (!enrollment) throw new AppError('enroll_not_approved');
  const events = await fetchMembership(client, enrollment.vaultId);
  const { state, parsed, addSeq } = verifyEnrollmentChain(events, device, enrollment);
  const selfId = deviceIdOf(device.keys);
  const vaultKeys = await loadVaultKeys(client, enrollment.vaultId, selfId, parsed, addSeq, kx);
  const entries = await fetchChanges(client, enrollment.vaultId);
  const replay = replayLog(entries, state, enrollment, vaultKeys, selfId);
  flagRotations(replay.items, parsed);
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
      itemStates: replay.itemStates, heads: replay.heads, log: replay.log, profiles: replay.profiles, items: replay.items, unreadable: replay.unreadable, hidden: replay.hidden, witnessed,
    },
    enrollment: { ...enrollment, confirmed: true, witnessed },
  };
}
