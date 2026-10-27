/**
 * Write-only item operations. `set` seals a new value under the current vault
 * key, signs the record with the device key and sends it with its name tag;
 * `delete` writes a signed tombstone. Both are compare-and-swap on the head the
 * dashboard verified, so a concurrent edit becomes a server-side conflict
 * branch instead of a lost update.
 *
 * A set that completes a human write request (`write-request.ts`) is the same
 * record, sent with `?write_request=<id>` and checked against the request's
 * operation first: `create` needs no live item of that name, `replace` exactly one.
 *
 * Metadata follows the AgentKit CLI mapping: schema `agentkit.secret/v1`,
 * `created_ms` on create, `rotated_ms` when the value changes, the verified profile (the
 * fields the provenance check kept) and every other carried key kept byte for byte, `value_encoding` dropped because
 * the dashboard writes text. The previous value is compared and dropped inside
 * this function; it is never returned or kept.
 */
import {
  authorizeRecordWrite,
  carryForwardMeta,
  cjsonBytes,
  isAkvError,
  MAX_RESOLVES,
  MAX_PLAINTEXT_BYTES,
  nameIndexKey,
  nameTag,
  randomId,
  recordDigest,
  sealItem,
  signRecordAsync,
  validateProfile,
  type DeviceSigner,
  type ItemPayload,
  type JsonObject,
  type Profile,
  type Sensitivity,
  type SignedRecord,
  type WriteIntentOperation,
} from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import { isVaultApiError, type AkvClient } from './akv-client.js';
import { validItemName, validItemValue } from './item-names.js';
import { valueBlocked } from './history.js';
import { isMs, ROTATE_TTL_META_KEY, ROTATION_META_KEY, MAX_ROTATE_TTL_DAYS, parseRotationWorkflow, workflowToMeta, type RotationWorkflow } from './rotation.js';
import { ITEM_META_SCHEMA, openHead, openRecord, type VaultSnapshot } from './vault-sync.js';

export interface WriteResult {
  itemId: string;
  revision: number;
  /** The Worker's opaque receipt when the write completed a write request. */
  receipt?: string;
}

/** The write request a set completes. */
export interface RequestedWrite {
  requestId: string;
  operation: WriteIntentOperation;
  /** Requested sensitivity; the write never lowers the head's. */
  sensitivity: Sensitivity | null;
}

const RECEIPT = /^[A-Za-z0-9_-]{22}$/;

function writableKey(snapshot: VaultSnapshot): Uint8Array {
  if (snapshot.state.rekey_required) throw new AppError('rekey_required');
  const self = snapshot.self;
  if (self.kind !== 'human' || (self.role !== 'owner' && self.role !== 'editor')) throw new AppError('device_mismatch');
  const vk = snapshot.vaultKeys.get(snapshot.state.key_epoch);
  if (!vk) throw new AppError('item_unreadable');
  return vk;
}

/** The profile a write over `itemId`'s head may carry: the fields this device's provenance check kept, byte for byte, or none when the base was not verified. */
function verifiedProfile(snapshot: VaultSnapshot, itemId: string): Profile | null {
  return snapshot.profiles.get(itemId) ?? null;
}

/**
 * The meta for a set over `prev` (null on create). `verified` is the head's
 * profile as this device checked it (spec §5.1); the raw `prev.meta.profile` is
 * never carried, since it can hold fields the check already dropped.
 */
export function nextMeta(prev: ItemPayload | null, valueChanged: boolean, nowMs: number, verified: Profile | null): JsonObject {
  const meta: JsonObject = prev ? carryForwardMeta(prev.meta) : {};
  delete meta['value_encoding'];
  meta['schema'] = ITEM_META_SCHEMA;
  if (!prev || typeof meta['created_ms'] !== 'number') meta['created_ms'] = nowMs;
  if (prev && valueChanged) meta['rotated_ms'] = nowMs;
  if (prev && verified && Object.keys(verified).length > 0) meta['profile'] = validateProfile(verified) as unknown as JsonObject;
  return meta;
}

/** The meta for a value taken from `source`: a base64 value (a binary secret the CLI wrote) stays marked as such; any other encoding is refused. */
function metaForValueFrom(prev: ItemPayload, source: ItemPayload, valueChanged: boolean, nowMs: number, verified: Profile | null): JsonObject {
  const enc = source.meta['value_encoding'];
  if (enc !== undefined && enc !== 'base64') throw new AppError('history_unavailable');
  const meta = nextMeta(prev, valueChanged, nowMs, verified);
  if (enc === 'base64') meta['value_encoding'] = 'base64';
  return meta;
}

function mapWriteError(err: unknown): never {
  if (isVaultApiError(err)) {
    if (err.code === 'conflict' || err.code === 'tombstoned') throw new AppError('conflict');
    if (err.code === 'rekey_required') throw new AppError('rekey_required');
    if (err.code === 'quota_exceeded') throw new AppError('quota_exceeded');
  }
  throw err;
}

async function sendRecord(client: AkvClient, snapshot: VaultSnapshot, record: SignedRecord, nameTagValue: string | null, requestId: string | null = null): Promise<WriteResult> {
  try {
    authorizeRecordWrite(snapshot.state, record);
  } catch (err) {
    if (isAkvError(err) && err.code === 'rekey_required') throw new AppError('rekey_required');
    throw new AppError('device_mismatch');
  }
  const body = nameTagValue === null ? { record } : { record, name_tag: { key_epoch: record.key_epoch, tag: nameTagValue } };
  const query = requestId === null ? '' : `?write_request=${encodeURIComponent(requestId)}`;
  let res: unknown;
  try {
    res = await client.put(`/v1/vaults/${encodeURIComponent(snapshot.vaultId)}/items/${encodeURIComponent(record.item_id)}${query}`, body);
  } catch (err) {
    mapWriteError(err);
  }
  const revision = (res as Record<string, unknown> | null)?.['revision'];
  if (typeof revision !== 'number' || revision !== record.base_revision + 1) throw new AppError('server');
  if (requestId === null) return { itemId: record.item_id, revision };
  const done = (res as Record<string, unknown>)['write_request'] as Record<string, unknown> | undefined;
  const receipt = done?.['receipt'];
  if (done?.['state'] !== 'completed' || typeof receipt !== 'string' || !RECEIPT.test(receipt)) throw new AppError('server');
  return { itemId: record.item_id, revision, receipt };
}

/** Live items with exactly this name. */
function itemsNamed(snapshot: VaultSnapshot, name: string): string[] {
  return snapshot.items.filter((i) => i.name === name).map((i) => i.itemId);
}

/**
 * The item a write request targets in the verified snapshot: null for a
 * `create` (any live item with the name is `already_exists`), the single live
 * item for a `replace` (none, or more than one, is `not_found`). Resolution uses
 * the device's synced state, never a lookup.
 */
export function requestTarget(snapshot: VaultSnapshot, name: string, operation: WriteIntentOperation): string | null {
  if (!validItemName(name)) throw new AppError('invalid_name');
  const matches = itemsNamed(snapshot, name);
  if (operation === 'create') {
    if (matches.length > 0) throw new AppError('already_exists');
    return null;
  }
  if (matches.length !== 1) throw new AppError('not_found');
  return matches[0]!;
}

/**
 * Set `name` to `value`: a new item, or a new revision of the one live item
 * with that name. Two live items sharing a name are refused (`duplicate_name`).
 * With `request`, the set completes that write request (see `requestTarget`).
 */
export async function setItem(args: {
  client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; name: string; value: string; nowMs?: number; request?: RequestedWrite;
}): Promise<WriteResult> {
  const { snapshot, request } = args;
  if (!validItemName(args.name)) throw new AppError('invalid_name');
  if (!validItemValue(args.value)) throw new AppError('value_too_large');
  const vk = writableKey(snapshot);
  const nowMs = args.nowMs ?? Date.now();
  let existing: string | null;
  if (request) {
    existing = requestTarget(snapshot, args.name, request.operation);
  } else {
    const matches = itemsNamed(snapshot, args.name);
    if (matches.length > 1) throw new AppError('duplicate_name');
    existing = matches[0] ?? null;
  }
  const itemId = existing ?? randomId();
  let base = 0;
  let meta: JsonObject;
  let sensitivity: ItemPayload['sensitivity'] = 'normal';
  if (existing) {
    const prev = openHead(snapshot, itemId);
    base = snapshot.itemStates.get(itemId)!.revision;
    meta = nextMeta(prev, prev.value !== args.value, nowMs, verifiedProfile(snapshot, itemId));
    sensitivity = prev.sensitivity;
  } else {
    meta = nextMeta(null, true, nowMs, null);
  }
  // A requested sensitivity only ever raises the head's.
  if (request?.sensitivity === 'high') sensitivity = 'high';
  const payload: ItemPayload = { name: args.name, value: args.value, meta, sensitivity };
  return writeRevision({ ...args, itemId, base, vk, payload, resolves: [], nowMs, requestId: request?.requestId ?? null });
}

/** Seal `payload` under the current key epoch, sign it at `base` and send it as one compare-and-swap write. */
async function writeRevision(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; base: number; vk: Uint8Array; payload: ItemPayload; resolves: string[]; nowMs: number; requestId?: string | null }): Promise<WriteResult> {
  const { snapshot, payload } = args;
  if (cjsonBytes(payload as unknown as JsonObject).length > MAX_PLAINTEXT_BYTES) throw new AppError('value_too_large');
  const ctx = { vault_id: snapshot.vaultId, item_id: args.itemId, base_revision: args.base, key_epoch: snapshot.state.key_epoch, author: snapshot.self.device_id, tombstone: false };
  const env = sealItem({ ...ctx, vk: args.vk, payload });
  const record = await signRecordAsync({ ...ctx, ts: args.nowMs, resolves: args.resolves, env }, args.signer);
  const tag = nameTag(nameIndexKey(args.vk, snapshot.vaultId, snapshot.state.key_epoch), payload.name);
  return sendRecord(args.client, snapshot, record, tag, args.requestId ?? null);
}

/** A live, listed item's verified state, or `not_found`. */
function liveState(snapshot: VaultSnapshot, itemId: string) {
  const state = snapshot.itemStates.get(itemId);
  if (!state || state.revision === 0 || state.tombstone || !snapshot.items.some((i) => i.itemId === itemId)) throw new AppError('not_found');
  return state;
}

/**
 * Restore the value of a verified earlier revision as a NEW revision of a live
 * item: sealed under the current key epoch, signed by this device and sent
 * compare-and-swap at the head the dashboard verified. The log position of the
 * old revision is never rewritten, a tombstone is never revived, and a
 * concurrent write turns this one into a preserved conflict branch. Only the
 * value comes from the old revision; the name, sensitivity, profile and other
 * metadata stay the current head's. The old value is opened and sealed again
 * inside this function and is never returned or shown.
 */
export async function restoreRevision(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; logSeq: number; nowMs?: number }): Promise<WriteResult> {
  const { snapshot } = args;
  const vk = writableKey(snapshot);
  const state = liveState(snapshot, args.itemId);
  const target = snapshot.log.get(args.itemId)?.find((e) => e.logSeq === args.logSeq && e.conflictId === null);
  if (!target || target.record.tombstone || recordDigest(target.record) === state.head) throw new AppError('history_unavailable');
  if (valueBlocked(target.record, target.logSeq, snapshot.log.get(args.itemId) ?? [], snapshot.state) !== null) throw new AppError('history_unavailable');
  const old = openRecord(target.record, snapshot.vaultKeys.get(target.record.key_epoch));
  if (!old || 'deleted' in old) throw new AppError('history_unavailable');
  const prev = openHead(snapshot, args.itemId);
  if (old.value === prev.value) throw new AppError('restore_current');
  const nowMs = args.nowMs ?? Date.now();
  const payload: ItemPayload = { name: prev.name, value: old.value, meta: metaForValueFrom(prev, old, true, nowMs, verifiedProfile(snapshot, args.itemId)), sensitivity: prev.sensitivity };
  return writeRevision({ ...args, base: state.revision, vk, payload, resolves: [], nowMs });
}

/**
 * Resolve every open conflict branch of a live item with one new revision at
 * the verified head, listing their IDs in `resolves` (the protocol's explicit
 * resolution). `adopt` null keeps the current value; an ID adopts that open,
 * readable, non-tombstone branch's value. The branches stay in the signed log.
 */
export async function resolveConflicts(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; adopt: string | null; nowMs?: number }): Promise<WriteResult> {
  const { snapshot } = args;
  const vk = writableKey(snapshot);
  const state = liveState(snapshot, args.itemId);
  const open = state.conflicts;
  if (open.length === 0 || open.length > MAX_RESOLVES) throw new AppError('history_unavailable');
  // A deletion or an unreadable branch is never dismissed from here, whichever value is kept.
  for (const c of open) {
    const p = c.record.tombstone ? null : openRecord(c.record, snapshot.vaultKeys.get(c.record.key_epoch));
    if (!p || 'deleted' in p) throw new AppError('history_unavailable');
  }
  const prev = openHead(snapshot, args.itemId);
  let value = prev.value;
  let source = prev;
  if (args.adopt !== null) {
    const branch = open.find((c) => c.conflict_id === args.adopt);
    if (!branch) throw new AppError('history_unavailable');
    const logged = snapshot.log.get(args.itemId)?.find((e) => e.conflictId === branch.conflict_id);
    if (!logged || valueBlocked(branch.record, logged.logSeq, snapshot.log.get(args.itemId) ?? [], snapshot.state) !== null) throw new AppError('history_unavailable');
    const payload = openRecord(branch.record, snapshot.vaultKeys.get(branch.record.key_epoch));
    if (!payload || 'deleted' in payload) throw new AppError('history_unavailable');
    value = payload.value;
    source = payload;
  }
  const nowMs = args.nowMs ?? Date.now();
  const next: ItemPayload = { name: prev.name, value, meta: source === prev ? nextMeta(prev, false, nowMs, verifiedProfile(snapshot, args.itemId)) : metaForValueFrom(prev, source, value !== prev.value, nowMs, verifiedProfile(snapshot, args.itemId)), sensitivity: prev.sensitivity };
  return writeRevision({ ...args, base: state.revision, vk, payload: next, resolves: open.map((c) => c.conflict_id), nowMs });
}

/** The rotation fields a metadata-only revision may change. `undefined` leaves a field as it is; `null` clears it. */
export interface RotationPatch {
  rotateTtlDays?: number | null;
  rotation?: RotationWorkflow | null;
  /** Confirm the old provider credential is revoked (needs a vault value written after the workflow started). */
  confirmRevoked?: boolean;
}

/**
 * Write a new revision of a live item that keeps its value and changes only
 * rotation metadata: the interval and the workflow. Compare-and-swap on the
 * verified head like every write. The value is re-sealed in this function and
 * never returned.
 */
export async function updateRotation(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; patch: RotationPatch; nowMs?: number }): Promise<WriteResult> {
  const { snapshot, patch } = args;
  const vk = writableKey(snapshot);
  const item = snapshot.items.find((i) => i.itemId === args.itemId);
  const state = snapshot.itemStates.get(args.itemId);
  if (!item || !state || state.revision === 0 || state.tombstone) throw new AppError('not_found');
  const nowMs = args.nowMs ?? Date.now();
  const prev = openHead(snapshot, args.itemId);
  const meta = nextMeta(prev, false, nowMs, verifiedProfile(snapshot, args.itemId));
  if (patch.rotateTtlDays !== undefined) {
    const ttl = patch.rotateTtlDays;
    if (ttl === null) delete meta[ROTATE_TTL_META_KEY];
    else if (Number.isSafeInteger(ttl) && ttl >= 1 && ttl <= MAX_ROTATE_TTL_DAYS) meta[ROTATE_TTL_META_KEY] = ttl;
    else throw new AppError('invalid_rotation');
  }
  let workflow = patch.rotation === undefined ? parseRotationWorkflow(prev.meta) : patch.rotation;
  if (patch.confirmRevoked) {
    const rotatedRaw = prev.meta['rotated_ms'];
    const rotatedMs = isMs(rotatedRaw) ? rotatedRaw : null;
    if (!workflow || workflow.state !== 'active' || rotatedMs === null || rotatedMs < workflow.startedMs) throw new AppError('rotation_not_ready');
    // Never earlier than the value write: another device's clock may run ahead of this one.
    workflow = { ...workflow, revokedMs: Math.max(nowMs, rotatedMs) };
  }
  if (workflow === null) delete meta[ROTATION_META_KEY];
  else meta[ROTATION_META_KEY] = workflowToMeta(workflow);
  const payload: ItemPayload = { name: prev.name, value: prev.value, meta, sensitivity: prev.sensitivity };
  if (cjsonBytes(payload as unknown as JsonObject).length > MAX_PLAINTEXT_BYTES) throw new AppError('value_too_large');
  const ctx = { vault_id: snapshot.vaultId, item_id: args.itemId, base_revision: state.revision, key_epoch: snapshot.state.key_epoch, author: snapshot.self.device_id, tombstone: false };
  const env = sealItem({ ...ctx, vk, payload });
  const record = await signRecordAsync({ ...ctx, ts: nowMs, resolves: [], env }, args.signer);
  return sendRecord(args.client, snapshot, record, nameTag(nameIndexKey(vk, snapshot.vaultId, snapshot.state.key_epoch), prev.name));
}

/**
 * Replace the value of one live item (a provider credential rotation). Refuses
 * a value equal to the current one: re-writing the old secret protects nothing
 * and must not read as a rotation. Writing a new value clears a recorded
 * revocation, since that confirmed the previous credential.
 */
export async function rotateValue(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; value: string; nowMs?: number }): Promise<WriteResult> {
  const { snapshot } = args;
  if (args.value === '' || !validItemValue(args.value)) throw new AppError('value_too_large');
  const vk = writableKey(snapshot);
  const state = snapshot.itemStates.get(args.itemId);
  if (!state || state.revision === 0 || state.tombstone || !snapshot.items.some((i) => i.itemId === args.itemId)) throw new AppError('not_found');
  const prev = openHead(snapshot, args.itemId);
  if (prev.value === args.value) throw new AppError('rotation_value_unchanged');
  const nowMs = args.nowMs ?? Date.now();
  const meta = nextMeta(prev, true, nowMs, verifiedProfile(snapshot, args.itemId));
  const workflow = parseRotationWorkflow(prev.meta);
  if (workflow) meta[ROTATION_META_KEY] = workflowToMeta({ ...workflow, revokedMs: null });
  const payload: ItemPayload = { name: prev.name, value: args.value, meta, sensitivity: prev.sensitivity };
  if (cjsonBytes(payload as unknown as JsonObject).length > MAX_PLAINTEXT_BYTES) throw new AppError('value_too_large');
  const ctx = { vault_id: snapshot.vaultId, item_id: args.itemId, base_revision: state.revision, key_epoch: snapshot.state.key_epoch, author: snapshot.self.device_id, tombstone: false };
  const env = sealItem({ ...ctx, vk, payload });
  const record = await signRecordAsync({ ...ctx, ts: nowMs, resolves: [], env }, args.signer);
  return sendRecord(args.client, snapshot, record, nameTag(nameIndexKey(vk, snapshot.vaultId, snapshot.state.key_epoch), prev.name));
}

/** Delete a live item with a signed tombstone at its verified head. */
export async function deleteItem(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; nowMs?: number }): Promise<WriteResult> {
  const { snapshot } = args;
  const vk = writableKey(snapshot);
  const state = liveState(snapshot, args.itemId);
  const nowMs = args.nowMs ?? Date.now();
  const ctx = { vault_id: snapshot.vaultId, item_id: args.itemId, base_revision: state.revision, key_epoch: snapshot.state.key_epoch, author: snapshot.self.device_id, tombstone: true };
  const env = sealItem({ ...ctx, vk, payload: { deleted: true } });
  const record = await signRecordAsync({ ...ctx, ts: nowMs, resolves: [], env }, args.signer);
  return sendRecord(args.client, snapshot, record, null);
}

/**
 * Exact-name search over the verified snapshot. Every name this device can read
 * is already in memory, so the search stays local: the server's blind-index
 * lookup would only tell it which item was looked for, and when.
 */
export function findByName(snapshot: VaultSnapshot, name: string): string[] {
  if (!validItemName(name)) throw new AppError('invalid_name');
  return itemsNamed(snapshot, name);
}
