/**
 * Write-only item operations. `set` seals a new value under the current vault
 * key, signs the record with the device key and sends it with its name tag;
 * `delete` writes a signed tombstone. Both are compare-and-swap on the head the
 * dashboard verified, so a concurrent edit becomes a server-side conflict
 * branch instead of a lost update.
 *
 * Metadata follows the AgentKit CLI mapping: schema `agentkit.secret/v1`,
 * `created_ms` on create, `rotated_ms` when the value changes, the profile and
 * every other carried key kept byte for byte, `value_encoding` dropped because
 * the dashboard writes text. The previous value is compared and dropped inside
 * this function; it is never returned or kept.
 */
import {
  authorizeRecordWrite,
  carryForwardMeta,
  cjsonBytes,
  isAkvError,
  MAX_PLAINTEXT_BYTES,
  nameIndexKey,
  nameTag,
  randomId,
  sealItem,
  signRecordAsync,
  type DeviceSigner,
  type ItemPayload,
  type JsonObject,
  type SignedRecord,
} from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import { isVaultApiError, type AkvClient } from './akv-client.js';
import { validItemName, validItemValue } from './item-names.js';
import { ITEM_META_SCHEMA, openHead, type VaultSnapshot } from './vault-sync.js';

export interface WriteResult {
  itemId: string;
  revision: number;
}

function writableKey(snapshot: VaultSnapshot): Uint8Array {
  if (snapshot.state.rekey_required) throw new AppError('rekey_required');
  const self = snapshot.self;
  if (self.kind !== 'human' || (self.role !== 'owner' && self.role !== 'editor')) throw new AppError('device_mismatch');
  const vk = snapshot.vaultKeys.get(snapshot.state.key_epoch);
  if (!vk) throw new AppError('item_unreadable');
  return vk;
}

/** The meta for a set over `prev` (null on create). */
export function nextMeta(prev: ItemPayload | null, valueChanged: boolean, nowMs: number): JsonObject {
  const meta: JsonObject = prev ? carryForwardMeta(prev.meta) : {};
  delete meta['value_encoding'];
  meta['schema'] = ITEM_META_SCHEMA;
  if (!prev || typeof meta['created_ms'] !== 'number') meta['created_ms'] = nowMs;
  if (prev && valueChanged) meta['rotated_ms'] = nowMs;
  if (prev && prev.meta['profile'] !== undefined) meta['profile'] = prev.meta['profile'];
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

async function sendRecord(client: AkvClient, snapshot: VaultSnapshot, record: SignedRecord, nameTagValue: string | null): Promise<WriteResult> {
  try {
    authorizeRecordWrite(snapshot.state, record);
  } catch (err) {
    if (isAkvError(err) && err.code === 'rekey_required') throw new AppError('rekey_required');
    throw new AppError('device_mismatch');
  }
  const body = nameTagValue === null ? { record } : { record, name_tag: { key_epoch: record.key_epoch, tag: nameTagValue } };
  let res: unknown;
  try {
    res = await client.put(`/v1/vaults/${encodeURIComponent(snapshot.vaultId)}/items/${encodeURIComponent(record.item_id)}`, body);
  } catch (err) {
    mapWriteError(err);
  }
  const revision = (res as Record<string, unknown> | null)?.['revision'];
  if (typeof revision !== 'number' || revision !== record.base_revision + 1) throw new AppError('server');
  return { itemId: record.item_id, revision };
}

/** Live items with exactly this name. */
function itemsNamed(snapshot: VaultSnapshot, name: string): string[] {
  return snapshot.items.filter((i) => i.name === name).map((i) => i.itemId);
}

/**
 * Set `name` to `value`: a new item, or a new revision of the one live item
 * with that name. Two live items sharing a name are refused (`duplicate_name`).
 */
export async function setItem(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; name: string; value: string; nowMs?: number }): Promise<WriteResult> {
  const { snapshot } = args;
  if (!validItemName(args.name)) throw new AppError('invalid_name');
  if (!validItemValue(args.value)) throw new AppError('value_too_large');
  const vk = writableKey(snapshot);
  const nowMs = args.nowMs ?? Date.now();
  const matches = itemsNamed(snapshot, args.name);
  if (matches.length > 1) throw new AppError('duplicate_name');
  const itemId = matches[0] ?? randomId();
  let base = 0;
  let meta: JsonObject;
  let sensitivity: ItemPayload['sensitivity'] = 'normal';
  if (matches[0]) {
    const prev = openHead(snapshot, itemId);
    base = snapshot.itemStates.get(itemId)!.revision;
    meta = nextMeta(prev, prev.value !== args.value, nowMs);
    sensitivity = prev.sensitivity;
  } else {
    meta = nextMeta(null, true, nowMs);
  }
  const payload: ItemPayload = { name: args.name, value: args.value, meta, sensitivity };
  if (cjsonBytes(payload as unknown as JsonObject).length > MAX_PLAINTEXT_BYTES) throw new AppError('value_too_large');
  const ctx = { vault_id: snapshot.vaultId, item_id: itemId, base_revision: base, key_epoch: snapshot.state.key_epoch, author: snapshot.self.device_id, tombstone: false };
  const env = sealItem({ ...ctx, vk, payload });
  const record = await signRecordAsync({ ...ctx, ts: nowMs, resolves: [], env }, args.signer);
  const tag = nameTag(nameIndexKey(vk, snapshot.vaultId, snapshot.state.key_epoch), args.name);
  return sendRecord(args.client, snapshot, record, tag);
}

/** Delete a live item with a signed tombstone at its verified head. */
export async function deleteItem(args: { client: AkvClient; snapshot: VaultSnapshot; signer: DeviceSigner; itemId: string; nowMs?: number }): Promise<WriteResult> {
  const { snapshot } = args;
  const vk = writableKey(snapshot);
  const state = snapshot.itemStates.get(args.itemId);
  if (!state || state.revision === 0 || state.tombstone || !snapshot.items.some((i) => i.itemId === args.itemId)) throw new AppError('not_found');
  const nowMs = args.nowMs ?? Date.now();
  const ctx = { vault_id: snapshot.vaultId, item_id: args.itemId, base_revision: state.revision, key_epoch: snapshot.state.key_epoch, author: snapshot.self.device_id, tombstone: true };
  const env = sealItem({ ...ctx, vk, payload: { deleted: true } });
  const record = await signRecordAsync({ ...ctx, ts: nowMs, resolves: [], env }, args.signer);
  return sendRecord(args.client, snapshot, record, null);
}

/**
 * Exact-name search through the server's blind index (spec §3.7): the tag of
 * `name` under each epoch key this device holds (newest first, at most the
 * lookup bound), mapped back to verified items. The server learns only tags.
 */
export async function lookupByName(args: { client: AkvClient; snapshot: VaultSnapshot; name: string; maxPairs?: number }): Promise<string[]> {
  const { snapshot } = args;
  if (!validItemName(args.name)) throw new AppError('invalid_name');
  const epochs = [...snapshot.vaultKeys.keys()].sort((a, b) => b - a).slice(0, args.maxPairs ?? 8);
  if (epochs.length === 0) return [];
  const q = new URLSearchParams();
  for (const e of epochs) {
    q.append('tag', nameTag(nameIndexKey(snapshot.vaultKeys.get(e)!, snapshot.vaultId, e), args.name));
    q.append('key_epoch', String(e));
  }
  const res = (await args.client.get(`/v1/vaults/${encodeURIComponent(snapshot.vaultId)}/lookup?${q.toString()}`)) as Record<string, unknown> | null;
  const hits = res?.['hits'];
  if (!Array.isArray(hits)) throw new AppError('server');
  const verified = new Map(snapshot.items.map((i) => [i.itemId, i]));
  const out: string[] = [];
  for (const hit of hits as unknown[]) {
    const id = (hit as Record<string, unknown> | null)?.['item_id'];
    const item = typeof id === 'string' ? verified.get(id) : undefined;
    // A hit counts only when the verified head carries that exact name.
    if (item && item.name === args.name && !out.includes(item.itemId)) out.push(item.itemId);
  }
  return out;
}
