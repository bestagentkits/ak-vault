/**
 * Restore an old revision, or settle open conflict branches, as a new signed
 * record. Both are compare-and-swap writes at the head the dashboard verified,
 * under the current key epoch, through the same authorization as `set`: a
 * removed device, an old epoch, a pending rekey or a viewer role refuses here
 * before anything is sent, and a concurrent write turns into a server-side
 * conflict branch rather than being overwritten.
 *
 * The old value is opened inside these functions, re-sealed and dropped. It is
 * never returned, rendered or stored, so the dashboard keeps its no-reveal rule.
 * Nothing rewrites a stored log position, and a deleted item is never revived.
 */
import {
  cjsonBytes,
  MAX_PLAINTEXT_BYTES,
  MAX_RESOLVES,
  nameIndexKey,
  nameTag,
  sealItem,
  signRecordAsync,
  type DeviceSigner,
  type ItemPayload,
  type JsonObject,
} from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { AkvClient } from './akv-client.js';
import type { HistoryEntry, ItemHistory } from './item-history.js';
import { openHead, openRecord, type VaultSnapshot } from './vault-sync.js';
import { nextMeta, sendRecord, writableKey, type WriteResult } from './write-ops.js';

/** Where the value of a settle comes from. */
export type SettleChoice = { source: 'current' } | { source: 'branch'; conflictId: string };

interface Context {
  client: AkvClient;
  snapshot: VaultSnapshot;
  signer: DeviceSigner;
  history: ItemHistory;
  nowMs?: number;
}

/** The payload of a live entry, opened only to be re-sealed by the caller. */
function openLive(snapshot: VaultSnapshot, entry: HistoryEntry): ItemPayload {
  const payload = openRecord(entry.record, snapshot.vaultKeys.get(entry.keyEpoch));
  if (!payload || 'deleted' in payload) throw new AppError('restore_unavailable');
  return payload;
}

/** Write `value` as the next revision of the item, optionally resolving branches. */
async function writeNext(ctx: Context, source: ItemPayload, valueChanged: boolean, resolves: string[]): Promise<WriteResult> {
  const value = source.value;
  const { snapshot, history } = ctx;
  const vk = writableKey(snapshot);
  const state = snapshot.itemStates.get(history.itemId);
  if (!state || state.revision === 0 || state.tombstone) throw new AppError('not_found');
  const head = openHead(snapshot, history.itemId);
  const nowMs = ctx.nowMs ?? Date.now();
  const sensitivity: ItemPayload['sensitivity'] = head.sensitivity === 'high' || source.sensitivity === 'high' ? 'high' : 'normal';
  const meta = nextMeta(head, valueChanged, nowMs) as JsonObject;
  // The value is copied from `source`, so its encoding marker travels with it (a base64 binary stays base64).
  if (source.meta['value_encoding'] !== undefined) meta['value_encoding'] = source.meta['value_encoding'];
  const payload: ItemPayload = { name: head.name, value, meta, sensitivity };
  if (cjsonBytes(payload as unknown as JsonObject).length > MAX_PLAINTEXT_BYTES) throw new AppError('value_too_large');
  const base = {
    vault_id: snapshot.vaultId, item_id: history.itemId, base_revision: state.revision, key_epoch: snapshot.state.key_epoch,
    author: snapshot.self.device_id, tombstone: false,
  };
  const env = sealItem({ ...base, vk, payload });
  const record = await signRecordAsync({ ...base, ts: nowMs, resolves, env }, ctx.signer);
  const tag = nameTag(nameIndexKey(vk, snapshot.vaultId, snapshot.state.key_epoch), head.name);
  return sendRecord(ctx.client, snapshot, record, tag);
}

function liveHistory(ctx: Context): void {
  // A history older than the verified list is never acted on: refresh and look again.
  if (ctx.history.stale) throw new AppError('conflict');
  const state = ctx.snapshot.itemStates.get(ctx.history.itemId);
  if (!state || state.revision === 0 || state.tombstone || ctx.history.deleted) throw new AppError('not_found');
}

/**
 * Write the value of a verified earlier revision as a new revision on top of
 * the verified head. Open conflict branches are left as they are.
 */
export async function restoreRevision(ctx: Context & { logSeq: number }): Promise<WriteResult> {
  liveHistory(ctx);
  const entry = ctx.history.entries.find((e) => e.logSeq === ctx.logSeq && e.kind === 'applied');
  if (!entry) throw new AppError('not_found');
  if (entry.restoreBlock !== null) throw new AppError('restore_unavailable');
  const old = openLive(ctx.snapshot, entry);
  const head = openHead(ctx.snapshot, ctx.history.itemId);
  if (old.value === head.value) throw new AppError('restore_unchanged');
  return writeNext(ctx, old, true, []);
}

/**
 * Settle every open conflict branch with one new revision whose value is the
 * current head's or one branch's. The listed branches stop being open; their
 * records stay in the log.
 */
export async function settleConflicts(ctx: Context & { choice: SettleChoice }): Promise<WriteResult> {
  liveHistory(ctx);
  const open = ctx.history.entries.filter((e) => e.kind === 'conflict' && e.conflictOpen);
  const resolves = ctx.history.openConflictIds;
  if (resolves.length === 0) throw new AppError('nothing_to_resolve');
  // One record lists at most MAX_RESOLVES branches; never settle part of them silently.
  if (resolves.length > MAX_RESOLVES) throw new AppError('restore_unavailable');
  const head = openHead(ctx.snapshot, ctx.history.itemId);
  if (ctx.choice.source === 'current') return writeNext(ctx, head, false, resolves);
  const chosenId = ctx.choice.conflictId;
  const branch = open.find((e) => e.conflictId === chosenId);
  if (!branch || branch.tombstone || branch.readability !== 'readable' || !resolves.includes(chosenId)) throw new AppError('restore_unavailable');
  const payload = openLive(ctx.snapshot, branch);
  return writeNext(ctx, payload, payload.value !== head.value, resolves);
}
