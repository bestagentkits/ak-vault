/** Handlers for genesis, membership append/read and wrap-set reads. */
import { parseMembershipEvent, verifyDeviceWraps, verifyRekeyWraps, type JsonObject, type MembershipEvent, type MembershipState, type X25519Wrap } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { currentLogSeq } from './changes-feed.js';
import type { MembershipStore } from './membership-store.js';
import { storeRecoveryBundle } from './recovery-store.js';
import { queryInt, requireArray, requireKeys } from './request-body.js';
import { listWraps, storeWrapSet, wrapSet } from './wrap-store.js';
import type { VaultRequest } from './vault-request.js';

function membershipSummary(state: MembershipState) {
  return {
    seq: state.seq,
    head: state.head,
    key_epoch: state.key_epoch,
    rekey_required: state.rekey_required,
    needs_rotate: state.needs_rotate,
  };
}

/**
 * The wrap set an event must carry. Device-adding events (genesis, device_add,
 * member_add) and rekeys MUST carry the set their signed `wraps_digest` commits
 * to; every other event carries none.
 */
function verifyEventWraps(event: MembershipEvent, raw: unknown, next: MembershipState): X25519Wrap[] {
  switch (event.type) {
    case 'rekey':
      return verifyRekeyWraps(event, requireArray(raw ?? null, LIMITS.wraps_per_request), { state: next });
    case 'genesis':
    case 'device_add':
    case 'member_add':
      return verifyDeviceWraps(event, requireArray(raw ?? null, LIMITS.wraps_per_request));
    default:
      if (raw !== undefined) throw new ApiError('bad_request', { message: 'this event type carries no wraps' });
      return [];
  }
}

/**
 * A removal's signed `log_fence` must be the change-log head at the moment the
 * removal lands: then every record the removed device got accepted is at or below
 * the fence, and nothing it writes later can be. A stale fence is `conflict` (pull
 * the change log and re-sign); a fence ahead of the log is `bad_request`.
 */
function checkLogFence(sql: SqlStorage, event: MembershipEvent): void {
  if (event.type !== 'device_remove' && event.type !== 'member_remove') return;
  const fence = event.body['log_fence'] as number; // integer >= 0, checked by chain verification
  const head = currentLogSeq(sql);
  if (fence > head) throw new ApiError('bad_request', { message: 'log_fence is ahead of the change log' });
  if (fence < head) throw new ApiError('conflict', { message: 'log_fence is behind the change log head' });
}

/** `PUT /v1/vaults/:vid` with `{event: genesis, wraps: [...]}` (already verified by the guard). */
export function handleGenesis(sql: SqlStorage, store: MembershipStore, body: JsonObject, genesis: MembershipState): ApiResult {
  if (store.state() !== null) throw new ApiError('conflict', { message: 'vault already exists' });
  const event = parseMembershipEvent(body['event']);
  const wraps = verifyEventWraps(event, body['wraps'], genesis);
  store.persist(event, genesis);
  storeWrapSet(sql, genesis.seq, wraps);
  return okResult({ membership: membershipSummary(genesis), wraps_stored: wraps.length }, 201);
}

/**
 * `POST /membership` with `{event, wraps?, bundle?}`. `next` is the verified chain
 * state including `event`. The event, its wrap set (checked against the signed
 * digest) and, for `recovery_rotate`, the resealed recovery bundle land in one
 * transaction, so the chain never trusts a recovery key the stored bundle lacks.
 */
export function handleMembershipPost(sql: SqlStorage, store: MembershipStore, vaultId: string, body: JsonObject, next: MembershipState): ApiResult {
  requireKeys(body, ['event'], ['wraps', 'bundle']);
  const event = parseMembershipEvent(body['event']);
  const rotating = event.type === 'recovery_rotate';
  if (rotating !== (body['bundle'] !== undefined)) throw new ApiError('bad_request', { message: 'recovery_rotate, and only it, carries the resealed bundle' });
  const wraps = verifyEventWraps(event, body['wraps'], next);
  checkLogFence(sql, event);
  store.persist(event, next);
  storeWrapSet(sql, next.seq, wraps);
  const bundleSeq = rotating ? storeRecoveryBundle(sql, vaultId, body['bundle']) : null;
  return okResult({ membership: membershipSummary(next), wraps_stored: wraps.length, ...(bundleSeq !== null ? { bundle_seq: bundleSeq } : {}) }, 201);
}

/** `GET /membership?from=&limit=`: signed events for client-side replay plus the derived summary. */
export function handleMembershipGet(store: MembershipStore, req: VaultRequest): ApiResult {
  const state = store.requireState();
  const from = queryInt(req.query, 'from', 0);
  const limit = queryInt(req.query, 'limit', LIMITS.membership_page_max, LIMITS.membership_page_max);
  const events = store.page(from, Math.max(1, limit));
  return okResult({ events, has_more: from + events.length <= state.seq, membership: membershipSummary(state) });
}

/**
 * `GET /wraps?membership_seq=n`: the complete signed set of event n as uploaded
 * (404 when that event carries none). Otherwise `GET /wraps?key_epoch=&rcpt=`:
 * wraps of current devices, each with the `membership_seq` of its set.
 */
export function handleWrapsGet(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  if (req.query['membership_seq'] !== undefined) {
    if (req.query['key_epoch'] !== undefined || req.query['rcpt'] !== undefined) throw new ApiError('bad_request');
    const seq = queryInt(req.query, 'membership_seq', 0);
    const wraps = seq <= state.seq ? wrapSet(sql, seq) : null;
    if (!wraps) throw new ApiError('not_found');
    return okResult({ membership_seq: seq, wraps });
  }
  const filter: { keyEpoch?: number; rcpt?: string } = {};
  if (req.query['key_epoch'] !== undefined) filter.keyEpoch = queryInt(req.query, 'key_epoch', 0);
  if (req.query['rcpt'] !== undefined) filter.rcpt = req.query['rcpt'];
  return okResult({ wraps: listWraps(sql, state, filter), key_epoch: state.key_epoch });
}

export { membershipSummary };
