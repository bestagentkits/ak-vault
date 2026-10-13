/** Handlers for genesis, membership append/read and wrap upload/read. */
import { parseMembershipEvent, verifyRekeyWraps, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import type { MembershipStore } from './membership-store.js';
import { queryInt, requireArray, requireKeys } from './request-body.js';
import { listWraps, storeWraps, validateWraps } from './wrap-store.js';
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

/** `PUT /v1/vaults/:vid` with `{event: genesis, wraps?: [...]}` (already verified by the guard). */
export function handleGenesis(sql: SqlStorage, store: MembershipStore, body: JsonObject, genesis: MembershipState): ApiResult {
  if (store.state() !== null) throw new ApiError('conflict', { message: 'vault already exists' });
  const wraps = body['wraps'] === undefined ? [] : validateWraps(genesis, body['wraps'], { keyEpoch: 1 });
  store.persist(parseMembershipEvent(body['event']), genesis);
  storeWraps(sql, wraps, genesis.seq);
  return okResult({ membership: membershipSummary(genesis), wraps_stored: wraps.length }, 201);
}

/**
 * `POST /membership` with `{event, wraps?}`. `next` is the verified chain state
 * including `event`. A rekey must carry the complete new-epoch wrap set whose
 * digest equals the event's `wraps_digest`, so the epoch change and its wraps
 * land atomically.
 */
export function handleMembershipPost(sql: SqlStorage, store: MembershipStore, body: JsonObject, next: MembershipState): ApiResult {
  requireKeys(body, ['event'], ['wraps']);
  const event = parseMembershipEvent(body['event']);
  let wraps;
  if (event.type === 'rekey') {
    wraps = verifyRekeyWraps(event, requireArray(body['wraps'] ?? null, LIMITS.wraps_per_request), { state: next });
  } else {
    wraps = body['wraps'] === undefined ? [] : validateWraps(next, body['wraps']);
  }
  store.persist(event, next);
  storeWraps(sql, wraps, next.seq);
  return okResult({ membership: membershipSummary(next), wraps_stored: wraps.length }, 201);
}

/** `GET /membership?from=&limit=`: signed events for client-side replay plus the derived summary. */
export function handleMembershipGet(store: MembershipStore, req: VaultRequest): ApiResult {
  const state = store.requireState();
  const from = queryInt(req.query, 'from', 0);
  const limit = queryInt(req.query, 'limit', LIMITS.membership_page_max, LIMITS.membership_page_max);
  const events = store.page(from, Math.max(1, limit));
  return okResult({ events, has_more: from + events.length <= state.seq, membership: membershipSummary(state) });
}

/** `POST /wraps` with `{wraps: [...]}`: owner devices upload wraps for current member devices. */
export function handleWrapsPost(sql: SqlStorage, state: MembershipState, body: JsonObject): ApiResult {
  requireKeys(body, ['wraps']);
  const wraps = validateWraps(state, body['wraps']);
  if (wraps.length === 0) throw new ApiError('bad_request');
  return okResult({ wraps_stored: storeWraps(sql, wraps, state.seq) });
}

/** `GET /wraps?key_epoch=&rcpt=`. */
export function handleWrapsGet(sql: SqlStorage, state: MembershipState, req: VaultRequest): ApiResult {
  const filter: { keyEpoch?: number; rcpt?: string } = {};
  if (req.query['key_epoch'] !== undefined) filter.keyEpoch = queryInt(req.query, 'key_epoch', 0);
  if (req.query['rcpt'] !== undefined) filter.rcpt = req.query['rcpt'];
  return okResult({ wraps: listWraps(sql, state, filter), key_epoch: state.key_epoch });
}

export { membershipSummary };
