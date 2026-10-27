/**
 * Resolve who is calling and whether the op is allowed, before any vault data is
 * touched. Normal ops: the token `did` must be a current device of the token
 * `sub`, the proof must verify against that device key, and scope and role must
 * allow the op. Two body-dependent cases:
 *  - genesis: no state exists yet, so the genesis event is verified alone and the
 *    caller must be its author device and owner account;
 *  - recovery enrollment: a fresh device posts a `device_add` for itself signed by
 *    the owner recovery key (spec §3.5). The event is chain-verified first, then
 *    the proof is checked against the key the owner-signed event adds.
 * One header-dependent case:
 *  - recovery identity: a fresh device (not current, never removed) of the owner
 *    account may `GET /recovery` to obtain the bundle that holds
 *    `recovery_sign_sk`, and `GET /membership` to verify the chain it must append
 *    to (spec §3.5, §9.4); nothing else. It presents its `sign_pub` in
 *    `AKV-Device-Key`; the token `did` must equal `kid(sign_pub)` and the proof
 *    must verify against that key. Only an `email_otp` session may take this path
 *    and recovery enrollment; `api_key_device` and `machine` sessions are refused
 *    (spec §9.4), so a leaked API key alone cannot collect bundles. Exposure: any
 *    holder of an owner-account token plus a key it generates can fetch the
 *    bundle and attempt offline guessing of the bundle password, and can read
 *    membership metadata (accounts, roles, device public keys).
 * Recovery operations by members (`GET`/`PUT /recovery` and `recovery_rotate`)
 * also require an `email_otp` session, whatever the device's role (spec §9.4): a
 * long-lived API key or machine credential may never read, replace or rotate the
 * recovery material, even on an owner-role device. It may only store the first
 * bundle of a vault that has none (the genesis seal).
 */
import { b64decodeLength, deviceIdFromSignPub, parseMembershipEvent, type DeviceRecord, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import type { Scope } from '../auth/jwt-verify.js';
import { ApiError } from '../http/errors.js';
import { MembershipStore } from './membership-store.js';
import { hasIdempotentResult } from './idempotency.js';
import { hasRecoveryBundle } from './recovery-store.js';
import { parseBodyObject, requireKeys } from './request-body.js';
import { enforceRole, memberDevice, requireScope, verifyRequestProof, type RoleRule } from './request-guard.js';
import { isMutation, type VaultOp, type VaultRequest } from './vault-request.js';

const READ: readonly Scope[] = ['vault:read'];
const WRITE: readonly Scope[] = ['vault:write'];

/**
 * Scope and role per op. Spec §9.4: `reader` members and `machine` devices are
 * read-only, so checkpoint and audit appends need `vault:write` and a writer;
 * read-only devices still read both streams.
 */
const POLICY: Record<Exclude<VaultOp, 'genesis' | 'membership.post'>, { scope: readonly Scope[]; role: RoleRule }> = {
  'membership.get': { scope: READ, role: 'any_device' },
  'wraps.get': { scope: READ, role: 'any_device' },
  'item.get': { scope: READ, role: 'any_device' },
  'item.put': { scope: WRITE, role: 'writer' },
  'changes.get': { scope: READ, role: 'any_device' },
  'checkpoints.get': { scope: READ, role: 'any_device' },
  'checkpoints.post': { scope: WRITE, role: 'writer' },
  'audit.get': { scope: READ, role: 'any_device' },
  'audit.post': { scope: WRITE, role: 'writer' },
  'recovery.get': { scope: READ, role: 'human_owner' },
  'recovery.put': { scope: WRITE, role: 'human_owner' },
  // Remote access (spec §9.6).
  'lookup.get': { scope: READ, role: 'any_device' },
  'sealkey.get': { scope: READ, role: 'any_device' },
  'sealkey.put': { scope: WRITE, role: 'human_owner' },
  'sealed.get': { scope: READ, role: 'writer' },
  'sealed.ack': { scope: WRITE, role: 'writer' },
  'writereq.get': { scope: READ, role: 'writer' },
  'writereq.close': { scope: WRITE, role: 'writer' },
};

/**
 * Ops a `browser` (dashboard) session may never call, whatever its device's role
 * (spec §9 item 1, ADR 0002 D1). The recovery-identity reads are refused to every
 * non-`email_otp` session by `requireHumanSession`; the relay refuses `browser`
 * at its upgrade.
 */
const BROWSER_REFUSED: ReadonlySet<VaultOp> = new Set<VaultOp>(['genesis', 'membership.post', 'recovery.get', 'recovery.put', 'sealkey.put', 'sealed.get', 'sealed.ack']);

/** Ops only a `browser` (dashboard) session may call: the person's side of a human write request (spec §3.10). */
const BROWSER_ONLY: ReadonlySet<VaultOp> = new Set<VaultOp>(['writereq.get', 'writereq.close']);

function refuseBrowserSession(req: VaultRequest): void {
  if (req.claims.kind === 'browser' && BROWSER_REFUSED.has(req.op)) throw new ApiError('forbidden');
  if (req.claims.kind !== 'browser' && BROWSER_ONLY.has(req.op)) throw new ApiError('forbidden');
}

/**
 * Fail closed: outside membership only an `email_otp` session is admitted (spec
 * §9.4). A token without `session_kind` was verified as `email_otp`.
 */
function requireHumanSession(req: VaultRequest): void {
  if (req.claims.kind !== 'email_otp') throw new ApiError('forbidden');
}

export interface Authorized {
  /** Current state, or for genesis the state the genesis event creates. */
  state: MembershipState;
  /** The calling current device; null for a recovery fetch by a not-yet-enrolled device. */
  device: DeviceRecord | null;
  /** Parsed body for mutations. */
  body: JsonObject | null;
  /** Verified next membership state (recovery enrollment only; computed during auth). */
  next?: MembershipState;
}

/**
 * Genesis checks that need no vault storage: event, author/owner binding, scope and
 * proof signature (its `jti` is not burned). Run before a new vault's schema is
 * created so a rejected genesis leaves no storage behind.
 */
export function preflightGenesis(req: VaultRequest): void {
  authorizeGenesis(req, null);
}

function authorizeGenesis(req: VaultRequest, sql: SqlStorage | null): Authorized {
  refuseBrowserSession(req);
  const body = parseBodyObject(req.body);
  requireKeys(body, ['event'], ['wraps']);
  const state = MembershipStore.verifyGenesis(body['event'], req.vaultId);
  const author = parseMembershipEvent(body['event']).author;
  if (author !== req.claims.did || state.owner_account !== req.claims.sub) throw new ApiError('forbidden');
  const device = state.devices.find((d) => d.device_id === author)!;
  verifyRequestProof(sql, req, device.sign_pub);
  requireScope(req.claims.scope, WRITE);
  return { state, device, body };
}

function authorizeMembershipPost(req: VaultRequest, sql: SqlStorage, store: MembershipStore): Authorized {
  const state = store.requireState();
  const body = parseBodyObject(req.body);
  requireKeys(body, ['event'], ['wraps', 'bundle']);
  const known = state.devices.find((d) => d.device_id === req.claims.did);
  if (known) {
    const device = memberDevice(state, req.claims.sub, req.claims.did);
    verifyRequestProof(sql, req, device.sign_pub);
    requireScope(req.claims.scope, WRITE);
    enforceRole(device, 'human_owner');
    // The chain is verified in the mutation step, after the idempotency lookup, so a
    // retried append returns its stored result instead of failing as a stale seq.
    return { state, device, body };
  }
  // Recovery enrollment: only a recovery-signed device_add that adds the caller itself,
  // and only for a human email-OTP session (it needs the bundle that path refuses others).
  requireHumanSession(req);
  const event = parseMembershipEvent(body['event']);
  if (event.type !== 'device_add' || event.author !== state.recovery_author) throw new ApiError('forbidden');
  const next = store.verifyAppend(body['event']);
  const device = next.devices.find((d) => d.device_id === req.claims.did);
  if (!device || device.account !== req.claims.sub) throw new ApiError('forbidden');
  verifyRequestProof(sql, req, device.sign_pub);
  requireScope(req.claims.scope, WRITE);
  return { state, device, body, next };
}

/**
 * A recovery operation other than `PUT /recovery`: a bundle read, or a membership
 * append that rotates the recovery key. A `bundle` marks a rotation too: the
 * mutation step refuses a bundle on any other event, so counting it here only
 * fails closed earlier. A body that does not parse is not classified; it fails
 * later as before.
 */
function isRecoveryReadOrRotate(req: VaultRequest): boolean {
  if (req.op === 'recovery.get') return true;
  if (req.op !== 'membership.post') return false;
  let body: JsonObject;
  try {
    body = parseBodyObject(req.body);
  } catch {
    return false;
  }
  const event = body['event'];
  const type = typeof event === 'object' && event !== null && !Array.isArray(event) ? (event as JsonObject)['type'] : undefined;
  return type === 'recovery_rotate' || body['bundle'] !== undefined;
}

/**
 * Recovery operations need an `email_otp` session whatever the device's role,
 * member or not (spec §9.4), with one exception: the genesis seal. A non-human
 * session may `PUT /recovery` while the vault has no bundle yet, so a vault it
 * created gets its first bundle; replacing a stored bundle is refused, except an
 * exact idempotent retry of that seal, which is answered from the stored result.
 * Checked before the proof is consumed, like the recovery-identity refusal; the
 * bundle store re-checks inside the mutation's transaction.
 */
function refuseNonHumanRecovery(req: VaultRequest, sql: SqlStorage): void {
  if (req.claims.kind === 'email_otp') return;
  if (isRecoveryReadOrRotate(req)) throw new ApiError('forbidden');
  if (req.op === 'recovery.put' && hasRecoveryBundle(sql) && !hasIdempotentResult(sql, req)) throw new ApiError('forbidden');
}

/**
 * The recovery identity: `GET /recovery` or `GET /membership` (the only ops a
 * not-yet-enrolled device may call) by a fresh owner-account device that proves
 * possession of the key it presents.
 */
function authorizeRecoveryFetch(req: VaultRequest, sql: SqlStorage, state: MembershipState): Authorized {
  requireHumanSession(req);
  const did = req.claims.did;
  if (req.claims.sub !== state.owner_account || state.removed_device_ids.includes(did)) throw new ApiError('forbidden');
  let signPub: string;
  try {
    signPub = req.deviceKey ?? '';
    b64decodeLength(signPub, 32);
    if (deviceIdFromSignPub(signPub) !== did) throw new ApiError('unauthorized');
  } catch {
    throw new ApiError('unauthorized');
  }
  verifyRequestProof(sql, req, signPub);
  requireScope(req.claims.scope, READ);
  return { state, device: null, body: null };
}

export function authorize(req: VaultRequest, sql: SqlStorage, store: MembershipStore): Authorized {
  refuseBrowserSession(req);
  refuseNonHumanRecovery(req, sql);
  if (req.op === 'genesis') return authorizeGenesis(req, sql);
  if (req.op === 'membership.post') return authorizeMembershipPost(req, sql, store);
  const state = store.requireState();
  // The bundle is only ever fetched this way; a membership read takes this path only
  // when the caller presents its key, so other non-member reads stay `forbidden`.
  const recoveryIdentity = req.op === 'recovery.get' || (req.op === 'membership.get' && req.deviceKey !== null);
  if (recoveryIdentity && !state.devices.some((d) => d.device_id === req.claims.did)) return authorizeRecoveryFetch(req, sql, state);
  const device = memberDevice(state, req.claims.sub, req.claims.did);
  verifyRequestProof(sql, req, device.sign_pub);
  const policy = POLICY[req.op];
  requireScope(req.claims.scope, policy.scope);
  enforceRole(device, policy.role);
  return { state, device, body: isMutation(req.op) ? parseBodyObject(req.body) : null };
}
