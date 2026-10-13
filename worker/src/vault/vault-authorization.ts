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
 */
import { parseMembershipEvent, type DeviceRecord, type JsonObject, type MembershipState } from '@ak-vault/protocol';
import type { Scope } from '../auth/jwt-verify.js';
import { ApiError } from '../http/errors.js';
import { MembershipStore } from './membership-store.js';
import { parseBodyObject, requireKeys } from './request-body.js';
import { enforceRole, memberDevice, requireScope, verifyRequestProof, type RoleRule } from './request-guard.js';
import type { VaultOp, VaultRequest } from './vault-request.js';

const READ: readonly Scope[] = ['vault:read'];
const WRITE: readonly Scope[] = ['vault:write'];
const EITHER: readonly Scope[] = ['vault:read', 'vault:write'];

/**
 * Scope and role per op. Checkpoints and audit appends are witness/log operations,
 * not vault data writes, so read-only devices (readers, machines) may post them
 * with either scope.
 */
const POLICY: Record<Exclude<VaultOp, 'genesis' | 'membership.post'>, { scope: readonly Scope[]; role: RoleRule }> = {
  'membership.get': { scope: READ, role: 'any_device' },
  'wraps.get': { scope: READ, role: 'any_device' },
  'wraps.post': { scope: WRITE, role: 'human_owner' },
  'item.get': { scope: READ, role: 'any_device' },
  'item.put': { scope: WRITE, role: 'writer' },
  'changes.get': { scope: READ, role: 'any_device' },
  'checkpoints.get': { scope: READ, role: 'any_device' },
  'checkpoints.post': { scope: EITHER, role: 'any_device' },
  'audit.get': { scope: READ, role: 'any_device' },
  'audit.post': { scope: EITHER, role: 'any_device' },
  'recovery.get': { scope: READ, role: 'human_owner' },
  'recovery.put': { scope: WRITE, role: 'human_owner' },
};

export interface Authorized {
  /** Current state, or for genesis the state the genesis event creates. */
  state: MembershipState;
  device: DeviceRecord;
  /** Parsed body for mutations. */
  body: JsonObject | null;
  /** Verified next membership state (recovery enrollment only; computed during auth). */
  next?: MembershipState;
}

function authorizeGenesis(req: VaultRequest, sql: SqlStorage): Authorized {
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
  requireKeys(body, ['event'], ['wraps']);
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
  // Recovery enrollment: only a recovery-signed device_add that adds the caller itself.
  const event = parseMembershipEvent(body['event']);
  if (event.type !== 'device_add' || event.author !== state.recovery_author) throw new ApiError('forbidden');
  const next = store.verifyAppend(body['event']);
  const device = next.devices.find((d) => d.device_id === req.claims.did);
  if (!device || device.account !== req.claims.sub) throw new ApiError('forbidden');
  verifyRequestProof(sql, req, device.sign_pub);
  requireScope(req.claims.scope, WRITE);
  return { state, device, body, next };
}

export function authorize(req: VaultRequest, sql: SqlStorage, store: MembershipStore): Authorized {
  if (req.op === 'genesis') return authorizeGenesis(req, sql);
  if (req.op === 'membership.post') return authorizeMembershipPost(req, sql, store);
  const state = store.requireState();
  const device = memberDevice(state, req.claims.sub, req.claims.did);
  verifyRequestProof(sql, req, device.sign_pub);
  const policy = POLICY[req.op];
  requireScope(req.claims.scope, policy.scope);
  enforceRole(device, policy.role);
  const mutating = req.op.endsWith('.post') || req.op.endsWith('.put');
  return { state, device, body: mutating ? parseBodyObject(req.body) : null };
}
