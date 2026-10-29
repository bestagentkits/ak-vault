/** Membership log types and untrusted-input parsers (spec §4). */
import type { JsonObject } from './canonical-json.js';
import { fail } from './errors.js';
import { deviceIdFromSignPub } from './signing.js';
import { asB64, asEnum, asId, asInt, asObject, asString, checkVersion, exactKeys } from './validate.js';

export const ROLES = ['owner', 'editor', 'reader'] as const;
export type Role = (typeof ROLES)[number];
export const DEVICE_KINDS = ['human', 'machine'] as const;
export type DeviceKind = (typeof DEVICE_KINDS)[number];
export const VAULT_KINDS = ['personal', 'shared', 'ci'] as const;
export type VaultKind = (typeof VAULT_KINDS)[number];
export const REMOVE_REASONS = ['lost', 'stolen', 'retired', 'compromised'] as const;
export type RemoveReason = (typeof REMOVE_REASONS)[number];
export const MEMBERSHIP_EVENT_TYPES = ['genesis', 'device_add', 'device_remove', 'member_add', 'member_remove', 'role_set', 'rekey', 'recovery_rotate'] as const;
export type MembershipEventType = (typeof MEMBERSHIP_EVENT_TYPES)[number];

export const MAX_ACCOUNT_LENGTH = 256;

export interface DeviceRecord {
  device_id: string;
  sign_pub: string;
  kx_pub: string;
  account: string;
  role: Role;
  kind: DeviceKind;
}

export interface MembershipEvent {
  v: 1;
  type: MembershipEventType;
  vault_id: string;
  seq: number;
  prev: string;
  membership_epoch: number;
  key_epoch: number;
  ts: number;
  author: string;
  body: JsonObject;
  sig: string;
}

export type UnsignedMembershipEvent = Omit<MembershipEvent, 'sig'>;

/** One removal of a device (`device_remove`, or `member_remove` for each of the account's devices). */
export interface DeviceRemoval {
  device_id: string;
  /** b64 Ed25519 public key of the removed device (verifies its historical records). */
  sign_pub: string;
  /** `seq` of the removing event. */
  removed_seq: number;
  /** Key epoch current when the device was removed (the newest key it could hold). */
  key_epoch: number;
  /** Signed `log_fence` of the removing event: the change-log position its author verified. */
  log_fence: number;
  /** Signed `log_head` of the removing event: the change-log head at `log_fence` (`""` at 0). */
  log_head: string;
  /** Role of the device when it was removed. */
  role: Role;
  /** Kind of the removed device. */
  kind: DeviceKind;
}

/**
 * One `role_set` as it applied to one device: the account's role changed from
 * `prev_role` to `role` at change-log position `log_fence`. Records at or below
 * the fence were accepted under `prev_role`, records above it under `role`.
 */
export interface RoleChange {
  device_id: string;
  /** `seq` of the `role_set` event. */
  changed_seq: number;
  prev_role: Role;
  role: Role;
  /**
   * Signed `log_fence` of the `role_set`: the change-log position its author
   * verified. `null` for a legacy `role_set` signed without a fence (spec §5).
   */
  log_fence: number | null;
  /** Signed `log_head` of the `role_set`: the change-log head at `log_fence` (`""` at 0); `null` when legacy. */
  log_head: string | null;
}

/**
 * Derived vault membership after replaying a verified chain. JSON-friendly
 * (arrays sorted by key) so it can be cached, compared and put in vectors.
 */
export interface MembershipState {
  vault_id: string;
  vault_kind: VaultKind;
  owner_account: string;
  /** b64 `sign_pub` of the genesis author: the pinned trust anchor. */
  trust_anchor: string;
  /** b64 owner recovery signing public key (§3.5); the latest `recovery_rotate` replaces it. */
  recovery_sign_pub: string;
  /** `kid(recovery_sign_pub)`: the author ID used by recovery-signed events. */
  recovery_author: string;
  seq: number;
  /** b64 sha256 of the last event's signing input (`prev` of the next event). */
  head: string;
  membership_epoch: number;
  key_epoch: number;
  rekey_required: boolean;
  /** Union of all `rekey.needs_rotate` item IDs, sorted. */
  needs_rotate: string[];
  /** `wraps_digest` of the latest rekey, or null before the first rekey. */
  wraps_digest: string | null;
  members: { account: string; role: Role }[];
  devices: DeviceRecord[];
  removed_device_ids: string[];
  /** Every removal in chain order (sorted by `removed_seq`, then `device_id`); a re-added device keeps its rows. */
  removals: DeviceRemoval[];
  /** Every `role_set`, one row per device of the account at that event, in chain order (by `changed_seq`, then `device_id`). */
  role_changes: RoleChange[];
}

/** Options for {@link verifyMembershipChain}. */
export interface VerifyChainOptions {
  /** Pinned owner anchor (b64 sign_pub of the genesis author). Mismatch is `forbidden`. */
  trustedAnchor?: string;
  /** Highest witnessed checkpoint; a shorter or forked chain is `rollback`. */
  witnessedCheckpoint?: { vault_id?: string; membership_seq: number; membership_head: string };
  /** Expected vault ID; mismatch is `bad_request`. */
  vaultId?: string;
}

export function parseDevice(value: unknown, what: string): DeviceRecord {
  const obj = asObject(value, what);
  exactKeys(obj, ['device_id', 'sign_pub', 'kx_pub', 'account', 'role', 'kind'], what);
  const device: DeviceRecord = {
    device_id: asId(obj['device_id'], `${what}.device_id`),
    sign_pub: asB64(obj['sign_pub'], `${what}.sign_pub`, 32),
    kx_pub: asB64(obj['kx_pub'], `${what}.kx_pub`, 32),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    role: asEnum(obj['role'], ROLES, `${what}.role`),
    kind: asEnum(obj['kind'], DEVICE_KINDS, `${what}.kind`),
  };
  if (deviceIdFromSignPub(device.sign_pub) !== device.device_id) fail('bad_request', `${what}.device_id does not match sign_pub`);
  return device;
}

/** Structural parse of one event (signature and chain rules are checked by the verifier). */
export function parseMembershipEvent(value: unknown, what = 'membership event'): MembershipEvent {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (!(MEMBERSHIP_EVENT_TYPES as readonly unknown[]).includes(obj['type'])) fail('unsupported_version', `${what}: unsupported event type`);
  exactKeys(obj, ['v', 'type', 'vault_id', 'seq', 'prev', 'membership_epoch', 'key_epoch', 'ts', 'author', 'body', 'sig'], what);
  const prev = obj['prev'] === '' ? '' : asB64(obj['prev'], `${what}.prev`, 32);
  return {
    v: 1,
    type: obj['type'] as MembershipEventType,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    seq: asInt(obj['seq'], `${what}.seq`),
    prev,
    membership_epoch: asInt(obj['membership_epoch'], `${what}.membership_epoch`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    ts: asInt(obj['ts'], `${what}.ts`),
    author: asId(obj['author'], `${what}.author`),
    body: asObject(obj['body'], `${what}.body`) as JsonObject,
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}
