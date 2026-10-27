/**
 * Membership projection for the dashboard: who the verified chain says are
 * members and devices, which key epoch and rekey state it is in, and what this
 * browser session may do. It reads only the verified `MembershipState`; nothing
 * here comes from an unverified response, and nothing is built from item values.
 *
 * The browser is a `browser` session (ADR 0002 D1): the Worker refuses it on
 * every membership write, so this view is read-only by design. Inviting,
 * removing, re-roling and rekeying stay with an owner CLI device.
 */
import type { DeviceKind, MembershipState, Role, VaultKind } from '@ak-vault/protocol';

export type CapabilityId =
  | 'read_metadata'
  | 'set_secret'
  | 'delete_secret'
  | 'reveal_value'
  | 'invite_member'
  | 'remove_member'
  | 'change_role'
  | 'rekey'
  | 'enroll_device';

/** Fixed reasons the UI maps to text. Never server or item text. */
export type CapabilityReason = 'role_read_only' | 'rekey_pending' | 'browser_session' | 'write_only_dashboard';

export interface Capability {
  id: CapabilityId;
  allowed: boolean;
  reason: CapabilityReason | null;
}

export interface DeviceView {
  /** First 8 characters of the device ID. */
  shortId: string;
  kind: DeviceKind;
  thisBrowser: boolean;
}

export interface MemberView {
  /** First 8 characters of the account ID. */
  shortId: string;
  role: Role;
  you: boolean;
  /** The account that created the vault. */
  ownerAccount: boolean;
  devices: DeviceView[];
}

export interface RemovedDeviceView {
  shortId: string;
  /** Epoch of the newest vault key that device could hold. */
  keyEpoch: number;
}

export interface RotationView {
  /** Names of items a removed member may have seen, as far as this browser can read them. */
  names: string[];
  /** Flagged items this browser does not list (unreadable, hidden or deleted since). */
  unlisted: number;
}

export interface MembershipView {
  vaultKind: VaultKind;
  keyEpoch: number;
  membershipSeq: number;
  rekeyRequired: boolean;
  selfRole: Role;
  members: MemberView[];
  removedDevices: RemovedDeviceView[];
  rotation: RotationView;
  capabilities: Capability[];
}

const SHORT = 8;

function short(id: string): string {
  return id.slice(0, SHORT);
}

const ROLE_ORDER: Record<Role, number> = { owner: 0, editor: 1, reader: 2 };

/** Whether a role may author item records (spec §11: human `owner` and `editor` devices). */
export function roleCanWrite(role: Role): boolean {
  return role === 'owner' || role === 'editor';
}

export function capabilitiesFor(role: Role, rekeyRequired: boolean): Capability[] {
  const canWrite = roleCanWrite(role);
  const write = (id: 'set_secret' | 'delete_secret'): Capability => ({
    id,
    allowed: canWrite && !rekeyRequired,
    reason: !canWrite ? 'role_read_only' : rekeyRequired ? 'rekey_pending' : null,
  });
  const never = (id: CapabilityId, reason: CapabilityReason): Capability => ({ id, allowed: false, reason });
  return [
    { id: 'read_metadata', allowed: true, reason: null },
    write('set_secret'),
    write('delete_secret'),
    never('reveal_value', 'write_only_dashboard'),
    never('invite_member', 'browser_session'),
    never('remove_member', 'browser_session'),
    never('change_role', 'browser_session'),
    never('rekey', 'browser_session'),
    never('enroll_device', 'browser_session'),
  ];
}

/**
 * Project the verified state. `selfDeviceId` must be a current device of the
 * state (the pull refuses otherwise); `itemNames` maps the item IDs this
 * browser lists to their names, for the `needs_rotate` flags.
 */
export function buildMembershipView(state: MembershipState, selfDeviceId: string, itemNames: ReadonlyMap<string, string>): MembershipView {
  const self = state.devices.find((d) => d.device_id === selfDeviceId);
  // Fail closed: a state that does not contain this device has no role to show.
  const selfRole: Role = self ? self.role : 'reader';
  const selfAccount = self?.account ?? null;

  const members: MemberView[] = state.members
    .map((m) => ({
      shortId: short(m.account),
      role: m.role,
      you: m.account === selfAccount,
      ownerAccount: m.account === state.owner_account,
      devices: state.devices
        .filter((d) => d.account === m.account)
        .map((d) => ({ shortId: short(d.device_id), kind: d.kind, thisBrowser: d.device_id === selfDeviceId }))
        .sort((a, b) => (a.shortId < b.shortId ? -1 : a.shortId > b.shortId ? 1 : 0)),
    }))
    .sort((a, b) => ROLE_ORDER[a.role] - ROLE_ORDER[b.role] || (a.shortId < b.shortId ? -1 : a.shortId > b.shortId ? 1 : 0));

  const names: string[] = [];
  let unlisted = 0;
  for (const id of state.needs_rotate) {
    const name = itemNames.get(id);
    if (name === undefined) unlisted++;
    else names.push(name);
  }
  names.sort();

  return {
    vaultKind: state.vault_kind,
    keyEpoch: state.key_epoch,
    membershipSeq: state.seq,
    rekeyRequired: state.rekey_required,
    selfRole,
    members,
    removedDevices: state.removals.map((r) => ({ shortId: short(r.device_id), keyEpoch: r.key_epoch })),
    rotation: { names, unlisted },
    capabilities: capabilitiesFor(selfRole, state.rekey_required),
  };
}
