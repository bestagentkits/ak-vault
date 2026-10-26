/**
 * What the dashboard shows about vault access. Everything here is derived from
 * the membership chain this browser verified itself (`MembershipState`): there
 * is no server-supplied list, no extra request and no field a server could add.
 * An account that is not a member of the enrolled vault never appears, and the
 * dashboard holds a single vault: the one this browser was enrolled into.
 *
 * Membership is cryptographic: a row exists only because an owner-signed
 * `genesis`, `device_add` or `member_add` event is on the chain. A web login or
 * an AgentKit license seat never creates one, and v1 has no invitation state on
 * the wire, so there is nothing to list as pending, accepted or timed out.
 */
import type { DeviceKind, MembershipState, Role, VaultKind } from '@ak-vault/protocol';

export interface DeviceEntry {
  deviceId: string;
  kind: DeviceKind;
  isThisBrowser: boolean;
}

export interface AccountEntry {
  account: string;
  isSelf: boolean;
  role: Role;
  devices: DeviceEntry[];
}

/** Why an operation is not available to this browser session. */
export type DeniedReason = 'role' | 'rekey_pending' | 'owner_device' | 'personal_vault';

export type CapabilityId =
  | 'view_access'
  | 'write_secrets'
  | 'invite_member'
  | 'change_role'
  | 'remove_member'
  | 'remove_device'
  | 'rekey';

export interface Capability {
  id: CapabilityId;
  allowed: boolean;
  reason: DeniedReason | null;
}

export interface MembershipView {
  vaultKind: VaultKind;
  selfRole: Role;
  keyEpoch: number;
  membershipSeq: number;
  rekeyRequired: boolean;
  needsRotate: string[];
  accounts: AccountEntry[];
  /** Devices removed from the chain, ever (a re-added device is counted once per removal). */
  removedDevices: number;
  capabilities: Capability[];
  /** True when this role may write items (server and UI both enforce it). */
  canWrite: boolean;
}

const ROLE_ORDER: Record<Role, number> = { owner: 0, editor: 1, reader: 2 };

/** Membership operations are authored by owner devices only (spec §4); a `browser` session cannot post them. */
const OWNER_DEVICE_OPS: CapabilityId[] = ['invite_member', 'change_role', 'remove_member', 'remove_device', 'rekey'];

export function membershipViewOf(state: MembershipState, selfDeviceId: string): MembershipView {
  const self = state.devices.find((d) => d.device_id === selfDeviceId);
  if (!self) throw new Error('self device is not in the verified chain');
  const byAccount = new Map<string, AccountEntry>();
  for (const m of state.members) byAccount.set(m.account, { account: m.account, isSelf: m.account === self.account, role: m.role, devices: [] });
  for (const d of state.devices) {
    const entry = byAccount.get(d.account);
    if (entry) entry.devices.push({ deviceId: d.device_id, kind: d.kind, isThisBrowser: d.device_id === selfDeviceId });
  }
  const accounts = [...byAccount.values()].sort(
    (a, b) => ROLE_ORDER[a.role] - ROLE_ORDER[b.role] || (a.account < b.account ? -1 : a.account > b.account ? 1 : 0),
  );
  for (const a of accounts) a.devices.sort((x, y) => (x.deviceId < y.deviceId ? -1 : x.deviceId > y.deviceId ? 1 : 0));

  const mayWrite = self.role !== 'reader';
  const capabilities: Capability[] = [
    { id: 'view_access', allowed: true, reason: null },
    {
      id: 'write_secrets',
      allowed: mayWrite && !state.rekey_required,
      reason: !mayWrite ? 'role' : state.rekey_required ? 'rekey_pending' : null,
    },
    ...OWNER_DEVICE_OPS.map<Capability>((id) => ({
      id,
      allowed: false,
      reason: id === 'invite_member' && state.vault_kind === 'personal' ? 'personal_vault' : 'owner_device',
    })),
  ];
  return {
    vaultKind: state.vault_kind,
    selfRole: self.role,
    keyEpoch: state.key_epoch,
    membershipSeq: state.seq,
    rekeyRequired: state.rekey_required,
    needsRotate: [...state.needs_rotate],
    accounts,
    removedDevices: state.removals.length,
    capabilities,
    canWrite: mayWrite,
  };
}

/** A change between two verified views that the user should hear about (never carries a name or a value). */
export type AccessChange =
  | { kind: 'role_changed'; from: Role; to: Role }
  | { kind: 'member_removed' }
  | { kind: 'member_added' }
  | { kind: 'rekey_started' }
  | { kind: 'rekey_done' };

/** Differences from `prev` to `next`, so a stale view is never silently replaced. */
export function diffAccess(prev: MembershipView, next: MembershipView): AccessChange[] {
  const out: AccessChange[] = [];
  if (prev.selfRole !== next.selfRole) out.push({ kind: 'role_changed', from: prev.selfRole, to: next.selfRole });
  const before = new Set(prev.accounts.map((a) => a.account));
  const after = new Set(next.accounts.map((a) => a.account));
  if ([...before].some((a) => !after.has(a))) out.push({ kind: 'member_removed' });
  if ([...after].some((a) => !before.has(a))) out.push({ kind: 'member_added' });
  if (!prev.rekeyRequired && next.rekeyRequired) out.push({ kind: 'rekey_started' });
  if (prev.rekeyRequired && !next.rekeyRequired) out.push({ kind: 'rekey_done' });
  return out;
}
