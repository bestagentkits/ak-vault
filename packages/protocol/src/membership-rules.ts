/**
 * Mutable replay state and per-event body rules of the membership log (spec §4).
 * Internal module: the public entry point is `verifyMembershipChain`.
 */
import type { JsonObject } from './canonical-json.js';
import { fail } from './errors.js';
import {
  REMOVE_REASONS,
  ROLES,
  VAULT_KINDS,
  MAX_ACCOUNT_LENGTH,
  parseDevice,
  type DeviceRecord,
  type DeviceRemoval,
  type MembershipEvent,
  type MembershipState,
  type Role,
  type VaultKind,
} from './membership-types.js';
import { parseLogPosition, type ChangeLogCursor } from './change-log.js';
import { deviceIdFromSignPub } from './signing.js';
import { asArray, asB64, asEnum, asId, asIdList, asInt, asString, exactKeys } from './validate.js';

export class ReplayState {
  vaultKind: VaultKind = 'personal';
  ownerAccount = '';
  trustAnchor = '';
  recoverySignPub = '';
  recoveryAuthor = '';
  keyEpoch = 1;
  rekeyRequired = false;
  wrapsDigest: string | null = null;
  readonly needsRotate = new Set<string>();
  readonly members = new Map<string, Role>();
  readonly devices = new Map<string, DeviceRecord>();
  readonly removed = new Set<string>();
  readonly removals: DeviceRemoval[] = [];
  /** Every recovery author ID the chain has ever trusted (genesis and each recovery_rotate). */
  readonly recoveryAuthors = new Set<string>();

  private ownerDeviceCount(): number {
    let n = 0;
    for (const d of this.devices.values()) if (d.role === 'owner' && d.kind === 'human') n++;
    return n;
  }

  private ownerAccountCount(): number {
    let n = 0;
    for (const role of this.members.values()) if (role === 'owner') n++;
    return n;
  }

  /** Validate a device being added; a previously removed ID needs `allowReadd` (fresh device_add). */
  private admitDevice(device: DeviceRecord, allowReadd: boolean): void {
    if (this.devices.has(device.device_id)) fail('bad_request', 'device is already a member');
    if (this.recoveryAuthors.has(device.device_id)) fail('bad_request', 'device key collides with a recovery key');
    if (this.removed.has(device.device_id)) {
      if (!allowReadd) fail('forbidden', 'removed device reappears without a fresh device_add');
      this.removed.delete(device.device_id);
    }
    this.devices.set(device.device_id, device);
  }

  /** Record a removal; the caller has already deleted the device from `devices`. */
  private recordRemoval(device: DeviceRecord, seq: number, fence: ChangeLogCursor): void {
    this.removed.add(device.device_id);
    this.removals.push({ device_id: device.device_id, sign_pub: device.sign_pub, removed_seq: seq, key_epoch: this.keyEpoch, log_fence: fence.log_seq, log_head: fence.log_head });
  }

  applyGenesis(body: JsonObject, author: string): DeviceRecord {
    exactKeys(body, ['vault_kind', 'owner_account', 'recovery_sign_pub', 'devices', 'wraps_digest'], 'genesis.body');
    asB64(body['wraps_digest'], 'genesis.body.wraps_digest', 32);
    this.vaultKind = asEnum(body['vault_kind'], VAULT_KINDS, 'genesis.body.vault_kind');
    this.ownerAccount = asString(body['owner_account'], 'genesis.body.owner_account', MAX_ACCOUNT_LENGTH, 1);
    this.recoverySignPub = asB64(body['recovery_sign_pub'], 'genesis.body.recovery_sign_pub', 32);
    this.recoveryAuthor = deviceIdFromSignPub(this.recoverySignPub);
    this.recoveryAuthors.add(this.recoveryAuthor);
    const devices = asArray(body['devices'], 'genesis.body.devices', 64).map((d, i) => parseDevice(d, `genesis.body.devices[${i}]`));
    if (devices.length === 0) fail('bad_request', 'genesis needs at least one device');
    this.members.set(this.ownerAccount, 'owner');
    for (const device of devices) {
      if (device.account !== this.ownerAccount || device.role !== 'owner') fail('bad_request', 'genesis devices must be owner devices of owner_account');
      this.admitDevice(device, false);
    }
    const authorDevice = this.devices.get(author);
    if (!authorDevice || authorDevice.kind !== 'human') fail('forbidden', 'genesis author must be a human owner device in genesis');
    this.trustAnchor = authorDevice.sign_pub;
    return authorDevice;
  }

  /** Resolve the signing key of a non-genesis author, enforcing who may author `type`. */
  authorKey(event: MembershipEvent): string {
    if (event.author === this.recoveryAuthor) {
      // The recovery identity cannot read the change log, so it cannot sign an honest
      // removal fence: it only enrolls a device, which then removes lost devices.
      if (event.type !== 'device_add') fail('forbidden', 'recovery key may only author device_add');
      return this.recoverySignPub;
    }
    const device = this.devices.get(event.author);
    if (!device) fail('forbidden', 'author is not a current device');
    if (device.role !== 'owner' || device.kind !== 'human') fail('forbidden', 'author is not a human owner device');
    return device.sign_pub;
  }

  apply(event: MembershipEvent): void {
    const body = event.body;
    const byRecovery = event.author === this.recoveryAuthor;
    switch (event.type) {
      case 'genesis':
        return fail('bad_request', 'genesis must be the first event only');
      case 'device_add': {
        exactKeys(body, ['device', 'sas', 'wraps_digest'], 'device_add.body');
        asB64(body['wraps_digest'], 'device_add.body.wraps_digest', 32);
        const device = parseDevice(body['device'], 'device_add.body.device');
        if (byRecovery) {
          if (body['sas'] !== '') fail('bad_request', 'recovery-authored device_add must carry sas ""');
          if (device.role !== 'owner') fail('forbidden', 'recovery key may only add owner devices');
        } else {
          asB64(body['sas'], 'device_add.body.sas', 32);
        }
        const accountRole = this.members.get(device.account);
        if (accountRole === undefined) fail('forbidden', 'device account is not a member');
        if (accountRole !== device.role) fail('bad_request', 'device role must equal its account role');
        return this.admitDevice(device, true);
      }
      case 'device_remove': {
        exactKeys(body, ['device_id', 'reason', 'log_fence', 'log_head'], 'device_remove.body');
        const id = asId(body['device_id'], 'device_remove.body.device_id');
        asEnum(body['reason'], REMOVE_REASONS, 'device_remove.body.reason');
        const logFence = parseLogPosition(body['log_fence'], body['log_head'], 'device_remove.body.log_fence', 'device_remove.body.log_head');
        const removed = this.devices.get(id);
        if (!removed) fail('bad_request', 'device is not a current member');
        this.devices.delete(id);
        this.recordRemoval(removed, event.seq, logFence);
        if (this.ownerDeviceCount() === 0) fail('forbidden', 'cannot remove the last human owner device');
        this.rekeyRequired = true;
        return;
      }
      case 'member_add': {
        exactKeys(body, ['account', 'role', 'devices', 'wraps_digest'], 'member_add.body');
        asB64(body['wraps_digest'], 'member_add.body.wraps_digest', 32);
        if (this.vaultKind !== 'shared') fail('forbidden', 'member_add is only allowed in shared vaults');
        const account = asString(body['account'], 'member_add.body.account', MAX_ACCOUNT_LENGTH, 1);
        const role = asEnum(body['role'], ROLES, 'member_add.body.role');
        if (this.members.has(account)) fail('bad_request', 'account is already a member');
        const devices = asArray(body['devices'], 'member_add.body.devices', 64).map((d, i) => parseDevice(d, `member_add.body.devices[${i}]`));
        if (devices.length === 0) fail('bad_request', 'member_add needs at least one device');
        this.members.set(account, role);
        for (const device of devices) {
          if (device.account !== account || device.role !== role) fail('bad_request', 'member device account/role mismatch');
          this.admitDevice(device, false);
        }
        return;
      }
      case 'member_remove': {
        exactKeys(body, ['account', 'log_fence', 'log_head'], 'member_remove.body');
        if (this.vaultKind !== 'shared') fail('forbidden', 'member_remove is only allowed in shared vaults');
        const account = asString(body['account'], 'member_remove.body.account', MAX_ACCOUNT_LENGTH, 1);
        const logFence = parseLogPosition(body['log_fence'], body['log_head'], 'member_remove.body.log_fence', 'member_remove.body.log_head');
        if (!this.members.has(account)) fail('bad_request', 'account is not a member');
        this.members.delete(account);
        const leaving = [...this.devices.values()].filter((d) => d.account === account).sort((a, b) => (a.device_id < b.device_id ? -1 : 1));
        for (const d of leaving) {
          this.devices.delete(d.device_id);
          this.recordRemoval(d, event.seq, logFence);
        }
        if (this.ownerAccountCount() === 0 || this.ownerDeviceCount() === 0) fail('forbidden', 'cannot remove the last owner');
        this.rekeyRequired = true;
        return;
      }
      case 'role_set': {
        exactKeys(body, ['account', 'role'], 'role_set.body');
        const account = asString(body['account'], 'role_set.body.account', MAX_ACCOUNT_LENGTH, 1);
        const role = asEnum(body['role'], ROLES, 'role_set.body.role');
        if (!this.members.has(account)) fail('bad_request', 'account is not a member');
        this.members.set(account, role);
        for (const [id, d] of this.devices) if (d.account === account) this.devices.set(id, { ...d, role });
        if (this.ownerAccountCount() === 0 || this.ownerDeviceCount() === 0) fail('forbidden', 'cannot demote the last owner');
        return;
      }
      case 'rekey': {
        exactKeys(body, ['new_key_epoch', 'wraps_digest', 'needs_rotate'], 'rekey.body');
        const next = asInt(body['new_key_epoch'], 'rekey.body.new_key_epoch', 1);
        if (next !== this.keyEpoch + 1 || event.key_epoch !== next) fail('bad_request', 'rekey must advance key_epoch by exactly 1');
        this.wrapsDigest = asB64(body['wraps_digest'], 'rekey.body.wraps_digest', 32);
        for (const id of asIdList(body['needs_rotate'], 'rekey.body.needs_rotate', 100_000)) this.needsRotate.add(id);
        this.keyEpoch = next;
        this.rekeyRequired = false;
        return;
      }
      case 'recovery_rotate': {
        exactKeys(body, ['recovery_sign_pub'], 'recovery_rotate.body');
        const pub = asB64(body['recovery_sign_pub'], 'recovery_rotate.body.recovery_sign_pub', 32);
        const author = deviceIdFromSignPub(pub);
        if (this.recoveryAuthors.has(author)) fail('bad_request', 'recovery_rotate must move to a recovery key never used before');
        if (this.devices.has(author) || this.removals.some((r) => r.device_id === author)) fail('bad_request', 'recovery key collides with a device key');
        this.recoverySignPub = pub;
        this.recoveryAuthor = author;
        this.recoveryAuthors.add(author);
        return;
      }
    }
  }

  snapshot(vaultId: string, seq: number, head: string): MembershipState {
    const byKey = <T>(items: T[], key: (t: T) => string): T[] => items.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
    return {
      vault_id: vaultId,
      vault_kind: this.vaultKind,
      owner_account: this.ownerAccount,
      trust_anchor: this.trustAnchor,
      recovery_sign_pub: this.recoverySignPub,
      recovery_author: this.recoveryAuthor,
      seq,
      head,
      membership_epoch: seq,
      key_epoch: this.keyEpoch,
      rekey_required: this.rekeyRequired,
      needs_rotate: [...this.needsRotate].sort(),
      wraps_digest: this.wrapsDigest,
      members: byKey([...this.members].map(([account, role]) => ({ account, role })), (m) => m.account),
      devices: byKey([...this.devices.values()].map((d) => ({ ...d })), (d) => d.device_id),
      removed_device_ids: [...this.removed].sort(),
      removals: this.removals.map((r) => ({ ...r })),
    };
  }
}
