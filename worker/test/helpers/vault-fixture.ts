/**
 * A client-side model of one vault built with the protocol library: real device
 * keys, owner-signed membership events, X25519 wraps and encrypted, signed
 * records. Tests drive the Worker through it exactly as a client would.
 */
import {
  b64encode,
  buildGenesisEvent,
  createDeviceKeys,
  deviceIdFromSignPub,
  nextMembershipEvent,
  randomBytes,
  randomId,
  sealItem,
  signKeyPairFromSeed,
  signRecord,
  verifyMembershipChain,
  wrapToDevice,
  wrapsDigest,
  type JsonObject,
  type KeyPair,
  type MembershipEvent,
  type MembershipEventType,
  type MembershipState,
  type SignedRecord,
  type VaultKind,
  type X25519Wrap,
} from '@ak-vault/protocol';
import { call, createDevice, type CallOptions, type CallResult, type TestDevice } from './api-client.js';

export interface ItemValue {
  name: string;
  value: string;
}

export class VaultFixture {
  readonly events: MembershipEvent[] = [];
  readonly vk = new Map<number, Uint8Array>();
  state!: MembershipState;

  private constructor(
    readonly vaultId: string,
    readonly owner: TestDevice,
    readonly recovery: KeyPair,
    readonly kind: VaultKind,
  ) {}

  /** Create a vault on the server: genesis plus the owner's epoch-1 wrap. */
  static async create(kind: VaultKind = 'personal', account = `acct-${randomId()}`): Promise<VaultFixture> {
    const fx = VaultFixture.local(kind, account);
    const res = await fx.putGenesis();
    if (res.status !== 201) throw new Error(`genesis failed: ${res.status} ${JSON.stringify(res.json)}`);
    return fx;
  }

  /** Build the fixture and genesis event without contacting the server. */
  static local(kind: VaultKind = 'personal', account = `acct-${randomId()}`): VaultFixture {
    const owner = createDevice(account, 'owner', 'human');
    const fx = new VaultFixture(randomId(), owner, signKeyPairFromSeed(randomBytes(32)), kind);
    fx.vk.set(1, randomBytes(32));
    const genesis = buildGenesisEvent(
      {
        vault_id: fx.vaultId,
        ts: Date.now(),
        author: owner.keys.record.device_id,
        body: { vault_kind: kind, owner_account: account, recovery_sign_pub: b64encode(fx.recovery.publicKey), devices: [owner.keys.record as unknown as JsonObject] },
      },
      owner.keys.signSecret,
    );
    fx.events.push(genesis);
    fx.state = verifyMembershipChain(fx.events);
    return fx;
  }

  private genesis?: JsonObject;

  /** Genesis request body; memoized so a retry sends identical bytes (wraps use random nonces). */
  genesisBody(): JsonObject {
    this.genesis ??= { event: this.events[0] as unknown as JsonObject, wraps: [this.wrapFor(this.owner, 1) as unknown as JsonObject] };
    return this.genesis;
  }

  putGenesis(opts: CallOptions = {}): Promise<CallResult> {
    return call(this.owner, 'PUT', `/v1/vaults/${this.vaultId}`, this.genesisBody(), opts);
  }

  get keyEpoch(): number {
    return this.state.key_epoch;
  }

  wrapFor(device: TestDevice, epoch = this.keyEpoch): X25519Wrap {
    return wrapToDevice({ vk: this.vk.get(epoch)!, vaultId: this.vaultId, keyEpoch: epoch, recipient: device.keys.record });
  }

  /** Sign the next membership event (default author: owner device). */
  buildEvent(type: Exclude<MembershipEventType, 'genesis'>, body: JsonObject, signer?: { id: string; secret: Uint8Array }): MembershipEvent {
    const author = signer ?? { id: this.owner.keys.record.device_id, secret: this.owner.keys.signSecret };
    return nextMembershipEvent(this.state, { type, ts: Date.now(), author: author.id, body }, author.secret);
  }

  /** Post an event; on success the local chain advances. */
  async append(event: MembershipEvent, wraps?: X25519Wrap[], caller: TestDevice = this.owner, opts: CallOptions = {}): Promise<CallResult> {
    const body: JsonObject = { event: event as unknown as JsonObject };
    if (wraps) body['wraps'] = wraps as unknown as JsonObject[];
    const res = await call(caller, 'POST', `/v1/vaults/${this.vaultId}/membership`, body, opts);
    if (res.status === 201) {
      this.events.push(event);
      this.state = verifyMembershipChain(this.events);
    }
    return res;
  }

  /** Enroll a device: `device_add` for an existing account, `member_add` for a new account (shared vaults). */
  async addDevice(opts: { account?: string; role?: 'owner' | 'editor' | 'reader'; kind?: 'human' | 'machine' } = {}): Promise<TestDevice> {
    const account = opts.account ?? this.owner.account;
    const known = this.state.members.find((m) => m.account === account);
    const role = known?.role ?? opts.role ?? 'editor';
    const device: TestDevice = { keys: createDeviceKeys({ account, role, kind: opts.kind ?? 'human' }), account, sid: `sid-${randomId()}` };
    const event = known
      ? this.buildEvent('device_add', { device: device.keys.record as unknown as JsonObject, sas: b64encode(randomBytes(32)) })
      : this.buildEvent('member_add', { account, role, devices: [device.keys.record as unknown as JsonObject] });
    const wrap = wrapToDevice({ vk: this.vk.get(this.keyEpoch)!, vaultId: this.vaultId, keyEpoch: this.keyEpoch, recipient: device.keys.record });
    const res = await this.append(event, [wrap]);
    if (res.status !== 201) throw new Error(`enroll failed: ${res.status} ${JSON.stringify(res.json)}`);
    return device;
  }

  async removeDevice(device: TestDevice): Promise<CallResult> {
    return this.append(this.buildEvent('device_remove', { device_id: device.keys.record.device_id, reason: 'lost' }));
  }

  /** Rekey to a fresh vault key with wraps for every current device. */
  rekeyEvent(): { event: MembershipEvent; wraps: X25519Wrap[]; vk: Uint8Array } {
    const vk = randomBytes(32);
    const epoch = this.keyEpoch + 1;
    const wraps = this.state.devices.map((d) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: epoch, recipient: d }));
    const event = this.buildEvent('rekey', { new_key_epoch: epoch, wraps_digest: wrapsDigest(wraps), needs_rotate: [] });
    return { event, wraps, vk };
  }

  async rekey(): Promise<CallResult> {
    const { event, wraps, vk } = this.rekeyEvent();
    const res = await this.append(event, wraps);
    if (res.status === 201) this.vk.set(this.keyEpoch, vk);
    return res;
  }

  /** Encrypt and sign a record (live value, or a tombstone when `value` is null). */
  record(device: TestDevice, itemId: string, base: number, value: ItemValue | null, opts: { keyEpoch?: number; resolves?: string[] } = {}): SignedRecord {
    const keyEpoch = opts.keyEpoch ?? this.keyEpoch;
    const author = device.keys.record.device_id;
    const tombstone = value === null;
    const env = sealItem({
      vk: this.vk.get(keyEpoch) ?? randomBytes(32),
      vault_id: this.vaultId,
      item_id: itemId,
      base_revision: base,
      key_epoch: keyEpoch,
      author,
      tombstone,
      payload: tombstone ? { deleted: true } : { name: value.name, value: value.value, meta: {}, sensitivity: 'normal' },
    });
    return signRecord({ vault_id: this.vaultId, item_id: itemId, base_revision: base, key_epoch: keyEpoch, tombstone, author, ts: Date.now(), resolves: opts.resolves ?? [], env }, device.keys.signSecret);
  }

  put(device: TestDevice, record: SignedRecord, opts: CallOptions = {}): Promise<CallResult> {
    return call(device, 'PUT', `/v1/vaults/${this.vaultId}/items/${record.item_id}`, record, opts);
  }

  write(device: TestDevice, itemId: string, base: number, value: ItemValue | null, opts: CallOptions = {}): Promise<CallResult> {
    return this.put(device, this.record(device, itemId, base, value), opts);
  }

  get(device: TestDevice, sub: string, opts: CallOptions = {}): Promise<CallResult> {
    return call(device, 'GET', `/v1/vaults/${this.vaultId}${sub}`, undefined, opts);
  }

  post(device: TestDevice, sub: string, body: unknown, opts: CallOptions = {}): Promise<CallResult> {
    return call(device, 'POST', `/v1/vaults/${this.vaultId}${sub}`, body, opts);
  }

  recoveryAuthorId(): string {
    return deviceIdFromSignPub(this.recovery.publicKey);
  }
}

export { randomId };
