/**
 * A client-side model of one vault built with the protocol library: real device
 * keys, owner-signed membership events, X25519 wraps and encrypted, signed
 * records. Tests drive the Worker through it exactly as a client would.
 */
import {
  b64encode,
  buildGenesisEvent,
  LOG_START,
  nextLogHead,
  recordDigest,
  verifyChangeLog,
  type ChangeLogCursor,
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

/** One entry of `GET /changes` (fields a client verifies; the rest is server metadata). */
export interface ChangeFeedEntry {
  log_seq: number;
  conflict_id: string | null;
  record: unknown;
  log_head: string;
}

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
    fx.genesisWraps = [fx.wrapFor(owner, 1)];
    const genesis = buildGenesisEvent(
      {
        vault_id: fx.vaultId,
        ts: Date.now(),
        author: owner.keys.record.device_id,
        body: {
          vault_kind: kind,
          owner_account: account,
          recovery_sign_pub: b64encode(fx.recovery.publicKey),
          devices: [owner.keys.record as unknown as JsonObject],
          wraps_digest: wrapsDigest(fx.genesisWraps),
        },
      },
      owner.keys.signSecret,
    );
    fx.events.push(genesis);
    fx.state = verifyMembershipChain(fx.events);
    return fx;
  }

  /** The signed genesis wrap set (fixed, so a retry sends identical bytes). */
  genesisWraps: X25519Wrap[] = [];

  /** Genesis request body. */
  genesisBody(): JsonObject {
    return { event: this.events[0] as unknown as JsonObject, wraps: this.genesisWraps as unknown as JsonObject[] };
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
  async append(event: MembershipEvent, wraps?: X25519Wrap[], caller: TestDevice = this.owner, opts: CallOptions = {}, extra: JsonObject = {}): Promise<CallResult> {
    const body: JsonObject = { ...extra, event: event as unknown as JsonObject };
    if (wraps) body['wraps'] = wraps as unknown as JsonObject[];
    const res = await call(caller, 'POST', `/v1/vaults/${this.vaultId}/membership`, body, opts);
    if (res.status === 201) {
      this.events.push(event);
      this.state = verifyMembershipChain(this.events);
    }
    return res;
  }

  /** A new device of `account` (not enrolled). */
  newDevice(opts: { account?: string; role?: 'owner' | 'editor' | 'reader'; kind?: 'human' | 'machine' } = {}): TestDevice {
    const account = opts.account ?? this.owner.account;
    const role = this.state.members.find((m) => m.account === account)?.role ?? opts.role ?? 'editor';
    return { keys: createDeviceKeys({ account, role, kind: opts.kind ?? 'human' }), account, sid: `sid-${randomId()}` };
  }

  /**
   * The enrollment event for `device` and its signed wrap set (one wrap per
   * `epochs`, default the current epoch): `device_add` for an existing account,
   * `member_add` for a new one (shared vaults).
   */
  enrollEvent(device: TestDevice, epochs: number[] = [this.keyEpoch], signer?: { id: string; secret: Uint8Array }): { event: MembershipEvent; wraps: X25519Wrap[] } {
    const wraps = epochs.map((e) => this.wrapFor(device, e));
    const known = this.state.members.some((m) => m.account === device.account);
    const record = device.keys.record as unknown as JsonObject;
    const wraps_digest = wrapsDigest(wraps);
    const sas = signer && signer.id === this.state.recovery_author ? '' : b64encode(randomBytes(32));
    const event = known
      ? this.buildEvent('device_add', { device: record, sas, wraps_digest }, signer)
      : this.buildEvent('member_add', { account: device.account, role: device.keys.record.role, devices: [record], wraps_digest }, signer);
    return { event, wraps };
  }

  /** Enroll a new device with a wrap of the current epoch. */
  async addDevice(opts: { account?: string; role?: 'owner' | 'editor' | 'reader'; kind?: 'human' | 'machine' } = {}): Promise<TestDevice> {
    const device = this.newDevice(opts);
    const { event, wraps } = this.enrollEvent(device);
    const res = await this.append(event, wraps);
    if (res.status !== 201) throw new Error(`enroll failed: ${res.status} ${JSON.stringify(res.json)}`);
    return device;
  }

  /** Current change-log head as the server reports it (the log_fence a remover signs). */
  async logHead(device: TestDevice = this.owner): Promise<number> {
    const res = await this.get(device, '/changes?cursor=0&limit=1');
    if (res.status !== 200) throw new Error(`changes failed: ${res.status}`);
    return (res.json as { head: { log_seq: number } }).head.log_seq;
  }

  /**
   * Pull the whole change log as `device`, verify it against the local chain as a client
   * would (`verifyChangeLog`, page by page) and return the head at every position
   * (`heads[n]`; `heads[0]` = ""). A remover signs the head it computed, never the server's.
   */
  async verifiedLogHeads(device: TestDevice = this.owner): Promise<string[]> {
    const heads = [LOG_START.log_head];
    let cursor: ChangeLogCursor = LOG_START;
    for (;;) {
      const res = await this.get(device, `/changes?cursor=${cursor.log_seq}`);
      if (res.status !== 200) throw new Error(`changes failed: ${res.status}`);
      const page = res.json as { changes: ChangeFeedEntry[]; has_more: boolean };
      const entries = page.changes.map(({ log_seq, conflict_id, record }) => ({ log_seq, conflict_id, record }));
      const keptHeads = new Map(heads.map((h, i) => [i, h]));
      const { head, records } = verifyChangeLog(entries, this.state, { from: cursor, complete: !page.has_more, keptHeads });
      let prev = cursor.log_head;
      records.forEach((r, i) => {
        prev = nextLogHead(prev, entries[i]!.log_seq, entries[i]!.conflict_id, recordDigest(r));
        heads.push(prev);
      });
      cursor = head;
      if (!page.has_more) return heads;
    }
  }

  /**
   * `by` removes `device`, signing the head of the change log it verified as `{log_fence,
   * log_head}`. A given `logFence` is signed with the head at that position (a random head
   * when the position does not exist yet).
   */
  /** The signed removal fence `{log_fence, log_head}` at the current head, as `by` verified the log. */
  async fence(by: TestDevice = this.owner): Promise<{ log_fence: number; log_head: string }> {
    const heads = await this.verifiedLogHeads(by);
    return { log_fence: heads.length - 1, log_head: heads[heads.length - 1]! };
  }

  async removeDevice(device: TestDevice, logFence?: number, by: TestDevice = this.owner): Promise<CallResult> {
    const heads = await this.verifiedLogHeads(by);
    const fence = logFence ?? heads.length - 1;
    const head = heads[fence] ?? b64encode(randomBytes(32));
    return this.append(this.buildEvent('device_remove', { device_id: device.keys.record.device_id, reason: 'lost', log_fence: fence, log_head: head }, signerOf(by)), undefined, by);
  }

  /** Rekey to a fresh vault key with wraps for every current device (signed by `by`, default the owner). */
  rekeyEvent(by: TestDevice = this.owner): { event: MembershipEvent; wraps: X25519Wrap[]; vk: Uint8Array } {
    const vk = randomBytes(32);
    const epoch = this.keyEpoch + 1;
    const wraps = this.state.devices.map((d) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: epoch, recipient: d }));
    const event = this.buildEvent('rekey', { new_key_epoch: epoch, wraps_digest: wrapsDigest(wraps), needs_rotate: [] }, signerOf(by));
    return { event, wraps, vk };
  }

  async rekey(by: TestDevice = this.owner): Promise<CallResult> {
    const { event, wraps, vk } = this.rekeyEvent(by);
    const res = await this.append(event, wraps, by);
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

/** Membership-event signer of a test device. */
export function signerOf(device: TestDevice): { id: string; secret: Uint8Array } {
  return { id: device.keys.record.device_id, secret: device.keys.signSecret };
}

export { randomId };
