/**
 * Client-side model of one vault for the platform log disclosure scan, built
 * with the protocol library and driven over HTTP against the lab Worker: real
 * device keys, owner-signed membership events, X25519 wraps, encrypted and signed
 * records, verified pulls and signed checkpoints. It mirrors
 * worker/test/helpers/vault-fixture.ts, which runs inside workerd and cannot be
 * imported from Node.
 */
import {
  LOG_START,
  applyRecord,
  b64encode,
  buildGenesisEvent,
  computeStateDigest,
  nextLogHead,
  nextMembershipEvent,
  openItem,
  randomBytes,
  randomId,
  recordDigest,
  sealItem,
  signCheckpoint,
  signKeyPairFromSeed,
  signRecord,
  unwrapFromDevice,
  verifyChangeLog,
  verifyDeviceWraps,
  verifyMembershipChain,
  wrapToDevice,
  wrapsDigest,
  type ChangeLogCursor,
  type ItemState,
  type JsonObject,
  type KeyPair,
  type MembershipEvent,
  type MembershipEventType,
  type MembershipState,
  type SignedRecord,
  type X25519Wrap,
} from '@ak-vault/protocol';
import type { CallOptions, CallResult, LabClient, LabDevice } from './lab-client.js';
import type { NeedleSet } from './needle-scan.js';

export interface Signer {
  id: string;
  secret: Uint8Array;
}

export const signerOf = (d: LabDevice): Signer => ({ id: d.keys.record.device_id, secret: d.keys.signSecret });

export interface PulledItem {
  name: string;
  value: string;
}

export class LabVault {
  readonly vaultId = randomId();
  readonly events: MembershipEvent[] = [];
  readonly vk = new Map<number, Uint8Array>();
  recovery: KeyPair;
  state!: MembershipState;

  constructor(
    private readonly client: LabClient,
    private readonly needles: NeedleSet,
    readonly owner: LabDevice,
  ) {
    this.recovery = signKeyPairFromSeed(randomBytes(32));
    needles.add('recovery_material', this.recovery.secretKey);
    needles.add('opaque_ids', this.vaultId);
  }

  get keyEpoch(): number {
    return this.state.key_epoch;
  }

  private newVaultKey(epoch: number): Uint8Array {
    const vk = randomBytes(32);
    this.vk.set(epoch, vk);
    this.needles.add('keys', vk);
    return vk;
  }

  call(device: LabDevice, method: string, sub: string, body?: unknown, opts?: CallOptions): Promise<CallResult> {
    return this.client.call(device, method, `/v1/vaults/${this.vaultId}${sub}`, body, opts);
  }

  async genesis(): Promise<CallResult> {
    const vk = this.newVaultKey(1);
    const wraps = [wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: 1, recipient: this.owner.keys.record })];
    const event = buildGenesisEvent(
      {
        vault_id: this.vaultId,
        ts: Date.now(),
        author: this.owner.keys.record.device_id,
        body: {
          vault_kind: 'personal',
          owner_account: this.owner.account,
          recovery_sign_pub: b64encode(this.recovery.publicKey),
          devices: [this.owner.keys.record as unknown as JsonObject],
          wraps_digest: wrapsDigest(wraps),
        },
      },
      this.owner.keys.signSecret,
    );
    const res = await this.call(this.owner, 'PUT', '', { event: event as unknown as JsonObject, wraps: wraps as unknown as JsonObject[] });
    if (res.status === 201) {
      this.events.push(event);
      this.state = verifyMembershipChain(this.events);
    }
    return res;
  }

  buildEvent(type: Exclude<MembershipEventType, 'genesis'>, body: JsonObject, signer: Signer = signerOf(this.owner)): MembershipEvent {
    return nextMembershipEvent(this.state, { type, ts: Date.now(), author: signer.id, body }, signer.secret);
  }

  async append(caller: LabDevice, event: MembershipEvent, wraps?: X25519Wrap[], extra: JsonObject = {}, opts?: CallOptions): Promise<CallResult> {
    const body: JsonObject = { ...extra, event: event as unknown as JsonObject };
    if (wraps) body['wraps'] = wraps as unknown as JsonObject[];
    const res = await this.call(caller, 'POST', '/membership', body, opts);
    if (res.status === 201) {
      this.events.push(event);
      this.state = verifyMembershipChain(this.events);
    }
    return res;
  }

  /** `device_add` for `device` with a wrap per epoch in `epochs`, signed by `signer` (owner or recovery key). */
  enrollEvent(device: LabDevice, signer: Signer = signerOf(this.owner), epochs: number[] = [this.keyEpoch]): { event: MembershipEvent; wraps: X25519Wrap[] } {
    const wraps = epochs.map((e) => wrapToDevice({ vk: this.vk.get(e)!, vaultId: this.vaultId, keyEpoch: e, recipient: device.keys.record }));
    const sas = signer.id === this.state.recovery_author ? '' : b64encode(randomBytes(32));
    const event = this.buildEvent('device_add', { device: device.keys.record as unknown as JsonObject, sas, wraps_digest: wrapsDigest(wraps) }, signer);
    return { event, wraps };
  }

  /** As `device`, fetch the wrap set of the event at `seq`, check it against the signed digest and unwrap its own key. */
  async receiveWrap(device: LabDevice, seq: number, opts?: CallOptions): Promise<{ res: CallResult; vk?: Uint8Array }> {
    const res = await this.call(device, 'GET', `/wraps?membership_seq=${seq}`, undefined, opts);
    if (res.status !== 200) return { res };
    const own = verifyDeviceWraps(this.events[seq], res.json.wraps as unknown[]).find((w) => w.rcpt === device.keys.record.device_id);
    if (!own) throw new Error('no wrap for the enrolled device');
    return { res, vk: unwrapFromDevice({ wrap: own, vaultId: this.vaultId, deviceId: device.keys.record.device_id, kxSecret: device.keys.kxSecret }) };
  }

  record(device: LabDevice, itemId: string, base: number, value: PulledItem | null): SignedRecord {
    const keyEpoch = this.keyEpoch;
    const author = device.keys.record.device_id;
    const tombstone = value === null;
    const env = sealItem({
      vk: this.vk.get(keyEpoch)!,
      vault_id: this.vaultId,
      item_id: itemId,
      base_revision: base,
      key_epoch: keyEpoch,
      author,
      tombstone,
      payload: tombstone ? { deleted: true } : { name: value.name, value: value.value, meta: {}, sensitivity: 'normal' },
    });
    return signRecord({ vault_id: this.vaultId, item_id: itemId, base_revision: base, key_epoch: keyEpoch, tombstone, author, ts: Date.now(), resolves: [], env }, device.keys.signSecret);
  }

  write(device: LabDevice, itemId: string, base: number, value: PulledItem | null, opts?: CallOptions): Promise<CallResult> {
    this.needles.add('opaque_ids', itemId);
    return this.call(device, 'PUT', `/items/${itemId}`, this.record(device, itemId, base, value), opts);
  }

  /**
   * Full verified pull as `device`: verify every page against the membership chain,
   * decrypt the live items, and return them with the position and state digest a
   * checkpoint signs, plus the log head at every position (for removal fences).
   */
  async pull(device: LabDevice): Promise<{ items: Map<string, PulledItem>; cursor: ChangeLogCursor; stateDigest: string; heads: string[] }> {
    const heads = [LOG_START.log_head];
    const states = new Map<string, ItemState>();
    let cursor: ChangeLogCursor = LOG_START;
    for (;;) {
      const res = await this.call(device, 'GET', `/changes?cursor=${cursor.log_seq}`);
      if (res.status !== 200) throw new Error(`pull failed with ${res.status}`);
      const entries = (res.json.changes as { log_seq: number; conflict_id: string | null; record: unknown }[]).map(({ log_seq, conflict_id, record }) => ({ log_seq, conflict_id, record }));
      const verified = verifyChangeLog(entries, this.state, { from: cursor, complete: !res.json.has_more, keptHeads: new Map(heads.map((h, i) => [i, h])) });
      let prev = cursor.log_head;
      verified.records.forEach((r, i) => {
        const entry = entries[i]!;
        prev = nextLogHead(prev, entry.log_seq, entry.conflict_id, recordDigest(r));
        heads.push(prev);
        states.set(r.item_id, applyRecord(states.get(r.item_id), r, entry.conflict_id ? { conflictId: entry.conflict_id } : {}).state);
      });
      cursor = verified.head;
      if (!res.json.has_more) break;
    }
    const items = new Map<string, PulledItem>();
    const latest = await this.latestRecords(device, [...states.values()].filter((s) => !s.tombstone && s.revision > 0).map((s) => s.item_id));
    for (const r of latest) {
      const payload = openItem({ vk: this.vk.get(r.key_epoch)!, vault_id: r.vault_id, item_id: r.item_id, base_revision: r.base_revision, key_epoch: r.key_epoch, author: r.author, tombstone: r.tombstone, env: r.env });
      if ('name' in payload) items.set(r.item_id, { name: payload.name, value: payload.value });
    }
    return { items, cursor, stateDigest: computeStateDigest(states.values()), heads };
  }

  private async latestRecords(device: LabDevice, itemIds: string[]): Promise<SignedRecord[]> {
    const out: SignedRecord[] = [];
    for (const id of itemIds) {
      const res = await this.call(device, 'GET', `/items/${id}`);
      if (res.status !== 200) throw new Error(`item read failed with ${res.status}`);
      out.push(res.json.record as SignedRecord);
    }
    return out;
  }

  async checkpoint(device: LabDevice, at: { cursor: ChangeLogCursor; stateDigest: string }): Promise<CallResult> {
    const cp = signCheckpoint(
      { vault_id: this.vaultId, membership_seq: this.state.seq, membership_head: this.state.head, log_seq: at.cursor.log_seq, state_digest: at.stateDigest, key_epoch: this.keyEpoch, ts: Date.now(), author: device.keys.record.device_id },
      device.keys.signSecret,
    );
    return this.call(device, 'POST', '/checkpoints', cp);
  }

  /** `by` removes `target`, fencing the change log at the head it verified itself. */
  async removeDevice(by: LabDevice, target: LabDevice): Promise<CallResult> {
    const { heads } = await this.pull(by);
    const body = { device_id: target.keys.record.device_id, reason: 'lost', log_fence: heads.length - 1, log_head: heads[heads.length - 1]! };
    return this.append(by, this.buildEvent('device_remove', body, signerOf(by)));
  }

  async rekey(by: LabDevice): Promise<CallResult> {
    const epoch = this.keyEpoch + 1;
    const vk = randomBytes(32);
    const wraps = this.state.devices.map((d) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: epoch, recipient: d }));
    const res = await this.append(by, this.buildEvent('rekey', { new_key_epoch: epoch, wraps_digest: wrapsDigest(wraps), needs_rotate: [] }, signerOf(by)), wraps);
    if (res.status === 201) {
      this.vk.set(epoch, vk);
      this.needles.add('keys', vk);
    }
    return res;
  }
}
