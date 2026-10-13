/**
 * Owner-signed, hash-chained membership log (spec §4): event building/signing
 * and full chain verification from genesis.
 */
import { sha256b64 } from './base64url.js';
import { fail } from './errors.js';
import { ReplayState } from './membership-rules.js';
import {
  parseDevice,
  parseMembershipEvent,
  type MembershipEvent,
  type MembershipEventType,
  type MembershipState,
  type UnsignedMembershipEvent,
  type VerifyChainOptions,
} from './membership-types.js';
import type { JsonObject } from './canonical-json.js';
import { SIGN_CONTEXT, signObject, signingInput, verifyObject } from './signing.js';
import { asArray } from './validate.js';

/** `b64(sha256(signing input))` of an event: the next event's `prev`. */
export function membershipEventHash(event: UnsignedMembershipEvent | MembershipEvent): string {
  return sha256b64(signingInput(SIGN_CONTEXT.membership, event));
}

/** Sign a fully specified event. */
export function signMembershipEvent(event: UnsignedMembershipEvent, secretKey: Uint8Array): MembershipEvent {
  return signObject(SIGN_CONTEXT.membership, event, secretKey);
}

/** Build and sign the genesis event (seq 0, key_epoch 1, prev ''). */
export function buildGenesisEvent(
  args: { vault_id: string; ts: number; author: string; body: JsonObject },
  secretKey: Uint8Array,
): MembershipEvent {
  return signMembershipEvent(
    { v: 1, type: 'genesis', vault_id: args.vault_id, seq: 0, prev: '', membership_epoch: 0, key_epoch: 1, ts: args.ts, author: args.author, body: args.body },
    secretKey,
  );
}

/** Build and sign the event that follows `state` (seq, prev and epochs are filled in). */
export function nextMembershipEvent(
  state: MembershipState,
  args: { type: Exclude<MembershipEventType, 'genesis'>; ts: number; author: string; body: JsonObject },
  secretKey: Uint8Array,
): MembershipEvent {
  const seq = state.seq + 1;
  const keyEpoch = args.type === 'rekey' ? state.key_epoch + 1 : state.key_epoch;
  return signMembershipEvent(
    { v: 1, type: args.type, vault_id: state.vault_id, seq, prev: state.head, membership_epoch: seq, key_epoch: keyEpoch, ts: args.ts, author: args.author, body: args.body },
    secretKey,
  );
}

/**
 * Replay a membership chain from genesis and return the derived state.
 *
 * Rejects (code): unknown `v`/`type` (unsupported_version); malformed fields,
 * non-sequential `seq`, wrong `prev`, `membership_epoch != seq`, key_epoch jumps
 * (bad_request); bad signature (invalid_signature); author not a current human
 * owner device or the recovery key for device_add/device_remove, removed device
 * reappearing, demoting/removing the last owner, member ops in non-shared vaults,
 * untrusted anchor (forbidden); `key_epoch` decreasing, chain shorter than or
 * forked from `witnessedCheckpoint` (rollback).
 */
export function verifyMembershipChain(events: readonly unknown[], opts: VerifyChainOptions = {}): MembershipState {
  const list = asArray(events, 'membership events', 1_000_000);
  if (list.length === 0) fail('bad_request', 'membership chain is empty');
  const replay = new ReplayState();
  const hashes: string[] = [];
  let vaultId = '';
  for (let i = 0; i < list.length; i++) {
    const event = parseMembershipEvent(list[i], `membership event ${i}`);
    if (i === 0) {
      vaultId = event.vault_id;
      if (opts.vaultId !== undefined && opts.vaultId !== vaultId) fail('bad_request', 'membership chain belongs to another vault');
    } else if (event.vault_id !== vaultId) {
      fail('bad_request', 'membership event belongs to another vault');
    }
    if (event.seq !== i) fail('bad_request', 'non-sequential seq');
    if (event.prev !== (i === 0 ? '' : hashes[i - 1])) fail('bad_request', 'wrong prev hash');
    if (event.membership_epoch !== event.seq) fail('bad_request', 'membership_epoch must equal seq');
    if (i === 0) {
      if (event.type !== 'genesis') fail('bad_request', 'chain must start with genesis');
      if (event.key_epoch !== 1) fail('bad_request', 'genesis key_epoch must be 1');
      const author = replay.applyGenesis(event.body, event.author);
      if (opts.trustedAnchor !== undefined && opts.trustedAnchor !== author.sign_pub) fail('forbidden', 'genesis author is not the trusted anchor');
      verifyObject(SIGN_CONTEXT.membership, event, author.sign_pub);
    } else {
      if (event.key_epoch < replay.keyEpoch) fail('rollback', 'key_epoch decreased');
      if (event.type !== 'rekey' && event.key_epoch !== replay.keyEpoch) fail('bad_request', 'key_epoch changes only on rekey');
      verifyObject(SIGN_CONTEXT.membership, event, replay.authorKey(event));
      replay.apply(event);
    }
    hashes.push(membershipEventHash(event));
  }
  const witnessed = opts.witnessedCheckpoint;
  if (witnessed) {
    if (witnessed.vault_id !== undefined && witnessed.vault_id !== vaultId) fail('bad_request', 'checkpoint belongs to another vault');
    if (witnessed.membership_seq >= hashes.length) fail('rollback', 'membership chain is behind the witnessed checkpoint');
    if (hashes[witnessed.membership_seq] !== witnessed.membership_head) fail('rollback', 'membership chain forks from the witnessed checkpoint');
  }
  return replay.snapshot(vaultId, list.length - 1, hashes[hashes.length - 1]!);
}

/** Look up a current device in a verified state. */
export function findDevice(state: MembershipState, deviceId: string) {
  return state.devices.find((d) => d.device_id === deviceId);
}

export { parseDevice };
