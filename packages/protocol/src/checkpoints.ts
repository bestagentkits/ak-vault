/** Signed checkpoints and the anti-rollback / fork check (spec §6). */
import { fail } from './errors.js';
import type { MembershipState } from './membership-types.js';
import { SIGN_CONTEXT, signObject, verifyObject } from './signing.js';
import { asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface Checkpoint {
  v: 1;
  vault_id: string;
  membership_seq: number;
  membership_head: string;
  log_seq: number;
  state_digest: string;
  key_epoch: number;
  ts: number;
  author: string;
  sig: string;
}

export type UnsignedCheckpoint = Omit<Checkpoint, 'v' | 'sig'>;

/** The comparable part of a checkpoint (a pulled state can be expressed as one). */
export type CheckpointView = Pick<Checkpoint, 'vault_id' | 'membership_seq' | 'membership_head' | 'log_seq' | 'state_digest' | 'key_epoch'>;

export function signCheckpoint(fields: UnsignedCheckpoint, secretKey: Uint8Array): Checkpoint {
  return signObject(SIGN_CONTEXT.checkpoint, { v: 1 as const, ...fields }, secretKey);
}

export function parseCheckpoint(value: unknown, what = 'checkpoint'): Checkpoint {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'membership_seq', 'membership_head', 'log_seq', 'state_digest', 'key_epoch', 'ts', 'author', 'sig'], what);
  return {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    membership_seq: asInt(obj['membership_seq'], `${what}.membership_seq`),
    membership_head: asB64(obj['membership_head'], `${what}.membership_head`, 32),
    log_seq: asInt(obj['log_seq'], `${what}.log_seq`),
    state_digest: asB64(obj['state_digest'], `${what}.state_digest`, 32),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    ts: asInt(obj['ts'], `${what}.ts`),
    author: asId(obj['author'], `${what}.author`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}

/**
 * Verify a checkpoint signed by any current member device of `state`
 * (`forbidden` for unknown authors, `invalid_signature` for bad signatures).
 */
export function verifyCheckpoint(value: unknown, state: MembershipState): Checkpoint {
  const cp = parseCheckpoint(value);
  if (cp.vault_id !== state.vault_id) fail('bad_request', 'checkpoint belongs to another vault');
  const device = state.devices.find((d) => d.device_id === cp.author);
  if (!device) fail('forbidden', 'checkpoint author is not a current device');
  verifyObject(SIGN_CONTEXT.checkpoint, cp, device.sign_pub);
  return cp;
}

/**
 * Throws `rollback` if `incoming` is older than or forked from `witnessed`:
 * lower membership_seq, same membership_seq with a different head, lower
 * log_seq, same log_seq with a different state_digest, or lower key_epoch.
 *
 * This compares checkpoints only, so it is not the whole §6 check: a log
 * restored below `witnessed.log_seq` and regrown past it passes. Callers MUST
 * also replay the log with `verifyChangeLog` passing the head they kept at
 * `witnessed.log_seq` in `keptHeads`, and, for a peer's checkpoint (which
 * carries no head), compare the state digest they computed at that position.
 */
export function checkRollback(witnessed: CheckpointView, incoming: CheckpointView): void {
  if (witnessed.vault_id !== incoming.vault_id) fail('bad_request', 'checkpoint belongs to another vault');
  if (incoming.membership_seq < witnessed.membership_seq) fail('rollback', 'membership head is behind the witnessed checkpoint');
  if (incoming.membership_seq === witnessed.membership_seq && incoming.membership_head !== witnessed.membership_head) {
    fail('rollback', 'membership head forks from the witnessed checkpoint');
  }
  if (incoming.log_seq < witnessed.log_seq) fail('rollback', 'log_seq is behind the witnessed checkpoint');
  if (incoming.log_seq === witnessed.log_seq && incoming.state_digest !== witnessed.state_digest) {
    fail('rollback', 'state forks from the witnessed checkpoint');
  }
  if (incoming.key_epoch < witnessed.key_epoch) fail('rollback', 'key_epoch is behind the witnessed checkpoint');
}
