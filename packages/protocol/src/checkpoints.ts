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
 * This compares the two checkpoints only. It accepts a vault that was restored
 * to an earlier point and then grown past `witnessed.log_seq` with different
 * contents, because the digests are compared only at an equal `log_seq`.
 * Callers MUST also run {@link checkWitnessedHistory} on the history they
 * replayed (spec §5 and §6).
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

/** The change-log head and state digest a client computed at every position it replayed, indexed by `log_seq` (0 is the empty log). */
export interface ReplayedHistory {
  heads: readonly string[];
  digests: readonly string[];
}

/**
 * Throws `rollback` unless the replayed history still holds, at the witnessed
 * `log_seq`, the state digest of `witnessed` and the change-log head
 * (`witnessedLogHead`) the client recorded with it. This is the half of the §6
 * check that {@link checkRollback} cannot make: it refuses a restored log that
 * has since grown past the witnessed position with different contents.
 */
export function checkWitnessedHistory(witnessed: CheckpointView, witnessedLogHead: string, history: ReplayedHistory): void {
  const at = witnessed.log_seq;
  if (!Number.isSafeInteger(at) || at < 0) fail('rollback', 'witnessed log_seq is not a position');
  if (history.heads.length <= at || history.digests.length <= at) fail('rollback', 'history is shorter than the witnessed checkpoint');
  if (history.digests[at] !== witnessed.state_digest) fail('rollback', 'state at the witnessed position differs from the witnessed checkpoint');
  if (history.heads[at] !== witnessedLogHead) fail('rollback', 'change-log head at the witnessed position differs from the witnessed head');
}
