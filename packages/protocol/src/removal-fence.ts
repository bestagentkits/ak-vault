/**
 * History-aware check of change-log records: the signed removal fence and the
 * signed role fence (spec §5, §6).
 *
 * The change feed returns every record ever accepted, including records by
 * devices that were removed or demoted later. A removed device keeps its signing
 * key and the vault keys it held, and a demoted editor stays a reader holding
 * both, so with a colluding server either could keep appending validly signed
 * records. Every `device_remove`, `member_remove` and `role_set` therefore
 * carries a signed `log_fence`: the change-log head (`log_seq`) its author had
 * verified, gap-free, when it signed. Change-log positions start at 1 and are
 * contiguous, so every position at or below the fence was already filled when
 * the fence was signed, and every later record lies above it.
 *
 * This check binds the position: it refuses a removed author's record above
 * its removal fence, and a record whose author, at that position, was not a
 * writer (a `reader`, a `machine` device, or an editor demoted at or below that
 * position). Each fence also signs `log_head`, the change-log head at the fence,
 * which binds the contents of every position at or below it; `verifyChangeLog`
 * (change-log.ts) replays the log and checks that head.
 *
 * A device ID can be removed and added again. Writes are refused between a
 * removal and the following rekey, so a record whose `key_epoch` is at or below
 * the epoch current at a removal belongs to the device as it was up to that
 * removal (its first such removal), and a newer record to the device as it is
 * now. Role changes apply to the device between its previous removal and that
 * one.
 *
 * A legacy `role_set`, signed before role fences existed, carries no fence and
 * is recorded with `log_fence: null`. Its position in the log is unknown, so
 * between the fenced changes around it a record is accepted when its author was
 * a writer under any role it held there: the Worker's check at write time is the
 * only evidence for that span. Refusing instead would make a vault holding such a
 * change fail every full replay, for good.
 */
import { fail } from './errors.js';
import { ROLES, type DeviceKind, type MembershipState, type Role, type RoleChange } from './membership-types.js';
import { mayWrite, parseRecord, type SignedRecord } from './records.js';
import { SIGN_CONTEXT, verifyObject } from './signing.js';
import { asInt } from './validate.js';

/** The device as it was when it wrote a record: signing key, kind, its last role and its role changes. */
interface AuthorTerm {
  signPub: string;
  kind: DeviceKind;
  /** Role at the end of the term (at removal, or now). */
  finalRole: Role;
  /** `role_set` rows of the term, in chain order. */
  changes: RoleChange[];
}

/** Select the term of `author` that wrote a record at `keyEpoch`, or null when no term could have. */
function authorTerm(state: MembershipState, author: string, keyEpoch: number): AuthorTerm | null {
  const removals = state.removals.filter((r) => r.device_id === author);
  const index = removals.findIndex((r) => keyEpoch <= r.key_epoch);
  const after = index === -1 ? removals[removals.length - 1] : removals[index - 1];
  const before = index === -1 ? undefined : removals[index];
  const inTerm = (c: RoleChange) => c.device_id === author && (after === undefined || c.changed_seq > after.removed_seq) && (before === undefined || c.changed_seq < before.removed_seq);
  const changes = state.role_changes.filter(inTerm);
  if (before) return { signPub: before.sign_pub, kind: before.kind, finalRole: before.role, changes };
  const current = state.devices.find((d) => d.device_id === author);
  if (!current) return null;
  return { signPub: current.sign_pub, kind: current.kind, finalRole: current.role, changes };
}

/**
 * Roles the term may have held at change-log position `logSeq`. Let `i` be the
 * first fenced change (chain order) whose `log_fence` is at or above `logSeq`,
 * and `j` the last fenced change before it. The record lies after change `j`
 * and before change `i`, so the author held the role each change in `(j, i]`
 * replaced, plus the final role when there is no `i`. Without legacy (unfenced)
 * changes that is exactly one role; a legacy change has no position, so every
 * role around it is a candidate.
 */
function rolesAt(term: AuthorTerm, logSeq: number): Role[] {
  const { changes } = term;
  const fenced = (c: RoleChange) => c.log_fence !== null;
  const i = changes.findIndex((c) => c.log_fence !== null && logSeq <= c.log_fence);
  const end = i === -1 ? changes.length : i + 1;
  let j = (i === -1 ? changes.length : i) - 1;
  while (j >= 0 && !fenced(changes[j]!)) j--;
  const roles = changes.slice(j + 1, end).map((c) => c.prev_role);
  if (i === -1) roles.push(term.finalRole);
  return roles;
}

/**
 * Verify a record read from the change log at position `logSeq` against verified
 * membership, for current, removed and demoted authors alike. Order: record
 * parses (bad_request / unsupported_version); same vault (bad_request); `logSeq`
 * is an integer >= 1 (bad_request); the record `key_epoch` is not above the
 * state's `key_epoch` (forbidden); the author is a current device, or a removed
 * device whose record `key_epoch` is not newer than the epoch current at its
 * last removal, else forbidden; signature under the author's key
 * (invalid_signature); for every removal of the author whose epoch is >= the
 * record's `key_epoch`, a `logSeq` above that removal's `log_fence` is
 * forbidden; the author's kind is `human` and its role at `logSeq` is `owner`
 * or `editor` (forbidden). A legacy `role_set` signed no fence, so around one
 * any role the author held between the neighbouring fenced changes counts; a
 * role outside the closed set is still refused.
 */
export function verifyLoggedRecord(value: unknown, state: MembershipState, logSeq: number): SignedRecord {
  const record = parseRecord(value);
  if (record.vault_id !== state.vault_id) fail('bad_request', 'record belongs to another vault');
  asInt(logSeq, 'log_seq', 1);
  if (record.key_epoch > state.key_epoch) fail('forbidden', 'record key epoch is newer than the verified membership');
  const term = authorTerm(state, record.author, record.key_epoch);
  if (!term) {
    if (state.removals.some((r) => r.device_id === record.author)) fail('forbidden', 'record key epoch is newer than its removed author could hold');
    fail('forbidden', 'record author was never a member device');
  }
  verifyObject(SIGN_CONTEXT.record, record, term.signPub);
  for (const removal of state.removals) {
    if (removal.device_id === record.author && record.key_epoch <= removal.key_epoch && logSeq > removal.log_fence) {
      fail('forbidden', 'record by a removed author is ordered after its removal fence');
    }
  }
  const roles = rolesAt(term, logSeq);
  // Any role outside the closed set fails closed, also inside a legacy span.
  const known = roles.every((role) => (ROLES as readonly string[]).includes(role));
  if (!known || !roles.some((role) => mayWrite(role, term.kind))) fail('forbidden', 'record author could not write at this log position');
  return record;
}
