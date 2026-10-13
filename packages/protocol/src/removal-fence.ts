/**
 * Records by removed authors and the signed removal fence (spec §5, §6).
 *
 * The change feed returns every record ever accepted, including records by
 * devices that were removed later. A removed device keeps its signing key and
 * the vault keys it held, so with a colluding server it could keep appending
 * validly signed records. Every `device_remove` and `member_remove` therefore
 * carries a signed `log_fence`: the change-log head (`log_seq`) its author had
 * verified, gap-free, when it removed the device. Change-log positions start at 1
 * and are contiguous, so every position at or below the fence was already
 * filled when the fence was signed.
 *
 * The fence binds a position, not the log contents. It refuses a removed
 * author's record above the fence; a client that holds its own copy of the
 * positions at or below the fence detects a substituted one, but a device that
 * first reads them later (a new or recovered device) trusts the server for them.
 *
 * A record by a removed device D at key epoch <= the epoch current at that
 * removal is accepted only at a `log_seq` not above that removal's fence.
 * Writes are refused between a removal and the following rekey, so every
 * legitimate later write, including one by a re-added device ID, uses a newer
 * key epoch and is unaffected.
 */
import { fail } from './errors.js';
import type { MembershipState } from './membership-types.js';
import { parseRecord, type SignedRecord } from './records.js';
import { SIGN_CONTEXT, verifyObject } from './signing.js';
import { asInt } from './validate.js';

/**
 * Verify a record read from the change log at position `logSeq` against verified
 * membership, for current and removed authors alike. Order: record parses
 * (bad_request / unsupported_version); same vault (bad_request); `logSeq` is an
 * integer >= 1 (bad_request); the author is a current device, or a removed
 * device whose record `key_epoch` is not newer than the epoch current at its
 * last removal, else forbidden; signature under the author's key
 * (invalid_signature); for every removal of the author whose epoch is >= the
 * record's `key_epoch`, a `logSeq` above that removal's `log_fence` is forbidden.
 */
export function verifyLoggedRecord(value: unknown, state: MembershipState, logSeq: number): SignedRecord {
  const record = parseRecord(value);
  if (record.vault_id !== state.vault_id) fail('bad_request', 'record belongs to another vault');
  asInt(logSeq, 'log_seq', 1);
  const removals = state.removals.filter((r) => r.device_id === record.author);
  const current = state.devices.find((d) => d.device_id === record.author);
  let signPub: string;
  if (current) {
    signPub = current.sign_pub;
  } else {
    const last = removals[removals.length - 1];
    if (!last) fail('forbidden', 'record author was never a member device');
    if (record.key_epoch > last.key_epoch) fail('forbidden', 'record key epoch is newer than its removed author could hold');
    signPub = last.sign_pub;
  }
  verifyObject(SIGN_CONTEXT.record, record, signPub);
  for (const removal of removals) {
    if (record.key_epoch <= removal.key_epoch && logSeq > removal.log_fence) {
      fail('forbidden', 'record by a removed author is ordered after its removal fence');
    }
  }
  return record;
}
