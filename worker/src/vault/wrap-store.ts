/**
 * Device key wraps (spec §3.3, §4). Every upload is validated against verified
 * membership with `validateWrapRecipients`, so a wrap to a device that no
 * owner-signed event added (injected recipient) is refused. Stored wraps are
 * immutable per (recipient, key_epoch); reads return wraps of current devices only.
 */
import { cjson, validateWrapRecipients, type MembershipState, type ValidateWrapsOptions, type X25519Wrap } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { requireArray } from './request-body.js';

export function validateWraps(state: MembershipState, raw: unknown, opts: ValidateWrapsOptions = {}): X25519Wrap[] {
  return validateWrapRecipients(state, requireArray(raw, LIMITS.wraps_per_request), opts);
}

/** Store wraps; an identical re-upload is a no-op, a different wrap for the same slot is `conflict`. */
export function storeWraps(sql: SqlStorage, wraps: readonly X25519Wrap[], membershipSeq: number): number {
  let stored = 0;
  for (const wrap of wraps) {
    const json = cjson(wrap);
    const existing = sql.exec<{ wrap_json: string }>('SELECT wrap_json FROM wraps WHERE rcpt = ? AND key_epoch = ?', wrap.rcpt, wrap.key_epoch).toArray()[0];
    if (existing) {
      if (existing.wrap_json !== json) throw new ApiError('conflict', { message: 'a different wrap exists for this recipient and epoch' });
      continue;
    }
    sql.exec('INSERT INTO wraps (rcpt, key_epoch, membership_seq, wrap_json) VALUES (?, ?, ?, ?)', wrap.rcpt, wrap.key_epoch, membershipSeq, json);
    stored++;
  }
  return stored;
}

/** Wraps for current devices, optionally filtered by epoch and recipient. `membership_seq` marks the upload's membership head. */
export function listWraps(sql: SqlStorage, state: MembershipState, filter: { keyEpoch?: number; rcpt?: string }): { membership_seq: number; wrap: unknown }[] {
  const current = new Set(state.devices.map((d) => d.device_id));
  return sql
    .exec<{ rcpt: string; key_epoch: number; membership_seq: number; wrap_json: string }>('SELECT rcpt, key_epoch, membership_seq, wrap_json FROM wraps ORDER BY key_epoch, rcpt')
    .toArray()
    .filter((r) => current.has(r.rcpt) && (filter.keyEpoch === undefined || r.key_epoch === filter.keyEpoch) && (filter.rcpt === undefined || r.rcpt === filter.rcpt))
    .map((r) => ({ membership_seq: r.membership_seq, wrap: JSON.parse(r.wrap_json) as unknown }));
}
