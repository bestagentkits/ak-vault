/**
 * Signed wrap sets (spec §4, §11). Every stored wrap belongs to the set uploaded
 * with one owner-signed event (genesis, device_add, member_add or rekey) and was
 * checked against that event's `wraps_digest` (`verifyDeviceWraps` /
 * `verifyRekeyWraps`) in the same transaction that appended the event. No wrap
 * outside a signed set is accepted, so the server cannot inject a recipient or
 * substitute a key. A set is immutable because its event is.
 */
import { cjson, type MembershipState, type X25519Wrap } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';

/**
 * Store the verified wrap set of the event at `membershipSeq`. `quota_exceeded`
 * past `wraps_per_vault` unless `exempt` (a rekey that clears `rekey_required`, or
 * a recovery enrollment; see limits.ts).
 */
export function storeWrapSet(sql: SqlStorage, membershipSeq: number, wraps: readonly X25519Wrap[], exempt = false): number {
  if (wraps.length === 0) return 0;
  if (!exempt) {
    const stored = sql.exec<{ n: number }>('SELECT COUNT(*) AS n FROM wrap_sets').one().n;
    if (stored + wraps.length > LIMITS.wraps_per_vault) throw new ApiError('quota_exceeded', { status: 403 });
  }
  for (const wrap of wraps) {
    sql.exec('INSERT INTO wrap_sets (membership_seq, rcpt, key_epoch, wrap_json) VALUES (?, ?, ?, ?)', membershipSeq, wrap.rcpt, wrap.key_epoch, cjson(wrap));
  }
  return wraps.length;
}

/**
 * The whole set uploaded with the event at `membershipSeq`, exactly as signed:
 * no current-device filter, so a client can recompute `wraps_digest` even after
 * some recipients were removed. Null when that event carries no set.
 */
export function wrapSet(sql: SqlStorage, membershipSeq: number): unknown[] | null {
  const rows = sql
    .exec<{ wrap_json: string }>('SELECT wrap_json FROM wrap_sets WHERE membership_seq = ? ORDER BY rcpt, key_epoch', membershipSeq)
    .toArray()
    .map((r) => JSON.parse(r.wrap_json) as unknown);
  return rows.length > 0 ? rows : null;
}

/**
 * Wraps of current devices, optionally filtered by epoch and recipient (in SQL);
 * each names the event whose signed set holds it, so the client fetches that set
 * with `wrapSet` and checks it against the event before unwrapping.
 */
export function listWraps(sql: SqlStorage, state: MembershipState, filter: { keyEpoch?: number; rcpt?: string }): { membership_seq: number; wrap: unknown }[] {
  const current = new Set(state.devices.map((d) => d.device_id));
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (filter.keyEpoch !== undefined) {
    where.push('key_epoch = ?');
    args.push(filter.keyEpoch);
  }
  if (filter.rcpt !== undefined) {
    where.push('rcpt = ?');
    args.push(filter.rcpt);
  }
  const clause = where.length > 0 ? `WHERE ${where.join(' AND ')} ` : '';
  return sql
    .exec<{ rcpt: string; membership_seq: number; wrap_json: string }>(`SELECT rcpt, membership_seq, wrap_json FROM wrap_sets ${clause}ORDER BY membership_seq, rcpt, key_epoch`, ...args)
    .toArray()
    .filter((r) => current.has(r.rcpt))
    .map((r) => ({ membership_seq: r.membership_seq, wrap: JSON.parse(r.wrap_json) as unknown }));
}
