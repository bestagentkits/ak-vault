/**
 * Device key wraps (spec §4, §11): recipient validation ("injected recipient")
 * and the signed wrap sets. Every wrap a client may use belongs to the set of
 * one owner-signed event whose body commits to it with `wraps_digest`: the
 * event that added the device (genesis, device_add, member_add) or a rekey.
 */
import { sha256b64 } from './base64url.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import { parseDevice, parseMembershipEvent, type DeviceRecord, type MembershipEvent, type MembershipState } from './membership-types.js';
import { membershipEventHash } from './membership-log.js';
import { parseX25519Wrap, type X25519Wrap } from './wrap-x25519.js';
import { asArray, asInt } from './validate.js';

export interface ValidateWrapsOptions {
  /** Only accept wraps for exactly this epoch (e.g. the wrap set of a rekey). */
  keyEpoch?: number;
  /** Require a wrap for every current device at `keyEpoch` (default false). */
  requireAll?: boolean;
}

/**
 * Validate untrusted wraps against verified membership. Rejects (code):
 * malformed wraps (bad_request / unsupported_version), a recipient that is not a
 * current member device (forbidden), an epoch outside 1..state.key_epoch or not
 * equal to `opts.keyEpoch` (bad_request), duplicate (rcpt, key_epoch) pairs
 * (bad_request), missing recipients when `requireAll` (bad_request).
 */
export function validateWrapRecipients(state: MembershipState, wraps: readonly unknown[], opts: ValidateWrapsOptions = {}): X25519Wrap[] {
  const current = new Set(state.devices.map((d) => d.device_id));
  const seen = new Set<string>();
  const parsed = asArray(wraps, 'wraps', 100_000).map((w, i) => parseX25519Wrap(w, `wraps[${i}]`));
  for (const wrap of parsed) {
    if (!current.has(wrap.rcpt)) fail('forbidden', 'wrap recipient is not a current member device');
    if (wrap.key_epoch > state.key_epoch) fail('bad_request', 'wrap key_epoch is ahead of the membership state');
    if (opts.keyEpoch !== undefined && wrap.key_epoch !== opts.keyEpoch) fail('bad_request', 'wrap key_epoch mismatch');
    const key = `${wrap.rcpt}/${wrap.key_epoch}`;
    if (seen.has(key)) fail('bad_request', 'duplicate wrap for a recipient and epoch');
    seen.add(key);
  }
  if (opts.requireAll) {
    const epoch = opts.keyEpoch ?? state.key_epoch;
    for (const id of current) if (!seen.has(`${id}/${epoch}`)) fail('bad_request', 'a current device has no wrap');
  }
  return parsed;
}

/**
 * `wraps_digest` = b64 sha256(cjson(wraps sorted by rcpt byte order, then key_epoch)).
 * A rekey set has one epoch, so it is sorted by rcpt alone.
 */
export function wrapsDigest(wraps: readonly X25519Wrap[]): string {
  const sorted = [...wraps].sort((a, b) => (a.rcpt < b.rcpt ? -1 : a.rcpt > b.rcpt ? 1 : a.key_epoch - b.key_epoch));
  return sha256b64(cjsonBytes(sorted));
}

/** Devices an event adds: genesis and member_add `devices`, device_add `device`; [] for every other type. */
export function addedDevices(event: MembershipEvent): DeviceRecord[] {
  const what = `${event.type}.body`;
  if (event.type === 'device_add') return [parseDevice(event.body['device'], `${what}.device`)];
  if (event.type === 'genesis' || event.type === 'member_add') {
    return asArray(event.body['devices'], `${what}.devices`, 64).map((d, i) => parseDevice(d, `${what}.devices[${i}]`));
  }
  return [];
}

/**
 * Check the wraps delivered with a device-adding event (genesis, device_add,
 * member_add) against its signed `wraps_digest` (spec §4, §11). The event must
 * come from a verified chain (its signature is not re-checked here). A device
 * MUST NOT use a vault key from a wrap that has not passed this check or
 * {@link verifyRekeyWraps}.
 *
 * Order: the event adds devices (bad_request); wraps parse (bad_request /
 * unsupported_version); every rcpt is a device the event adds (forbidden); key
 * epochs lie in 1..event.key_epoch and (rcpt, key_epoch) pairs are unique
 * (bad_request); completeness (bad_request): a recovery-authored device_add
 * (`sas` "", which replay allows only for the recovery author) carries at least
 * one wrap, because the recovery bundle may predate later rekeys; every other
 * event carries a wrap at event.key_epoch for every added device. Older epochs
 * are optional: content the joiner cannot read is rotated forward, never
 * delivered by a later unsigned wrap. Finally
 * wrapsDigest(wraps) === body.wraps_digest (bad_request). Input order does not matter.
 */
export function verifyDeviceWraps(event: unknown, wraps: readonly unknown[]): X25519Wrap[] {
  const ev = parseMembershipEvent(event, 'membership event');
  const devices = addedDevices(ev);
  if (devices.length === 0) fail('bad_request', 'event does not add devices');
  const added = new Set(devices.map((d) => d.device_id));
  const parsed = asArray(wraps, 'wraps', 100_000).map((w, i) => parseX25519Wrap(w, `wraps[${i}]`));
  const seen = new Set<string>();
  for (const w of parsed) {
    if (!added.has(w.rcpt)) fail('forbidden', 'wrap recipient is not a device added by the event');
    if (w.key_epoch > ev.key_epoch) fail('bad_request', 'wrap key_epoch is ahead of the event');
    const key = `${w.rcpt}/${w.key_epoch}`;
    if (seen.has(key)) fail('bad_request', 'duplicate wrap for a recipient and epoch');
    seen.add(key);
  }
  const byRecovery = ev.type === 'device_add' && ev.body['sas'] === '';
  const complete = byRecovery ? parsed.length > 0 : [...added].every((id) => seen.has(`${id}/${ev.key_epoch}`));
  if (!complete) fail('bad_request', 'wrap set is incomplete');
  if (wrapsDigest(parsed) !== ev.body['wraps_digest']) fail('bad_request', 'wrap set does not match the signed wraps_digest');
  return parsed;
}

export interface VerifyRekeyWrapsOptions {
  /**
   * Verified membership state immediately after the rekey event (state.seq ===
   * event.seq and state.head === hash(event)). When given, every wrap recipient
   * must be a current device and every current device must have a wrap.
   */
  state?: MembershipState;
}

/**
 * Check a wrap set against a `rekey` event's signed `wraps_digest` (spec §4, §11).
 * The event must come from a verified chain (its signature is not re-checked here).
 * Order: event is a rekey (bad_request); wraps parse (bad_request /
 * unsupported_version); every wrap has key_epoch = new_key_epoch, no duplicate rcpt
 * (bad_request); if `state`: state is at the event (bad_request), recipients are
 * current devices (forbidden), all present (bad_request); finally
 * wrapsDigest(wraps) === body.wraps_digest (bad_request).
 */
export function verifyRekeyWraps(event: unknown, wraps: readonly unknown[], opts: VerifyRekeyWrapsOptions = {}): X25519Wrap[] {
  const ev = parseMembershipEvent(event, 'rekey event');
  if (ev.type !== 'rekey') fail('bad_request', 'event is not a rekey');
  const epoch = asInt(ev.body['new_key_epoch'], 'rekey.body.new_key_epoch', 1);
  const parsed = asArray(wraps, 'wraps', 100_000).map((w, i) => parseX25519Wrap(w, `wraps[${i}]`));
  const rcpts = new Set<string>();
  for (const w of parsed) {
    if (w.key_epoch !== epoch) fail('bad_request', 'wrap key_epoch differs from new_key_epoch');
    if (rcpts.has(w.rcpt)) fail('bad_request', 'duplicate wrap recipient');
    rcpts.add(w.rcpt);
  }
  if (opts.state) {
    if (opts.state.seq !== ev.seq || opts.state.head !== membershipEventHash(ev)) fail('bad_request', 'membership state is not at the rekey event');
    validateWrapRecipients(opts.state, parsed, { keyEpoch: epoch, requireAll: true });
  }
  if (wrapsDigest(parsed) !== ev.body['wraps_digest']) fail('bad_request', 'wrap set does not match the signed wraps_digest');
  return parsed;
}
