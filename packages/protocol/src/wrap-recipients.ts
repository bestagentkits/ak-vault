/**
 * Recipient validation for device key wraps (spec §4 "injected recipient").
 * A wrap is acceptable only when its `rcpt` is a current member device of the
 * verified membership state; wraps for older retained epochs (1..key_epoch) are
 * accepted for current members so pre-rekey items stay readable.
 */
import { sha256b64 } from './base64url.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import { parseMembershipEvent, type MembershipState } from './membership-types.js';
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

/** `wraps_digest` = b64 sha256(cjson(wraps sorted by rcpt byte order)) for a rekey's new-epoch wrap list. */
export function wrapsDigest(wraps: readonly X25519Wrap[]): string {
  const sorted = [...wraps].sort((a, b) => (a.rcpt < b.rcpt ? -1 : a.rcpt > b.rcpt ? 1 : 0));
  return sha256b64(cjsonBytes(sorted));
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
