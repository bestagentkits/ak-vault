/**
 * Per-connection state and checks of the device relay (spec §9.7): close codes,
 * the hibernation attachment that survives eviction, the session rules shared by
 * the upgrade and `reauth`, and proof verification with a single-use `jti`.
 * Nothing here holds a token beyond the check that uses it.
 */
import { b64decodeLength, deviceIdFromSignPub, isAkvError, utf8Encode, verifyProof } from '@ak-vault/protocol';
import type { VerifiedClaims } from '../auth/jwt-verify.js';
import { LIMITS } from '../limits.js';

export const CLOSE = {
  badFrame: 4400,
  unauthorized: 4401,
  forbidden: 4403,
  replaced: 4409,
  tooFast: 4429,
  internal: 1011,
} as const;
export type CloseCode = (typeof CLOSE)[keyof typeof CLOSE];

/** Fixed close reasons: they carry nothing from the connection. */
export const CLOSE_REASON: Record<CloseCode, string> = {
  4400: 'bad frame',
  4401: 'token expired or revoked',
  4403: 'not a member or wrong device kind',
  4409: 'replaced by a newer connection',
  4429: 'too many frames',
  1011: 'internal error',
};

/**
 * Hibernation attachment of one device connection (at most 2 KiB serialized:
 * bounded claims, at most 16 vault IDs and 7 tool names).
 */
export interface Connection {
  /** Random per connection; calls are bound to it, so a replaced connection's results never match. */
  cid: string;
  sub: string;
  did: string;
  signPub: string;
  /** Token in force: `sid`, `iat`, `exp` (unix s) for per-call revocation and expiry. */
  sid: string;
  iat: number;
  exp: number;
  /** The exact relay URL the proofs sign as `htu`. */
  htu: string;
  connectedAt: number;
  /** `none` until `hello` arrives, `pending` while it is checked, `ready` once answered. */
  hello: 'none' | 'pending' | 'ready';
  helloAt: number;
  vaults: string[];
  tools: string[];
  /** `reauth` frames in the current window and the window's end (unix ms). */
  reauths: number;
  reauthWindowEnd: number;
  /** Consecutive result frames that matched no outstanding call. */
  unsolicited: number;
}

/** Verified upgrade facts the Worker hands to the relay object (internal header, never client-supplied). */
export interface RelayOpen {
  sub: string;
  did: string;
  sid: string;
  iat: number;
  exp: number;
  signPub: string;
  token: string;
  proof: string;
  htu: string;
}

export const RELAY_OPEN_HEADER = 'X-AKV-Relay-Open';

export function encodeRelayOpen(open: RelayOpen): string {
  return JSON.stringify(open);
}

/** Parse the internal header; null when absent or malformed (the object then refuses). */
export function decodeRelayOpen(value: string | null): RelayOpen | null {
  if (!value) return null;
  try {
    const o = JSON.parse(value) as Partial<RelayOpen>;
    const strings = [o.sub, o.did, o.sid, o.signPub, o.token, o.proof, o.htu];
    if (!strings.every((s) => typeof s === 'string' && s.length > 0)) return null;
    if (!Number.isSafeInteger(o.iat) || !Number.isSafeInteger(o.exp)) return null;
    return o as RelayOpen;
  } catch {
    return null;
  }
}

/** Why a sync token may not hold a relay connection, or null when it may (spec §9.6). */
export function relaySessionRefusal(claims: VerifiedClaims): 'kind' | 'scope' | null {
  if (claims.kind === 'machine' || claims.kind === 'browser') return 'kind';
  if (!claims.scope.includes('vault:read') || !claims.scope.includes('vault:write')) return 'scope';
  return null;
}

/** Whether `signPub` is a 32-byte key whose `kid` is `did` (the `AKV-Device-Key` binding). */
export function deviceKeyMatches(signPub: string | null, did: string): signPub is string {
  if (!signPub) return false;
  try {
    b64decodeLength(signPub, 32);
    return deviceIdFromSignPub(signPub) === did;
  } catch {
    return false;
  }
}

const EMPTY = new Uint8Array();

/**
 * Verify a relay proof (htm `GET`, htu the relay URL, `ath` of `token`, `bh` of
 * the empty body) against `signPub` and burn its `jti` for the device. False on
 * any failure.
 */
export function verifyRelayProof(sql: SqlStorage, args: { proof: string; token: string; htu: string; did: string; signPub: string; nowMs: number }): boolean {
  sql.exec('DELETE FROM proof_jti WHERE expires_at < ?', args.nowMs);
  try {
    const proof = verifyProof(args.proof, {
      htm: 'GET',
      htu: args.htu,
      token: args.token,
      body: EMPTY,
      now: args.nowMs,
      signPub: args.signPub,
      maxSkewMs: LIMITS.clock_skew_seconds * 1000,
      isReplay: (jti) => sql.exec('SELECT 1 FROM proof_jti WHERE did = ? AND jti = ?', args.did, jti).toArray().length > 0,
    });
    sql.exec('INSERT INTO proof_jti (did, jti, expires_at) VALUES (?, ?, ?)', args.did, proof.jti, args.nowMs + LIMITS.proof_jti_ttl_seconds * 1000);
    return true;
  } catch (err) {
    if (isAkvError(err)) return false;
    throw err;
  }
}

/** UTF-8 size of a frame about to be sent. */
export function frameBytes(text: string): number {
  return utf8Encode(text).length;
}
