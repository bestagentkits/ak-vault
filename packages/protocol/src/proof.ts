/**
 * Transport proof of possession (spec §9.2):
 *   AKV-Proof: b64(cjson(proof)) "." b64(sig)
 *   proof = {htm, htu, ts, jti, ath: b64 sha256(token), bh: b64 sha256(body)}
 * signed with context `akv1/proof` by the device whose device_id == token `did`.
 */
import { b64decode, b64encode, sha256b64 } from './base64url.js';
import { randomBytes, utf8Encode } from './bytes.js';
import { cjson, cjsonParse } from './canonical-json.js';
import { AkvError, fail } from './errors.js';
import { SIGN_CONTEXT, signDetached, verifyDetached } from './signing.js';
import { asB64, asId, asInt, asObject, asString, exactKeys } from './validate.js';

export interface TransportProof {
  htm: string;
  htu: string;
  ts: number;
  jti: string;
  ath: string;
  bh: string;
}

export const PROOF_MAX_SKEW_MS = 60_000;
export const PROOF_JTI_TTL_MS = 120_000;
const MAX_HEADER = 4096;
const HTM_PATTERN = /^[A-Z]{1,16}$/;

export interface BuildProofArgs {
  htm: string;
  htu: string;
  ts: number;
  token: string;
  body: Uint8Array;
  secretKey: Uint8Array;
  /** Inject a fixed jti (test vectors only); random 16 bytes otherwise. */
  jti?: string;
}

/** The validated proof object `buildProof` signs. */
export function proofObject(args: Omit<BuildProofArgs, 'secretKey'>): TransportProof {
  return parseProofObject({
    htm: args.htm,
    htu: args.htu,
    ts: args.ts,
    jti: args.jti ?? b64encode(randomBytes(16)),
    ath: sha256b64(utf8Encode(args.token)),
    bh: sha256b64(args.body),
  });
}

/** Header value from a proof object and its b64 signature. */
export function encodeProofHeader(proof: TransportProof, sig: string): string {
  return `${b64encode(utf8Encode(cjson(proof)))}.${sig}`;
}

export function buildProof(args: BuildProofArgs): string {
  const proof = proofObject(args);
  return encodeProofHeader(proof, signDetached(SIGN_CONTEXT.proof, proof, args.secretKey));
}

function parseProofObject(value: unknown): TransportProof {
  const obj = asObject(value, 'proof');
  exactKeys(obj, ['htm', 'htu', 'ts', 'jti', 'ath', 'bh'], 'proof');
  const htm = asString(obj['htm'], 'proof.htm', 16, 1);
  if (!HTM_PATTERN.test(htm)) fail('bad_request', 'proof.htm must be an uppercase method');
  return {
    htm,
    htu: asString(obj['htu'], 'proof.htu', 2048, 1),
    ts: asInt(obj['ts'], 'proof.ts'),
    jti: asId(obj['jti'], 'proof.jti'),
    ath: asB64(obj['ath'], 'proof.ath', 32),
    bh: asB64(obj['bh'], 'proof.bh', 32),
  };
}

/** Decode the header without verifying it. Malformed input is `unauthorized`. */
export function decodeProof(header: string): { proof: TransportProof; sig: string } {
  try {
    if (typeof header !== 'string' || header.length > MAX_HEADER) fail('bad_request', 'proof header too long');
    const parts = header.split('.');
    if (parts.length !== 2) fail('bad_request', 'proof header must have two parts');
    const proof = parseProofObject(cjsonParse(b64decode(parts[0]!)));
    return { proof, sig: asB64(parts[1], 'proof sig', 64) };
  } catch (err) {
    if (err instanceof AkvError) fail('unauthorized', 'malformed proof');
    throw err;
  }
}

export interface VerifyProofOptions {
  htm: string;
  htu: string;
  token: string;
  body: Uint8Array;
  /** Current time, unix ms. */
  now: number;
  /** Ed25519 public key of the device named by the token `did`. */
  signPub: string | Uint8Array;
  maxSkewMs?: number;
  /** Return true if this jti was already used by the device within its TTL. */
  isReplay?: (jti: string) => boolean;
}

/**
 * Verify a proof header. Bad signature is `invalid_signature`; everything else
 * (malformed, wrong htm/htu, outside the ±60 s window, wrong ath/bh, replayed jti)
 * is `unauthorized`.
 */
export function verifyProof(header: string, opts: VerifyProofOptions): TransportProof {
  const { proof, sig } = decodeProof(header);
  if (!verifyDetached(SIGN_CONTEXT.proof, proof, sig, opts.signPub)) fail('invalid_signature', 'proof signature verification failed');
  if (proof.htm !== opts.htm) fail('unauthorized', 'proof htm mismatch');
  if (proof.htu !== opts.htu) fail('unauthorized', 'proof htu mismatch');
  if (Math.abs(opts.now - proof.ts) > (opts.maxSkewMs ?? PROOF_MAX_SKEW_MS)) fail('unauthorized', 'proof outside the time window');
  if (proof.ath !== sha256b64(utf8Encode(opts.token))) fail('unauthorized', 'proof is not bound to this token');
  if (proof.bh !== sha256b64(opts.body)) fail('unauthorized', 'proof is not bound to this body');
  if (opts.isReplay?.(proof.jti)) fail('unauthorized', 'proof jti replayed');
  return proof;
}
