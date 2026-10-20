/**
 * Ed25519 signing over domain-separated canonical JSON (spec §2):
 * `signing_input = utf8(context) || 0x0A || cjson(object_without_sig)`.
 * Verification is strict RFC 8032 and identical in every implementation (spec §11):
 * S < L, canonical A and R encodings, no small-order A, and the cofactorless
 * equation `encode([S]B - [k]A) == R` (byte comparison, as in Go's crypto/ed25519).
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { b64decode, b64encode } from './base64url.js';
import { bytesEqual, concatBytes, sha256, utf8Encode } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';

/** Closed set of signing contexts used by protocol v1. */
export const SIGN_CONTEXT = {
  membership: 'akv1/membership',
  record: 'akv1/record',
  checkpoint: 'akv1/checkpoint',
  auditCheckpoint: 'akv1/audit-checkpoint',
  proof: 'akv1/proof',
  sealKey: 'akv1/seal-key',
  relay: 'akv1/relay',
  relayResult: 'akv1/relay-result',
} as const;
export type SignContext = (typeof SIGN_CONTEXT)[keyof typeof SIGN_CONTEXT];

const NEWLINE = new Uint8Array([0x0a]);

/** Build the exact bytes that are signed. A top-level `sig` field is always excluded. */
export function signingInput(context: string, obj: object): Uint8Array {
  if (typeof context !== 'string' || context.length === 0 || context.includes('\n')) fail('bad_request', 'invalid signing context');
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) fail('bad_request', 'signed value must be an object');
  const { sig: _sig, ...rest } = obj as Record<string, unknown>;
  return concatBytes(utf8Encode(context), NEWLINE, cjsonBytes(rest));
}

/** `kid = b64(SHA-256(utf8("akv1/kid") || 0x0A || pubkey)[0:16])`. */
export function kid(publicKey: Uint8Array): string {
  return b64encode(sha256(concatBytes(utf8Encode('akv1/kid'), NEWLINE, publicKey)).subarray(0, 16));
}

/** A device ID is the `kid` of its Ed25519 signing public key (raw bytes or b64). */
export function deviceIdFromSignPub(signPub: Uint8Array | string): string {
  const bytes = typeof signPub === 'string' ? b64decode(signPub) : signPub;
  if (bytes.length !== 32) fail('bad_request', 'sign_pub must be 32 bytes');
  return kid(bytes);
}

export interface KeyPair {
  /** 32-byte secret (Ed25519 seed or X25519 scalar). */
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

function checkSeed(seed: Uint8Array): void {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) fail('bad_request', 'secret key must be 32 bytes');
}

export function signKeyPairFromSeed(seed: Uint8Array): KeyPair {
  checkSeed(seed);
  return { secretKey: seed, publicKey: ed25519.getPublicKey(seed) };
}

export function kxKeyPairFromSecret(secret: Uint8Array): KeyPair {
  checkSeed(secret);
  return { secretKey: secret, publicKey: x25519.getPublicKey(secret) };
}

/** Sign `obj` (minus `sig`) under `context`; returns the b64 signature. */
export function signDetached(context: string, obj: object, secretKey: Uint8Array): string {
  checkSeed(secretKey);
  return b64encode(ed25519.sign(signingInput(context, obj), secretKey));
}

/** Return a copy of `obj` with `sig` set. */
export function signObject<T extends object>(context: string, obj: T, secretKey: Uint8Array): T & { sig: string } {
  return { ...obj, sig: signDetached(context, obj, secretKey) };
}

const ED25519_L = ed25519.Point.Fn.ORDER;

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] as number);
  return n;
}

/**
 * RFC 8032 §5.1.7 without the cofactor: `encode([S]B - [k]A)` must equal the
 * signature's R bytes, k = SHA-512(R || A || M) mod L. Callers have already
 * passed noble's strict checks (S < L, A decodes canonically).
 */
function cofactorlessEquationHolds(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean {
  const r = sig.subarray(0, 32);
  const s = bytesToBigIntLE(sig.subarray(32));
  if (s >= ED25519_L) return false;
  const A = ed25519.Point.fromBytes(pub, false);
  const k = bytesToBigIntLE(sha512(concatBytes(r, pub, msg))) % ED25519_L;
  const expectedR = ed25519.Point.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(k));
  return bytesEqual(expectedR.toBytes(), r);
}

/** Boolean signature check. Malformed signatures or keys return false. */
export function verifyDetached(context: string, obj: object, sig: string, publicKey: Uint8Array | string): boolean {
  try {
    const pub = typeof publicKey === 'string' ? b64decode(publicKey) : publicKey;
    const sigBytes = b64decode(sig);
    if (pub.length !== 32 || sigBytes.length !== 64) return false;
    const msg = signingInput(context, obj);
    // noble strict mode: S < L, canonical A/R encodings, rejects small-order A,
    // cofactored equation. The cofactorless check below additionally rejects
    // torsion components in R or A, which Go's crypto/ed25519 also rejects.
    return ed25519.verify(sigBytes, msg, pub, { zip215: false }) && cofactorlessEquationHolds(sigBytes, msg, pub);
  } catch {
    return false;
  }
}

/** Verify `obj.sig`; throws `invalid_signature` on failure. */
export function verifyObject(context: string, obj: object, publicKey: Uint8Array | string): void {
  const sig = (obj as { sig?: unknown }).sig;
  if (typeof sig !== 'string' || !verifyDetached(context, obj, sig, publicKey)) {
    fail('invalid_signature', `${context}: signature verification failed`);
  }
}
