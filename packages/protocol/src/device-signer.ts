/**
 * Async device-key operations for holders whose private keys never leave a
 * key store (the browser dashboard keeps non-extractable WebCrypto keys).
 * Each function produces exactly the bytes of its synchronous counterpart:
 * Ed25519 is deterministic and the X25519 shared secret is the same value.
 */
import { b64decode, b64encode } from './base64url.js';
import { isAllZero } from './bytes.js';
import { fail } from './errors.js';
import { encodeProofHeader, proofObject, type BuildProofArgs } from './proof.js';
import { parseRecord, type SignedRecord, type UnsignedRecord } from './records.js';
import { SIGN_CONTEXT, signingInput } from './signing.js';
import { openWrapWithShared, parseX25519Wrap } from './wrap-x25519.js';

/** An Ed25519 device signing key held elsewhere. */
export interface DeviceSigner {
  /** Return the 64-byte RFC 8032 signature of `message`. */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** An X25519 device exchange key held elsewhere. */
export interface DeviceKx {
  /** 32-byte X25519 public key. */
  readonly kxPub: Uint8Array;
  /** Return the raw 32-byte X25519 shared secret with `peerPublic`. */
  deriveShared(peerPublic: Uint8Array): Promise<Uint8Array>;
}

function isOperationError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { name?: unknown }).name === 'OperationError';
}

async function signB64(signer: DeviceSigner, context: string, obj: object): Promise<string> {
  const sig = await signer.sign(signingInput(context, obj));
  if (!(sig instanceof Uint8Array) || sig.length !== 64) fail('bad_request', 'signer returned a malformed signature');
  return b64encode(sig);
}

/** `signObject` with an external signer. */
export async function signObjectAsync<T extends object>(context: string, obj: T, signer: DeviceSigner): Promise<T & { sig: string }> {
  return { ...obj, sig: await signB64(signer, context, obj) };
}

/** `signRecord` with an external signer. */
export async function signRecordAsync(fields: UnsignedRecord, signer: DeviceSigner): Promise<SignedRecord> {
  return parseRecord(await signObjectAsync(SIGN_CONTEXT.record, { v: 1 as const, ...fields }, signer));
}

/** `buildProof` with an external signer (same proof object and header format). */
export async function buildProofAsync(args: Omit<BuildProofArgs, 'secretKey'>, signer: DeviceSigner): Promise<string> {
  const proof = proofObject(args);
  return encodeProofHeader(proof, await signB64(signer, SIGN_CONTEXT.proof, proof));
}

/** `unwrapFromDevice` with an external exchange key. Throws `decrypt_failed` on a wrong key or tampering. */
export async function unwrapFromDeviceAsync(args: { wrap: unknown; vaultId: string; deviceId: string; kx: DeviceKx }): Promise<Uint8Array> {
  const wrap = parseX25519Wrap(args.wrap);
  if (wrap.rcpt !== args.deviceId) fail('forbidden', 'wrap is addressed to a different device');
  let shared: Uint8Array;
  try {
    shared = await args.kx.deriveShared(b64decode(wrap.epk));
  } catch (err) {
    // WebCrypto refuses a low-order point (the all-zero case) with OperationError.
    // Anything else (key store, permission, a protocol error) propagates as is.
    if (isOperationError(err)) return fail('bad_request', 'X25519 produced an all-zero shared secret');
    throw err;
  }
  if (!(shared instanceof Uint8Array) || shared.length !== 32 || isAllZero(shared)) fail('bad_request', 'X25519 produced an all-zero shared secret');
  if (!(args.kx.kxPub instanceof Uint8Array) || args.kx.kxPub.length !== 32) fail('bad_request', 'kx_pub must be 32 bytes');
  return openWrapWithShared(wrap, shared, args.kx.kxPub, args.vaultId);
}
