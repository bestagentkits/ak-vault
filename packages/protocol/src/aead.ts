/**
 * XChaCha20-Poly1305 envelope (spec §3.1). The AAD is `cjson(aad_object)`; it is
 * never transmitted, the receiver rebuilds it from authenticated context.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { b64decode, b64encode } from './base64url.js';
import { randomBytes } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import { asB64, asObject, checkVersion, exactKeys } from './validate.js';

export const MAX_PLAINTEXT_BYTES = 65_536;
export const NONCE_BYTES = 24;
export const KEY_BYTES = 32;
export const TAG_BYTES = 16;
const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export interface Envelope {
  v: 1;
  alg: 'xc20p';
  kid: string;
  n: string;
  ct: string;
}

export interface SealOptions {
  kid: string;
  /** Inject a fixed nonce (test vectors only). Defaults to 24 random bytes. */
  nonce?: Uint8Array;
}

/** Epoch tag used as the envelope `kid` for vault-key-derived keys: `e<key_epoch>`. */
export function epochTag(keyEpoch: number): string {
  if (!Number.isSafeInteger(keyEpoch) || keyEpoch < 1) fail('bad_request', 'key_epoch must be a positive integer');
  return `e${keyEpoch}`;
}

/** Inverse of {@link epochTag}: the key epoch named by an `e<key_epoch>` kid (`bad_request` otherwise). */
export function parseEpochTag(kid: string): number {
  const match = /^e([1-9][0-9]{0,15})$/.exec(kid);
  const epoch = match ? Number(match[1]) : NaN;
  if (!Number.isSafeInteger(epoch)) fail('bad_request', 'envelope kid is not an epoch tag');
  return epoch;
}

function checkKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) fail('bad_request', 'AEAD key must be 32 bytes');
}

/** Raw XChaCha20-Poly1305 encryption (ct || tag) with plaintext size limit. */
export function xc20pSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: object): Uint8Array {
  checkKey(key);
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) fail('bad_request', 'nonce must be 24 bytes');
  if (plaintext.length > MAX_PLAINTEXT_BYTES) fail('bad_request', 'plaintext exceeds 65536 bytes');
  return xchacha20poly1305(key, nonce, cjsonBytes(aad)).encrypt(plaintext);
}

/** Raw XChaCha20-Poly1305 decryption; authentication failure is `decrypt_failed`. */
export function xc20pOpen(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: object): Uint8Array {
  checkKey(key);
  if (nonce.length !== NONCE_BYTES) fail('bad_request', 'nonce must be 24 bytes');
  if (ciphertext.length < TAG_BYTES || ciphertext.length > MAX_PLAINTEXT_BYTES + TAG_BYTES) fail('bad_request', 'ciphertext length out of range');
  const aadBytes = cjsonBytes(aad);
  try {
    return xchacha20poly1305(key, nonce, aadBytes).decrypt(ciphertext);
  } catch {
    return fail('decrypt_failed', 'AEAD authentication failed');
  }
}

/** Validate an untrusted envelope's shape (version and algorithm fail closed). */
export function parseEnvelope(value: unknown, what = 'envelope'): Envelope {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== 'xc20p') fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'kid', 'n', 'ct'], what);
  if (typeof obj['kid'] !== 'string' || !KID_PATTERN.test(obj['kid'])) fail('bad_request', `${what}.kid is invalid`);
  asB64(obj['n'], `${what}.n`, NONCE_BYTES);
  asB64(obj['ct'], `${what}.ct`);
  return { v: 1, alg: 'xc20p', kid: obj['kid'], n: obj['n'] as string, ct: obj['ct'] as string };
}

export function sealEnvelope(key: Uint8Array, plaintext: Uint8Array, aad: object, opts: SealOptions): Envelope {
  if (!KID_PATTERN.test(opts.kid)) fail('bad_request', 'envelope kid is invalid');
  const nonce = opts.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(key, nonce, plaintext, aad);
  return { v: 1, alg: 'xc20p', kid: opts.kid, n: b64encode(nonce), ct: b64encode(ct) };
}

/** Open an envelope. If `expectedKid` is given the envelope kid must match it. */
export function openEnvelope(key: Uint8Array, envelope: unknown, aad: object, expectedKid?: string): Uint8Array {
  const env = parseEnvelope(envelope);
  if (expectedKid !== undefined && env.kid !== expectedKid) fail('bad_request', 'envelope kid mismatch');
  return xc20pOpen(key, b64decode(env.n), b64decode(env.ct), aad);
}

/**
 * Reject a set of envelopes produced under the same key that reuse a nonce
 * (`bad_request`). Senders MUST NOT reuse nonces; receivers use this on batches.
 */
export function assertUniqueNonces(envelopes: readonly { n: string }[]): void {
  const seen = new Set<string>();
  for (const env of envelopes) {
    if (seen.has(env.n)) fail('bad_request', 'duplicate nonce under the same key');
    seen.add(env.n);
  }
}
