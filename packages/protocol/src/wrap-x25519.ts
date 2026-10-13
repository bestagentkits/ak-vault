/**
 * Device key wrap `x25519-xc20p` (spec §3.3):
 *
 *   shared   = X25519(esk, recipient.kx_pub)          ; all-zero output rejected
 *   wrap_key = HKDF(ikm=shared, salt=epk || recipient.kx_pub, info="akv1/wrap/x25519", L=32)
 *   ct       = XC20P(wrap_key, n, VK[e], aad={ctx:"akv1/wrap", vault_id, key_epoch, recipient})
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { b64decode, b64decodeLength, b64encode } from './base64url.js';
import { concatBytes, isAllZero, randomBytes, utf8Encode } from './bytes.js';
import { NONCE_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { kxKeyPairFromSecret } from './signing.js';
import { asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface X25519Wrap {
  v: 1;
  alg: 'x25519-xc20p';
  rcpt: string;
  key_epoch: number;
  epk: string;
  n: string;
  ct: string;
}

export interface WrapRecipient {
  device_id: string;
  /** Recipient X25519 public key, b64 or raw bytes. */
  kx_pub: string | Uint8Array;
}

const INFO = utf8Encode('akv1/wrap/x25519');

function wrapAad(vaultId: string, keyEpoch: number, recipient: string): object {
  return { ctx: 'akv1/wrap', vault_id: vaultId, key_epoch: keyEpoch, recipient };
}

/** X25519 that fails closed (`bad_request`) on low-order points / all-zero output. */
export function x25519Shared(secret: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (!(secret instanceof Uint8Array) || !(publicKey instanceof Uint8Array) || secret.length !== 32 || publicKey.length !== 32) fail('bad_request', 'X25519 keys must be 32 bytes');
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(secret, publicKey);
  } catch {
    return fail('bad_request', 'X25519 produced an all-zero shared secret');
  }
  if (isAllZero(shared)) fail('bad_request', 'X25519 produced an all-zero shared secret');
  return shared;
}

function deriveWrapKey(shared: Uint8Array, epk: Uint8Array, rcptKxPub: Uint8Array): Uint8Array {
  return hkdf32(shared, concatBytes(epk, rcptKxPub), INFO);
}

export function parseX25519Wrap(value: unknown, what = 'wrap'): X25519Wrap {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== 'x25519-xc20p') fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'rcpt', 'key_epoch', 'epk', 'n', 'ct'], what);
  return {
    v: 1,
    alg: 'x25519-xc20p',
    rcpt: asId(obj['rcpt'], `${what}.rcpt`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    epk: asB64(obj['epk'], `${what}.epk`, 32),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct: asB64(obj['ct'], `${what}.ct`, 48),
  };
}

export interface WrapToDeviceArgs {
  vk: Uint8Array;
  vaultId: string;
  keyEpoch: number;
  recipient: WrapRecipient;
  /** Inject a fixed ephemeral secret (test vectors only). */
  ephemeralSecret?: Uint8Array;
  /** Inject a fixed nonce (test vectors only). */
  nonce?: Uint8Array;
}

export function wrapToDevice(args: WrapToDeviceArgs): X25519Wrap {
  if (args.vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  const rcpt = asId(args.recipient.device_id, 'recipient.device_id');
  const keyEpoch = asInt(args.keyEpoch, 'key_epoch', 1);
  const vaultId = asId(args.vaultId, 'vault_id');
  const rcptPub = typeof args.recipient.kx_pub === 'string' ? b64decodeLength(args.recipient.kx_pub, 32, 'kx_pub') : args.recipient.kx_pub;
  if (!(rcptPub instanceof Uint8Array) || rcptPub.length !== 32) fail('bad_request', 'kx_pub must be 32 bytes');
  const esk = args.ephemeralSecret ?? randomBytes(32);
  const epk = kxKeyPairFromSecret(esk).publicKey; // bad_request on a wrong-length secret
  const wrapKey = deriveWrapKey(x25519Shared(esk, rcptPub), epk, rcptPub);
  const nonce = args.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(wrapKey, nonce, args.vk, wrapAad(vaultId, keyEpoch, rcpt));
  return { v: 1, alg: 'x25519-xc20p', rcpt, key_epoch: keyEpoch, epk: b64encode(epk), n: b64encode(nonce), ct: b64encode(ct) };
}

export interface UnwrapFromDeviceArgs {
  wrap: unknown;
  vaultId: string;
  /** The unwrapping device's own ID; the wrap's `rcpt` must equal it (`forbidden` otherwise). */
  deviceId: string;
  kxSecret: Uint8Array;
}

/** Recover VK[e]. Throws `decrypt_failed` on wrong key / tampering. */
export function unwrapFromDevice(args: UnwrapFromDeviceArgs): Uint8Array {
  const wrap = parseX25519Wrap(args.wrap);
  if (wrap.rcpt !== args.deviceId) fail('forbidden', 'wrap is addressed to a different device');
  const ownPub = kxKeyPairFromSecret(args.kxSecret).publicKey; // bad_request on a wrong-length secret
  const epk = b64decode(wrap.epk);
  const wrapKey = deriveWrapKey(x25519Shared(args.kxSecret, epk), epk, ownPub);
  return xc20pOpen(wrapKey, b64decode(wrap.n), b64decode(wrap.ct), wrapAad(asId(args.vaultId, 'vault_id'), wrap.key_epoch, wrap.rcpt));
}
