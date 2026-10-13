/**
 * Recovery key (spec §3.4): 32 random bytes displayed as Crockford base32
 * (MSB-first bit order, uppercase, 52 symbols in 13 groups of 4 joined by "-").
 *
 *   KEK_rk = HKDF(ikm=rk, salt=utf8("akv1"), info="akv1/recovery-kek", L=32)
 *   wire   = {v:1, alg:"rk-xc20p", key_epoch, n, ct}, aad = {ctx:"akv1/rk-wrap", vault_id, key_epoch}
 *
 * Decoding accepts ASCII only (any non-ASCII character is `bad_request`, so
 * look-alikes such as U+0131 or fullwidth digits never fold into symbols). It is
 * ASCII case-insensitive, ignores "-" and ASCII whitespace, maps I/L to 1 and O
 * to 0, and rejects any other symbol, a wrong length or non-zero padding bits.
 */
import { b64decode, b64encode } from './base64url.js';
import { randomBytes, utf8Encode } from './bytes.js';
import { NONCE_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ALIASES: Record<string, string> = { I: '1', L: '1', O: '0' };
export const RECOVERY_KEY_BYTES = 32;
const SYMBOLS = Math.ceil((RECOVERY_KEY_BYTES * 8) / 5); // 52

export interface RecoveryWrap {
  v: 1;
  alg: 'rk-xc20p';
  key_epoch: number;
  n: string;
  ct: string;
}

export function generateRecoveryKey(): Uint8Array {
  return randomBytes(RECOVERY_KEY_BYTES);
}

/** Display form of a 32-byte recovery key. */
export function encodeRecoveryKey(rk: Uint8Array): string {
  if (rk.length !== RECOVERY_KEY_BYTES) fail('bad_request', 'recovery key must be 32 bytes');
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of rk) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += CROCKFORD[(acc << (5 - bits)) & 31];
  return out.match(/.{1,4}/g)!.join('-');
}

/** Parse a user-entered recovery key. Throws `bad_request`. */
export function decodeRecoveryKey(display: string): Uint8Array {
  if (typeof display !== 'string' || display.length > 128) fail('bad_request', 'recovery key must be a string');
  if (/[^\x00-\x7f]/.test(display)) fail('bad_request', 'recovery key must be ASCII');
  // ASCII-only input: toUpperCase folds a-z only and \s matches ASCII whitespace only.
  const symbols = display.toUpperCase().replace(/[-\s]/g, '');
  if (symbols.length !== SYMBOLS) fail('bad_request', 'recovery key has the wrong length');
  const out = new Uint8Array(RECOVERY_KEY_BYTES);
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (const raw of symbols) {
    const value = CROCKFORD.indexOf(ALIASES[raw] ?? raw);
    if (value < 0) fail('bad_request', 'recovery key contains an invalid symbol');
    acc = ((acc << 5) | value) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      out[o++] = (acc >> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) fail('bad_request', 'recovery key has non-zero padding bits');
  return out;
}

export function deriveRecoveryKek(rk: Uint8Array): Uint8Array {
  if (rk.length !== RECOVERY_KEY_BYTES) fail('bad_request', 'recovery key must be 32 bytes');
  return hkdf32(rk, utf8Encode('akv1'), utf8Encode('akv1/recovery-kek'));
}

function rkAad(vaultId: string, keyEpoch: number): object {
  return { ctx: 'akv1/rk-wrap', vault_id: vaultId, key_epoch: keyEpoch };
}

export function parseRecoveryWrap(value: unknown, what = 'recovery wrap'): RecoveryWrap {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== 'rk-xc20p') fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'key_epoch', 'n', 'ct'], what);
  return {
    v: 1,
    alg: 'rk-xc20p',
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct: asB64(obj['ct'], `${what}.ct`, 48),
  };
}

export interface WrapWithRecoveryKeyArgs {
  vk: Uint8Array;
  vaultId: string;
  keyEpoch: number;
  rk: Uint8Array;
  /** Inject a fixed nonce (test vectors only). */
  nonce?: Uint8Array;
}

export function wrapWithRecoveryKey(args: WrapWithRecoveryKeyArgs): RecoveryWrap {
  if (args.vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  const vaultId = asId(args.vaultId, 'vault_id');
  const keyEpoch = asInt(args.keyEpoch, 'key_epoch', 1);
  const nonce = args.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(deriveRecoveryKek(args.rk), nonce, args.vk, rkAad(vaultId, keyEpoch));
  return { v: 1, alg: 'rk-xc20p', key_epoch: keyEpoch, n: b64encode(nonce), ct: b64encode(ct) };
}

export function unwrapWithRecoveryKey(args: { wrap: unknown; vaultId: string; rk: Uint8Array }): Uint8Array {
  const wrap = parseRecoveryWrap(args.wrap);
  return xc20pOpen(deriveRecoveryKek(args.rk), b64decode(wrap.n), b64decode(wrap.ct), rkAad(asId(args.vaultId, 'vault_id'), wrap.key_epoch));
}
