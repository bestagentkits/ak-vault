/**
 * base64url without padding (spec §2). The decoder is strict: it rejects
 * padding, non-alphabet characters, impossible lengths and non-canonical
 * trailing bits, so every byte string has exactly one accepted encoding.
 */
import { fail } from './errors.js';
import { sha256 } from './bytes.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

export function b64encode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

function sextet(text: string, index: number): number {
  const code = text.charCodeAt(index);
  const value = code < 128 ? (LOOKUP[code] as number) : -1;
  if (value < 0) fail('bad_request', 'invalid base64url character');
  return value;
}

/** Strict base64url decode. Throws `bad_request` on any non-canonical input. */
export function b64decode(text: string): Uint8Array {
  if (typeof text !== 'string') fail('bad_request', 'base64url input must be a string');
  const rem = text.length % 4;
  if (rem === 1) fail('bad_request', 'invalid base64url length');
  const full = text.length - rem;
  const out = new Uint8Array((full / 4) * 3 + (rem === 0 ? 0 : rem - 1));
  let o = 0;
  for (let i = 0; i < full; i += 4) {
    const n = (sextet(text, i) << 18) | (sextet(text, i + 1) << 12) | (sextet(text, i + 2) << 6) | sextet(text, i + 3);
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  if (rem === 2) {
    const a = sextet(text, full);
    const b = sextet(text, full + 1);
    if ((b & 15) !== 0) fail('bad_request', 'non-canonical base64url trailing bits');
    out[o++] = ((a << 2) | (b >> 4)) & 255;
  } else if (rem === 3) {
    const a = sextet(text, full);
    const b = sextet(text, full + 1);
    const c = sextet(text, full + 2);
    if ((c & 3) !== 0) fail('bad_request', 'non-canonical base64url trailing bits');
    out[o++] = ((a << 2) | (b >> 4)) & 255;
    out[o++] = ((b << 4) | (c >> 2)) & 255;
  }
  return out;
}

/** Decode and require an exact byte length. */
export function b64decodeLength(text: string, length: number, what = 'value'): Uint8Array {
  const bytes = b64decode(text);
  if (bytes.length !== length) fail('bad_request', `${what} must be ${length} bytes`);
  return bytes;
}

/** `b64(SHA-256(data))`, the digest form used throughout the protocol. */
export function sha256b64(data: Uint8Array): string {
  return b64encode(sha256(data));
}
