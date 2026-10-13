/** Byte helpers shared by every module. Runtime-neutral (Workers, Node, browsers). */
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { fail } from './errors.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Strict UTF-8 decode; invalid sequences are `bad_request`. */
export function utf8Decode(bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    return fail('bad_request', 'invalid UTF-8');
  }
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time comparison for equal-length inputs. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function isAllZero(bytes: Uint8Array): boolean {
  let acc = 0;
  for (const b of bytes) acc |= b;
  return acc === 0;
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** Cryptographically secure random bytes from WebCrypto (available in Workers and Node >= 19). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
