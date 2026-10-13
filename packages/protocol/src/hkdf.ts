/** HKDF-SHA256 (RFC 5869) wrapper with fixed 32-byte output. */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

export function hkdf32(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, salt, info, 32);
}
