/**
 * Name tags, the device-computed keyed blind index (spec §3.7):
 *
 *   NameIndexKey[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id),
 *                          info=utf8("akv1/name-index\n") || cjson({key_epoch:e}), L=32)
 *   name_tag        = b64(HKDF(ikm=NameIndexKey[e], salt="", info=utf8("akv1/name-tag\n") || utf8(NFC(name)), L=16))
 *
 * Only devices hold the index key; the server stores and matches tags only.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { b64decode, b64encode } from './base64url.js';
import { concatBytes, utf8Encode } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { MAX_ITEM_NAME } from './sealed-op.js';
import { asId, asInt, asString, asWellFormed } from './validate.js';

export const NAME_TAG_BYTES = 16;
const TAG_INFO = utf8Encode('akv1/name-tag\n');
const EMPTY = new Uint8Array(0);

export function nameIndexKey(vk: Uint8Array, vaultId: string, keyEpoch: number): Uint8Array {
  if (!(vk instanceof Uint8Array) || vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  const salt = b64decode(asId(vaultId, 'vault_id'));
  const info = concatBytes(utf8Encode('akv1/name-index\n'), cjsonBytes({ key_epoch: asInt(keyEpoch, 'key_epoch', 1) }));
  return hkdf32(vk, salt, info);
}

/** The b64 16-byte tag of `name` (NFC-normalized) under one epoch's index key. */
export function nameTag(indexKey: Uint8Array, name: string): string {
  if (!(indexKey instanceof Uint8Array) || indexKey.length !== 32) fail('bad_request', 'name index key must be 32 bytes');
  const nfc = asWellFormed(asString(name, 'name', MAX_ITEM_NAME, 1), 'name').normalize('NFC');
  return b64encode(hkdf(sha256, indexKey, EMPTY, concatBytes(TAG_INFO, utf8Encode(nfc)), NAME_TAG_BYTES));
}
