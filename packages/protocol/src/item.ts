/**
 * Item payload, item key derivation and item AAD (spec §3, §3.2).
 *
 *   ItemKey = HKDF(ikm=VK[e], salt=b64decode(vault_id),
 *                  info=utf8("akv1/item-key\n") || cjson({item_id, key_epoch}), L=32)
 *
 * Envelope `kid` is the epoch tag `e<key_epoch>`. Live items encrypt
 * `cjson({name, value, meta, sensitivity})`; tombstones encrypt `cjson({deleted:true})`.
 */
import { b64decode } from './base64url.js';
import { concatBytes, utf8Encode } from './bytes.js';
import { cjson, cjsonBytes, cjsonParse, type JsonObject } from './canonical-json.js';
import { epochTag, openEnvelope, sealEnvelope, type Envelope } from './aead.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { asBool, asEnum, asId, asInt, asObject, asString, exactKeys } from './validate.js';

export const SENSITIVITIES = ['normal', 'high'] as const;
export type Sensitivity = (typeof SENSITIVITIES)[number];

export interface ItemPayload {
  name: string;
  value: string;
  meta: JsonObject;
  sensitivity: Sensitivity;
}

export interface TombstonePayload {
  deleted: true;
}

/** Authenticated context bound into every item ciphertext. */
export interface ItemContext {
  vault_id: string;
  item_id: string;
  base_revision: number;
  key_epoch: number;
  author: string;
  tombstone: boolean;
}

export function deriveItemKey(vk: Uint8Array, vaultId: string, itemId: string, keyEpoch: number): Uint8Array {
  if (vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  asId(itemId, 'item_id');
  asInt(keyEpoch, 'key_epoch', 1);
  const salt = b64decode(asId(vaultId, 'vault_id'));
  const info = concatBytes(utf8Encode('akv1/item-key\n'), cjsonBytes({ item_id: itemId, key_epoch: keyEpoch }));
  return hkdf32(vk, salt, info);
}

export function itemAad(ctx: ItemContext): JsonObject {
  return {
    ctx: 'akv1/item',
    vault_id: asId(ctx.vault_id, 'vault_id'),
    item_id: asId(ctx.item_id, 'item_id'),
    base_revision: asInt(ctx.base_revision, 'base_revision'),
    key_epoch: asInt(ctx.key_epoch, 'key_epoch', 1),
    author: asId(ctx.author, 'author'),
    tombstone: asBool(ctx.tombstone, 'tombstone'),
  };
}

/** Validate an untrusted (decrypted) payload object. */
export function parseItemPayload(value: unknown, tombstone: boolean): ItemPayload | TombstonePayload {
  const obj = asObject(value, 'item payload');
  if (tombstone) {
    exactKeys(obj, ['deleted'], 'tombstone payload');
    if (obj['deleted'] !== true) fail('bad_request', 'tombstone payload must be {"deleted":true}');
    return { deleted: true };
  }
  exactKeys(obj, ['name', 'value', 'meta', 'sensitivity'], 'item payload');
  const meta = asObject(obj['meta'], 'item payload.meta');
  cjson(meta); // meta must be inside the canonical data model
  return {
    name: asString(obj['name'], 'item payload.name', 4096, 1),
    value: asString(obj['value'], 'item payload.value', 65_536),
    meta: meta as JsonObject,
    sensitivity: asEnum(obj['sensitivity'], SENSITIVITIES, 'item payload.sensitivity'),
  };
}

export interface SealItemArgs extends ItemContext {
  vk: Uint8Array;
  payload: ItemPayload | TombstonePayload;
  /** Inject a fixed nonce (test vectors only). */
  nonce?: Uint8Array;
}

export function sealItem(args: SealItemArgs): Envelope {
  const payload = parseItemPayload(args.payload, args.tombstone);
  const key = deriveItemKey(args.vk, args.vault_id, args.item_id, args.key_epoch);
  const opts = args.nonce ? { kid: epochTag(args.key_epoch), nonce: args.nonce } : { kid: epochTag(args.key_epoch) };
  return sealEnvelope(key, cjsonBytes(payload), itemAad(args), opts);
}

export interface OpenItemArgs extends ItemContext {
  vk: Uint8Array;
  env: unknown;
}

/** Decrypt and validate an item. The plaintext must itself be canonical JSON. */
export function openItem(args: OpenItemArgs): ItemPayload | TombstonePayload {
  const key = deriveItemKey(args.vk, args.vault_id, args.item_id, args.key_epoch);
  const plaintext = openEnvelope(key, args.env, itemAad(args), epochTag(args.key_epoch));
  return parseItemPayload(cjsonParse(plaintext), args.tombstone);
}
