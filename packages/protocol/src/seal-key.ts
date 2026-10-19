/**
 * Per-epoch seal key and the owner-signed seal-key document (spec §3.6):
 *
 *   SealSK[e]   = HKDF(ikm=VK[e], salt=b64decode(vault_id),
 *                      info=utf8("akv1/seal-key\n") || cjson({key_epoch:e}), L=32)
 *   seal_pub[e] = X25519(SealSK[e], 9)
 *
 * `SealSK[e]` is used unmodified as an X25519 private key (X25519 clamps it).
 */
import { b64decode, b64encode } from './base64url.js';
import { bytesEqual, concatBytes, utf8Encode } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { verifyMembershipChain } from './membership-log.js';
import type { VerifyChainOptions } from './membership-types.js';
import { SIGN_CONTEXT, kxKeyPairFromSecret, signObject, verifyObject, type KeyPair } from './signing.js';
import { asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface SealKeyDoc {
  v: 1;
  vault_id: string;
  key_epoch: number;
  membership_seq: number;
  seal_pub: string;
  author: string;
  ts: number;
  sig: string;
}

export type UnsignedSealKeyDoc = Omit<SealKeyDoc, 'v' | 'sig'>;

/** Derive the seal keypair of epoch `keyEpoch` from `VK[keyEpoch]`. */
export function deriveSealKeyPair(vk: Uint8Array, vaultId: string, keyEpoch: number): KeyPair {
  if (!(vk instanceof Uint8Array) || vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  const salt = b64decode(asId(vaultId, 'vault_id'));
  const info = concatBytes(utf8Encode('akv1/seal-key\n'), cjsonBytes({ key_epoch: asInt(keyEpoch, 'key_epoch', 1) }));
  return kxKeyPairFromSecret(hkdf32(vk, salt, info));
}

export function parseSealKeyDoc(value: unknown, what = 'seal-key document'): SealKeyDoc {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'key_epoch', 'membership_seq', 'seal_pub', 'author', 'ts', 'sig'], what);
  return {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    membership_seq: asInt(obj['membership_seq'], `${what}.membership_seq`),
    seal_pub: asB64(obj['seal_pub'], `${what}.seal_pub`, 32),
    author: asId(obj['author'], `${what}.author`),
    ts: asInt(obj['ts'], `${what}.ts`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}

/** Build and sign a seal-key document (author = an owner device). */
export function signSealKeyDoc(fields: UnsignedSealKeyDoc, secretKey: Uint8Array): SealKeyDoc {
  const doc = signObject(SIGN_CONTEXT.sealKey, { v: 1 as const, ...fields }, secretKey);
  parseSealKeyDoc(doc);
  return doc;
}

/** Sign the document of `VK[keyEpoch]` for a verified chain position. */
export function buildSealKeyDoc(
  args: { vk: Uint8Array; vaultId: string; keyEpoch: number; membershipSeq: number; author: string; ts: number },
  secretKey: Uint8Array,
): SealKeyDoc {
  const { publicKey } = deriveSealKeyPair(args.vk, args.vaultId, args.keyEpoch);
  return signSealKeyDoc(
    { vault_id: args.vaultId, key_epoch: args.keyEpoch, membership_seq: args.membershipSeq, seal_pub: b64encode(publicKey), author: args.author, ts: args.ts },
    secretKey,
  );
}

export interface VerifySealKeyDocOptions {
  /** The vault the document must name (`bad_request` otherwise). */
  vaultId: string;
  /** `VK[doc.key_epoch]` when the verifier holds it; a device that holds it MUST pass it. */
  vk?: Uint8Array;
  /** Pinned owner anchor (b64 sign_pub of the genesis author), checked on the chain and its prefix (`forbidden`). */
  trustedAnchor?: VerifyChainOptions['trustedAnchor'];
  /** Highest witnessed membership checkpoint; a shorter or forked chain is `rollback`. */
  witnessedCheckpoint?: VerifyChainOptions['witnessedCheckpoint'];
}

/**
 * Verify a seal-key document against the verifier's verified membership chain
 * (`chain`, genesis first, at or after `membership_seq`), pinned to
 * `trustedAnchor` and `witnessedCheckpoint` when given (a device passes the
 * values it pinned and witnessed itself). Checks in spec §3.6
 * order: shape; vault; `membership_seq` within the chain and `key_epoch` equal
 * to the chain's key epoch there (`bad_request`); author a human owner device
 * current at `membership_seq` (`forbidden`); signature (`invalid_signature`);
 * `seal_pub` recomputed from `vk` (`forbidden`).
 */
export function verifySealKeyDoc(value: unknown, chain: readonly unknown[], opts: VerifySealKeyDocOptions): SealKeyDoc {
  const doc = parseSealKeyDoc(value);
  if (doc.vault_id !== opts.vaultId) fail('bad_request', 'seal-key document belongs to another vault');
  const anchor = opts.trustedAnchor === undefined ? {} : { trustedAnchor: opts.trustedAnchor };
  const witnessed = opts.witnessedCheckpoint === undefined ? {} : { witnessedCheckpoint: opts.witnessedCheckpoint };
  const head = verifyMembershipChain(chain, { vaultId: opts.vaultId, ...anchor, ...witnessed });
  if (doc.membership_seq > head.seq) fail('bad_request', 'seal-key document is ahead of the verified chain');
  // The prefix of a verified chain is itself a verified chain; the witnessed checkpoint applies only to the full chain.
  const at = doc.membership_seq === head.seq ? head : verifyMembershipChain(chain.slice(0, doc.membership_seq + 1), { vaultId: opts.vaultId, ...anchor });
  if (doc.key_epoch !== at.key_epoch) fail('bad_request', 'seal-key document key_epoch does not match the chain');
  const author = at.devices.find((d) => d.device_id === doc.author);
  if (!author || author.kind !== 'human' || author.role !== 'owner') fail('forbidden', 'seal-key document author is not an owner device');
  verifyObject(SIGN_CONTEXT.sealKey, doc, author.sign_pub);
  if (opts.vk !== undefined) {
    const expected = deriveSealKeyPair(opts.vk, doc.vault_id, doc.key_epoch).publicKey;
    if (!bytesEqual(expected, b64decode(doc.seal_pub))) fail('forbidden', 'seal_pub does not match the vault key');
  }
  return doc;
}

/**
 * Server-side replacement rule (spec §9.6): one document per key epoch; an
 * incoming document whose `membership_seq` is below the stored one for the
 * same epoch is `conflict`. Both documents must already be verified.
 */
export function checkSealKeyDocReplace(stored: SealKeyDoc | null, incoming: SealKeyDoc): void {
  if (stored && stored.vault_id === incoming.vault_id && stored.key_epoch === incoming.key_epoch && incoming.membership_seq < stored.membership_seq) {
    fail('conflict', 'a newer seal-key document is stored for this epoch');
  }
}
