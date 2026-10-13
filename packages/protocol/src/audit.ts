/**
 * Encrypted, hash-chained audit stream (spec §7). Entry `i` is an AEAD envelope
 * under the audit key of key epoch `e`:
 *
 *   AuditKey[e] = HKDF(ikm=VK[e], salt=b64decode(vault_id),
 *                      info=utf8("akv1/audit-key\n") || cjson({key_epoch}), L=32)
 *
 * with kid `e<e>` and aad `{ctx:"akv1/audit", vault_id, seq:i, prev, key_epoch:e}`,
 * where `prev` is `b64 sha256(cjson(entry i-1))` ('' for seq 0). Key epochs never
 * decrease along the chain and never exceed the vault's current key epoch.
 * Entries carry no author signature: any holder of VK[e] can write entries at
 * epoch e, so per-epoch keys bound a removed device to the epochs it held.
 * Audit checkpoints are `{v:1, vault_id, seq, head,
 * author, ts, sig}` signed with `akv1/audit-checkpoint`, where `head` is the hash
 * of entry `seq`.
 */
import { b64decode, sha256b64 } from './base64url.js';
import { assertUniqueNonces, epochTag, openEnvelope, parseEnvelope, parseEpochTag, sealEnvelope, type Envelope } from './aead.js';
import { concatBytes, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse, type JsonObject } from './canonical-json.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import type { MembershipState } from './membership-types.js';
import { SIGN_CONTEXT, signObject, verifyObject } from './signing.js';
import { asArray, asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface AuditHead {
  seq: number;
  head: string;
}

export interface AuditCheckpoint {
  v: 1;
  vault_id: string;
  seq: number;
  head: string;
  author: string;
  ts: number;
  sig: string;
}

/** Audit key of one key epoch, derived from that epoch's vault key (same salt convention as the item key). */
export function deriveAuditKey(vk: Uint8Array, vaultId: string, keyEpoch: number): Uint8Array {
  if (!(vk instanceof Uint8Array) || vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  asInt(keyEpoch, 'key_epoch', 1);
  const salt = b64decode(asId(vaultId, 'vault_id'));
  return hkdf32(vk, salt, concatBytes(utf8Encode('akv1/audit-key\n'), cjsonBytes({ key_epoch: keyEpoch })));
}

export function auditAad(vaultId: string, seq: number, prev: string, keyEpoch: number): JsonObject {
  return { ctx: 'akv1/audit', vault_id: vaultId, seq, prev, key_epoch: keyEpoch };
}

export function auditEntryHash(entry: Envelope): string {
  return sha256b64(cjsonBytes(entry));
}

export interface AppendAuditArgs {
  /** Vault key of `keyEpoch`; the audit key is derived from it. */
  vk: Uint8Array;
  vaultId: string;
  /** The vault's current key epoch (the Worker refuses any other). */
  keyEpoch: number;
  /** Head of the existing chain, or null for the first entry. */
  head: AuditHead | null;
  event: JsonObject;
  /** Inject a fixed nonce (test vectors only). */
  nonce?: Uint8Array;
}

export function appendAuditEntry(args: AppendAuditArgs): { entry: Envelope; head: AuditHead } {
  const seq = args.head ? args.head.seq + 1 : 0;
  const prev = args.head ? args.head.head : '';
  const vaultId = asId(args.vaultId, 'vault_id');
  const key = deriveAuditKey(args.vk, vaultId, args.keyEpoch);
  const kid = epochTag(args.keyEpoch);
  const opts = args.nonce ? { kid, nonce: args.nonce } : { kid };
  const entry = sealEnvelope(key, cjsonBytes(args.event), auditAad(vaultId, seq, prev, args.keyEpoch), opts);
  return { entry, head: { seq, head: auditEntryHash(entry) } };
}

export interface VerifyAuditOptions {
  /** Vault key lookup by key epoch; `undefined` when the caller holds no key for that epoch. */
  vaultKeys: (keyEpoch: number) => Uint8Array | undefined;
  vaultId: string;
  /** Current key epoch of the verified membership state; no entry may name a later one. */
  keyEpoch: number;
  /**
   * Lowest epoch whose key the caller MUST hold (default `keyEpoch`): the epoch it
   * joined at, or the oldest epoch its recovery bundle covers. A missing key for
   * any epoch in `minKeyEpoch..keyEpoch` is a refusal, never an opaque entry.
   */
  minKeyEpoch?: number;
  /** Witnessed audit checkpoint (already signature-verified). */
  witnessed?: AuditHead;
}

/** One verified chain entry: decrypted, or opaque (an epoch below `minKeyEpoch` whose key the caller lacks). */
export type AuditChainEntry =
  | { seq: number; key_epoch: number; opaque: false; event: JsonObject }
  | { seq: number; key_epoch: number; opaque: true };

/**
 * Replay the whole chain and decrypt every entry whose epoch key the caller
 * holds, selecting the audit key from the entry's `e<key_epoch>` kid. The
 * caller MUST hold the key of `keyEpoch` (checked before any entry is read)
 * and of every epoch in `minKeyEpoch..keyEpoch` an entry uses (bad_request
 * otherwise), so every entry at or above `minKeyEpoch` is decrypted. That does
 * not prove the chain reaches such an epoch: a chain truncated before its first
 * entry there is all-opaque and passes unless `witnessed` bounds it, so callers
 * must not present an all-opaque result as verified. An entry at an older epoch the caller
 * holds no key for (a device enrolled after it, or a recovery bundle that
 * predates it) is opaque: hash-chained and epoch-checked, returned as
 * `{seq, key_epoch, opaque: true}`. Rejects (code): `minKeyEpoch` outside
 * 1..keyEpoch, a kid that is not an epoch tag, a key epoch lower than the
 * previous entry's or above `keyEpoch` (bad_request); reordered, dropped or substituted decryptable entries
 * (decrypt_failed); a chain shorter than, or with a different entry at, the
 * witnessed checkpoint (rollback); reused nonces (bad_request).
 */
export function verifyAuditChain(entries: readonly unknown[], opts: VerifyAuditOptions): { events: AuditChainEntry[]; head: AuditHead | null } {
  const parsed = asArray(entries, 'audit entries', 1_000_000).map((e, i) => parseEnvelope(e, `audit entry ${i}`));
  assertUniqueNonces(parsed);
  const vaultId = asId(opts.vaultId, 'vault_id');
  const maxEpoch = asInt(opts.keyEpoch, 'key_epoch', 1);
  const minEpoch = asInt(opts.minKeyEpoch ?? maxEpoch, 'min_key_epoch', 1);
  if (minEpoch > maxEpoch) fail('bad_request', 'min_key_epoch is above key_epoch');
  const keys = new Map<number, Uint8Array | null>();
  const keyFor = (epoch: number): Uint8Array | null => {
    let key = keys.get(epoch);
    if (key === undefined) {
      const vk = opts.vaultKeys(epoch);
      if (!vk && epoch >= minEpoch) fail('bad_request', 'no vault key for a required audit epoch');
      key = vk ? deriveAuditKey(vk, vaultId, epoch) : null;
      keys.set(epoch, key);
    }
    return key;
  };
  keyFor(maxEpoch); // the current epoch's key is always required, even before any entry uses it
  const events: AuditChainEntry[] = [];
  const hashes: string[] = [];
  let lastEpoch = 0;
  parsed.forEach((entry, seq) => {
    const epoch = parseEpochTag(entry.kid);
    if (epoch < lastEpoch) fail('bad_request', 'audit key epoch decreased along the chain');
    if (epoch > maxEpoch) fail('bad_request', 'audit key epoch is ahead of the membership state');
    lastEpoch = epoch;
    const key = keyFor(epoch);
    const prev = seq === 0 ? '' : hashes[seq - 1]!;
    if (key) {
      const plaintext = openEnvelope(key, entry, auditAad(vaultId, seq, prev, epoch));
      events.push({ seq, key_epoch: epoch, opaque: false, event: asObject(cjsonParse(plaintext), 'audit event') as JsonObject });
    } else {
      events.push({ seq, key_epoch: epoch, opaque: true });
    }
    hashes.push(auditEntryHash(entry));
  });
  if (opts.witnessed) {
    if (opts.witnessed.seq >= hashes.length) fail('rollback', 'audit chain is behind the witnessed checkpoint');
    if (hashes[opts.witnessed.seq] !== opts.witnessed.head) fail('rollback', 'audit chain forks from the witnessed checkpoint');
  }
  const last = hashes.length - 1;
  return { events, head: last >= 0 ? { seq: last, head: hashes[last]! } : null };
}

export function signAuditCheckpoint(fields: Omit<AuditCheckpoint, 'v' | 'sig'>, secretKey: Uint8Array): AuditCheckpoint {
  return signObject(SIGN_CONTEXT.auditCheckpoint, { v: 1 as const, ...fields }, secretKey);
}

export function parseAuditCheckpoint(value: unknown, what = 'audit checkpoint'): AuditCheckpoint {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'seq', 'head', 'author', 'ts', 'sig'], what);
  return {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    seq: asInt(obj['seq'], `${what}.seq`),
    head: asB64(obj['head'], `${what}.head`, 32),
    author: asId(obj['author'], `${what}.author`),
    ts: asInt(obj['ts'], `${what}.ts`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}

/** Verify an audit checkpoint signed by a current member device. */
export function verifyAuditCheckpoint(value: unknown, state: MembershipState): AuditCheckpoint {
  const cp = parseAuditCheckpoint(value);
  if (cp.vault_id !== state.vault_id) fail('bad_request', 'audit checkpoint belongs to another vault');
  const device = state.devices.find((d) => d.device_id === cp.author);
  if (!device) fail('forbidden', 'audit checkpoint author is not a current device');
  verifyObject(SIGN_CONTEXT.auditCheckpoint, cp, device.sign_pub);
  return cp;
}
