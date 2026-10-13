/**
 * Recovery bundle (spec §3.4, §11): an opaque blob stored by the server that gives
 * a fresh device the vault keys, the owner trust anchor, the owner recovery
 * signing key and the newest owner-witnessed checkpoint.
 *
 *   BK  = 32 random bytes
 *   env = XC20P(BK, n, cjson(plaintext), aad={ctx:"akv1/recovery-bundle", vault_id, bundle_seq}), kid "bk"
 *   pw  = XC20P(Argon2id(NFC(password), s, t, m, p), n, BK, aad={ctx:"akv1/bundle-pw-wrap", vault_id, bundle_seq, t, m, p})
 *   rk  = XC20P(KEK_rk(rk), n, BK, aad={ctx:"akv1/bundle-rk-wrap", vault_id, bundle_seq})
 */
import { b64decode, b64encode } from './base64url.js';
import { randomBytes } from './bytes.js';
import { NONCE_BYTES, sealEnvelope, openEnvelope, xc20pOpen, xc20pSeal } from './aead.js';
import { cjsonBytes, cjsonParse } from './canonical-json.js';
import { fail } from './errors.js';
import { deriveRecoveryKek } from './recovery-key.js';
import {
  BUNDLE_ENVELOPE_KID,
  parseRecoveryBundlePlaintext,
  parseRecoveryBundleWire,
  parseVkMap,
  type RecoveryBundlePlaintext,
  type RecoveryBundleWire,
} from './recovery-bundle-parse.js';
import { SIGN_CONTEXT, deviceIdFromSignPub, signKeyPairFromSeed, verifyObject } from './signing.js';
import { ARGON2_DEFAULTS, SALT_BYTES, argonNeedsUpgrade, derivePasswordKek, validateArgonParams, type ArgonParams } from './wrap-password.js';
import { asId, asInt } from './validate.js';
import { parseCheckpoint, type Checkpoint } from './checkpoints.js';

const bundleAad = (vaultId: string, seq: number) => ({ ctx: 'akv1/recovery-bundle', vault_id: vaultId, bundle_seq: seq });
const pwAad = (vaultId: string, seq: number, a: ArgonParams) => ({ ctx: 'akv1/bundle-pw-wrap', vault_id: vaultId, bundle_seq: seq, t: a.t, m: a.m, p: a.p });
const rkAad = (vaultId: string, seq: number) => ({ ctx: 'akv1/bundle-rk-wrap', vault_id: vaultId, bundle_seq: seq });

/** Checkpoint author must be the owner anchor; signature must verify (`forbidden` / `invalid_signature`). */
function checkBundleCheckpoint(cp: Checkpoint, vaultId: string, ownerSignPub: string): void {
  if (cp.vault_id !== vaultId) fail('bad_request', 'bundle checkpoint belongs to another vault');
  if (cp.author !== deviceIdFromSignPub(ownerSignPub)) fail('forbidden', 'bundle checkpoint is not signed by the owner anchor');
  verifyObject(SIGN_CONTEXT.checkpoint, cp, ownerSignPub);
}

export interface SealRecoveryBundleArgs {
  vaultId: string;
  /** Monotonic bundle sequence (>= 1); every replacement bundle MUST increase it. */
  bundleSeq: number;
  /** Vault key per key epoch. */
  vk: Record<string, Uint8Array>;
  ownerSignPub: string;
  recoverySignSk: Uint8Array;
  checkpoint: Checkpoint;
  password: string;
  rk: Uint8Array;
  params?: ArgonParams;
  /** Inject fixed values (test vectors only). */
  bundleKey?: Uint8Array;
  salt?: Uint8Array;
  nonces?: { env: Uint8Array; pw: Uint8Array; rk: Uint8Array };
}

export function sealRecoveryBundle(args: SealRecoveryBundleArgs): RecoveryBundleWire {
  const vaultId = asId(args.vaultId, 'vault_id');
  const seq = asInt(args.bundleSeq, 'bundle_seq', 1);
  const params = validateArgonParams(args.params ?? ARGON2_DEFAULTS);
  const vk: Record<string, string> = {};
  for (const [epoch, key] of Object.entries(args.vk)) vk[epoch] = b64encode(key);
  const plaintext: RecoveryBundlePlaintext = parseRecoveryBundlePlaintext({
    v: 1,
    vault_id: vaultId,
    bundle_seq: seq,
    vk: parseVkMap(vk, 'vk'),
    owner_sign_pub: args.ownerSignPub,
    recovery_sign_sk: b64encode(args.recoverySignSk),
    checkpoint: { ...args.checkpoint },
  });
  checkBundleCheckpoint(plaintext.checkpoint, vaultId, plaintext.owner_sign_pub);
  const bk = args.bundleKey ?? randomBytes(32);
  if (bk.length !== 32) fail('bad_request', 'bundle key must be 32 bytes');
  const salt = args.salt ?? randomBytes(SALT_BYTES);
  const nonces = args.nonces ?? { env: randomBytes(NONCE_BYTES), pw: randomBytes(NONCE_BYTES), rk: randomBytes(NONCE_BYTES) };
  const env = sealEnvelope(bk, cjsonBytes(plaintext), bundleAad(vaultId, seq), { kid: BUNDLE_ENVELOPE_KID, nonce: nonces.env });
  const pwCt = xc20pSeal(derivePasswordKek(args.password, salt, params), nonces.pw, bk, pwAad(vaultId, seq, params));
  const rkCt = xc20pSeal(deriveRecoveryKek(args.rk), nonces.rk, bk, rkAad(vaultId, seq));
  return {
    v: 1,
    vault_id: vaultId,
    bundle_seq: seq,
    pw: { v: 1, alg: 'argon2id-xc20p', s: b64encode(salt), ...params, n: b64encode(nonces.pw), ct: b64encode(pwCt) },
    rk: { v: 1, alg: 'rk-xc20p', n: b64encode(nonces.rk), ct: b64encode(rkCt) },
    env,
  };
}

export interface OpenRecoveryBundleArgs {
  bundle: unknown;
  vaultId: string;
  /** Exactly one of `password` / `rk`. */
  password?: string;
  rk?: Uint8Array;
  /** Highest bundle_seq this client has seen; a lower one is `rollback`. */
  knownBundleSeq?: number;
}

export interface OpenedRecoveryBundle {
  bundle_seq: number;
  /** Vault keys by decimal epoch. */
  vk: Record<string, Uint8Array>;
  owner_sign_pub: string;
  recovery_sign_sk: Uint8Array;
  recovery_sign_pub: string;
  checkpoint: Checkpoint;
  /** Password params weaker than defaults: re-seal the bundle after unlock. */
  needsUpgrade: boolean;
}

/**
 * Open a recovery bundle. Order: parse wire (unsupported_version / bad_request),
 * vault match (bad_request), bundle_seq < knownBundleSeq (rollback, before any KDF),
 * unwrap BK (decrypt_failed), open env (decrypt_failed), plaintext must be canonical
 * and repeat the wire vault_id/bundle_seq (bad_request), checkpoint author must be
 * kid(owner_sign_pub) (forbidden) with a valid signature (invalid_signature).
 */
export function openRecoveryBundle(args: OpenRecoveryBundleArgs): OpenedRecoveryBundle {
  const wire = parseRecoveryBundleWire(args.bundle);
  if (wire.vault_id !== asId(args.vaultId, 'vault_id')) fail('bad_request', 'recovery bundle belongs to another vault');
  if (args.knownBundleSeq !== undefined && wire.bundle_seq < asInt(args.knownBundleSeq, 'knownBundleSeq')) fail('rollback', 'recovery bundle is older than a known one');
  if ((args.password === undefined) === (args.rk === undefined)) fail('bad_request', 'provide exactly one of password or rk');
  const seq = wire.bundle_seq;
  const bk =
    args.password !== undefined
      ? xc20pOpen(derivePasswordKek(args.password, b64decode(wire.pw.s), wire.pw), b64decode(wire.pw.n), b64decode(wire.pw.ct), pwAad(wire.vault_id, seq, wire.pw))
      : xc20pOpen(deriveRecoveryKek(args.rk!), b64decode(wire.rk.n), b64decode(wire.rk.ct), rkAad(wire.vault_id, seq));
  const plaintext = parseRecoveryBundlePlaintext(cjsonParse(openEnvelope(bk, wire.env, bundleAad(wire.vault_id, seq), BUNDLE_ENVELOPE_KID)));
  if (plaintext.vault_id !== wire.vault_id || plaintext.bundle_seq !== seq) fail('bad_request', 'recovery bundle plaintext does not match its wire header');
  checkBundleCheckpoint(plaintext.checkpoint, wire.vault_id, plaintext.owner_sign_pub);
  const recoverySk = b64decode(plaintext.recovery_sign_sk);
  const vk: Record<string, Uint8Array> = {};
  for (const [epoch, key] of Object.entries(plaintext.vk)) vk[epoch] = b64decode(key);
  return {
    bundle_seq: seq,
    vk,
    owner_sign_pub: plaintext.owner_sign_pub,
    recovery_sign_sk: recoverySk,
    recovery_sign_pub: b64encode(signKeyPairFromSeed(recoverySk).publicKey),
    checkpoint: parseCheckpoint(plaintext.checkpoint),
    needsUpgrade: args.password !== undefined && argonNeedsUpgrade(wire.pw),
  };
}

export { parseRecoveryBundleWire, parseRecoveryBundlePlaintext };
export type { RecoveryBundleWire, RecoveryBundlePlaintext };
