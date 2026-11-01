/**
 * Recovery kit backup `argon2id-xc20p-kit` (spec §3.12, ADR 0005): the recovery kit
 * (vault ID, account, vault origin, recovery key) encrypted on the owner's trusted
 * device under a separate backup passphrase, so the file can sit in a mailbox. The
 * file is useless without the passphrase and the passphrase is useless without the
 * file; neither one alone opens a vault or authenticates to the account.
 *
 *   K_pw  = Argon2id(NFC(passphrase), salt16, t, m KiB, p, L=32)
 *   key   = HKDF(ikm=K_pw, salt=utf8("akv1"), info=utf8("akv1/kit-backup-key"), L=32)
 *   aad   = {ctx:"akv1/kit-backup", vault_id, account, recovery_sign_pub, t, m, p}
 *   ct    = XC20P(key, n, cjson({v:1, vault_id, account, vault_origin, recovery_key}), aad)
 *   file  = {v:1, alg:"argon2id-xc20p-kit", vault_id, account, recovery_sign_pub, s, t, m, p, n, ct}
 *
 * The header fields are authenticated by the AAD and checked against what the
 * opener independently knows (the signed-in account, optionally the vault and the
 * chain's current recovery signing key). Parameters are validated BEFORE any KDF
 * work. The file is never trusted for the recovery signing key: recovery still
 * verifies the key against the membership chain (spec §3.5), so a stale or
 * substituted kit fails there too.
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { b64decode, b64encode } from './base64url.js';
import { NONCE_BYTES, TAG_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { randomBytes, utf8Decode, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse, parseJson } from './canonical-json.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { MAX_ACCOUNT_LENGTH } from './membership-types.js';
import { RECOVERY_KEY_BYTES } from './recovery-key.js';
import { SALT_BYTES } from './wrap-password.js';
import { asB64, asId, asInt, asObject, asPrintableAscii, asString, asWellFormed, checkVersion, exactKeys } from './validate.js';

export const KIT_BACKUP_ALG = 'argon2id-xc20p-kit';
export const KIT_BACKUP_ARGON2_DEFAULTS = Object.freeze({ t: 3, m: 262_144, p: 1 });
export const KIT_BACKUP_ARGON2_BOUNDS = Object.freeze({ tMin: 3, tMax: 10, mMin: 65_536, mMax: 524_288, pMin: 1, pMax: 4 });
export const KIT_BACKUP_MAX_FILE_BYTES = 4096;
export const KIT_BACKUP_MIN_PASSPHRASE_CODE_POINTS = 12;
export const KIT_BACKUP_MAX_PASSPHRASE_BYTES = 1024;
export const KIT_BACKUP_MAX_ORIGIN = 256;
// Largest valid payload: 134 bytes of structure + account (256 chars, up to 3 bytes each) + origin (256 bytes), plus the tag, rounded up.
const CIPHERTEXT_BYTES = 1280;
const GENERATED_PASSPHRASE_BYTES = 20;
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const KEY_SALT = utf8Encode('akv1');
const KEY_INFO = utf8Encode('akv1/kit-backup-key');

export interface KitBackupArgon {
  t: number;
  m: number;
  p: number;
}

/** What the kit holds; `recovery_key` is the raw 32-byte key as b64url. */
export interface KitBackupKit {
  vault_id: string;
  account: string;
  vault_origin: string;
  recovery_key: string;
}

export interface KitBackupFile extends KitBackupArgon {
  v: 1;
  alg: typeof KIT_BACKUP_ALG;
  vault_id: string;
  account: string;
  recovery_sign_pub: string;
  s: string;
  n: string;
  ct: string;
}

/** What the opener already knows. `account` is required; the rest narrow the match. */
export interface KitBackupExpected {
  account: string;
  vault_id?: string;
  recovery_sign_pub?: string;
}

export interface KitBackupSealArgs {
  kit: KitBackupKit;
  /** The chain's current recovery signing public key (b64url, 32 bytes) that this kit's recovery key belongs to. */
  recoverySignPub: string;
  passphrase: string;
  params?: KitBackupArgon;
  /** Inject a fixed salt / nonce (test vectors only). */
  salt?: Uint8Array;
  nonce?: Uint8Array;
}

/** Throws `bad_request` outside the kit-backup Argon2id bounds (checked before any KDF work). */
export function validateKitBackupParams(params: KitBackupArgon): KitBackupArgon {
  const b = KIT_BACKUP_ARGON2_BOUNDS;
  return {
    t: asInt(params.t, 'argon2 t', b.tMin, b.tMax),
    m: asInt(params.m, 'argon2 m', b.mMin, b.mMax),
    p: asInt(params.p, 'argon2 p', b.pMin, b.pMax),
  };
}

/** A fresh passphrase with 160 bits of entropy: 32 Crockford base32 symbols in 8 groups of 4, joined by "-". Enter it exactly as shown. */
export function generateBackupPassphrase(): string {
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of randomBytes(GENERATED_PASSPHRASE_BYTES)) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  return out.match(/.{4}/g)!.join('-');
}

function normalizePassphrase(passphrase: unknown, seal: boolean): Uint8Array {
  if (typeof passphrase !== 'string' || passphrase.length === 0) fail('bad_request', 'backup passphrase must be a non-empty string');
  if (passphrase.length > 3 * KIT_BACKUP_MAX_PASSPHRASE_BYTES) fail('bad_request', 'backup passphrase is too long');
  asWellFormed(passphrase, 'backup passphrase');
  const nfc = passphrase.normalize('NFC');
  const bytes = utf8Encode(nfc);
  if (bytes.length > KIT_BACKUP_MAX_PASSPHRASE_BYTES) fail('bad_request', 'backup passphrase is too long');
  if (seal && [...nfc].length < KIT_BACKUP_MIN_PASSPHRASE_CODE_POINTS) fail('bad_request', 'backup passphrase is too short');
  return bytes;
}

function deriveKey(passphrase: Uint8Array, salt: Uint8Array, params: KitBackupArgon): Uint8Array {
  const raw = argon2id(passphrase, salt, { t: params.t, m: params.m, p: params.p, dkLen: 32 });
  return hkdf32(raw, KEY_SALT, KEY_INFO);
}

interface Header extends KitBackupArgon {
  vault_id: string;
  account: string;
  recovery_sign_pub: string;
}

function aadOf(h: Header): object {
  return { ctx: 'akv1/kit-backup', vault_id: h.vault_id, account: h.account, recovery_sign_pub: h.recovery_sign_pub, t: h.t, m: h.m, p: h.p };
}

/** Validate the kit fields (exact keys; the recovery key is exactly 32 bytes). */
export function parseKitBackupKit(value: unknown, what = 'kit'): KitBackupKit {
  const obj = asObject(value, what);
  exactKeys(obj, ['vault_id', 'account', 'vault_origin', 'recovery_key'], what);
  return {
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    vault_origin: asPrintableAscii(obj['vault_origin'], `${what}.vault_origin`, KIT_BACKUP_MAX_ORIGIN, 1),
    recovery_key: asB64(obj['recovery_key'], `${what}.recovery_key`, RECOVERY_KEY_BYTES),
  };
}

/** Structural parse of an untrusted backup file object (version and algorithm fail closed; bounds checked here). */
export function parseKitBackupFile(value: unknown, what = 'kit backup'): KitBackupFile {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== KIT_BACKUP_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'vault_id', 'account', 'recovery_sign_pub', 's', 't', 'm', 'p', 'n', 'ct'], what);
  const params = validateKitBackupParams({ t: obj['t'] as number, m: obj['m'] as number, p: obj['p'] as number });
  const ct = asB64(obj['ct'], `${what}.ct`);
  const ctLength = b64decode(ct).length;
  if (ctLength < TAG_BYTES || ctLength > CIPHERTEXT_BYTES) fail('bad_request', `${what}.ct length out of range`);
  return {
    v: 1,
    alg: KIT_BACKUP_ALG,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    recovery_sign_pub: asB64(obj['recovery_sign_pub'], `${what}.recovery_sign_pub`, 32),
    s: asB64(obj['s'], `${what}.s`, SALT_BYTES),
    ...params,
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct,
  };
}

/** Encrypt `kit` into the backup file object. Serialize it with {@link kitBackupFileBytes}. */
export function sealKitBackup(args: KitBackupSealArgs): KitBackupFile {
  const kit = parseKitBackupKit(args.kit);
  const recoverySignPub = asB64(args.recoverySignPub, 'recovery_sign_pub', 32);
  const params = validateKitBackupParams(args.params ?? KIT_BACKUP_ARGON2_DEFAULTS);
  const passphrase = normalizePassphrase(args.passphrase, true);
  const salt = args.salt ?? randomBytes(SALT_BYTES);
  const nonce = args.nonce ?? randomBytes(NONCE_BYTES);
  if (salt.length !== SALT_BYTES) fail('bad_request', 'salt must be 16 bytes');
  const header: Header = { vault_id: kit.vault_id, account: kit.account, recovery_sign_pub: recoverySignPub, ...params };
  const ct = xc20pSeal(deriveKey(passphrase, salt, params), nonce, cjsonBytes({ v: 1, ...kit }), aadOf(header));
  return { v: 1, alg: KIT_BACKUP_ALG, ...header, s: b64encode(salt), n: b64encode(nonce), ct: b64encode(ct) };
}

/** The exact bytes to attach or save: canonical JSON, UTF-8, no trailing newline. */
export function kitBackupFileBytes(file: KitBackupFile): Uint8Array {
  const bytes = cjsonBytes(parseKitBackupFile(file));
  if (bytes.length > KIT_BACKUP_MAX_FILE_BYTES) fail('bad_request', 'kit backup file too large');
  return bytes;
}

/**
 * Open a backup file. Order (spec §3.12): size cap and strict JSON parse
 * (`bad_request`); structure, version, algorithm and Argon2id bounds
 * (`unsupported_version` / `bad_request`) before any KDF work; header ≠ expected
 * (`bad_request`, before any KDF work, so a file for another account never costs
 * a derivation); AEAD failure (`decrypt_failed`: wrong passphrase, tampered or
 * relabelled header); inner payload not canonical, invalid or disagreeing with the
 * header (`bad_request`). The sealer writes canonical JSON; the opener accepts any
 * JSON in the restricted data model (key order and whitespace are free, duplicate
 * keys are not) because the AAD is rebuilt from the parsed values, never from the
 * received bytes.
 */
export function openKitBackup(input: string | Uint8Array | object, passphrase: string, expected: KitBackupExpected): KitBackupKit {
  let value: unknown = input;
  if (typeof input === 'string' || input instanceof Uint8Array) {
    if (typeof input !== 'string' && input.length > KIT_BACKUP_MAX_FILE_BYTES) fail('bad_request', 'kit backup file too large');
    const text = typeof input === 'string' ? input : utf8Decode(input);
    if (text.length > KIT_BACKUP_MAX_FILE_BYTES || utf8Encode(text).length > KIT_BACKUP_MAX_FILE_BYTES) fail('bad_request', 'kit backup file too large');
    value = parseJson(text);
  }
  const file = parseKitBackupFile(value);
  const want = asObject(expected, 'expected');
  exactKeys(want, ['account'], 'expected', ['vault_id', 'recovery_sign_pub']);
  if (file.account !== asString(want['account'], 'expected.account', MAX_ACCOUNT_LENGTH, 1)) fail('bad_request', 'kit backup belongs to another account');
  if (want['vault_id'] !== undefined && file.vault_id !== asId(want['vault_id'], 'expected.vault_id')) fail('bad_request', 'kit backup belongs to another vault');
  if (want['recovery_sign_pub'] !== undefined && file.recovery_sign_pub !== asB64(want['recovery_sign_pub'], 'expected.recovery_sign_pub', 32)) {
    fail('bad_request', 'kit backup is not for the current recovery key');
  }
  const key = deriveKey(normalizePassphrase(passphrase, false), b64decode(file.s), file);
  const pt = xc20pOpen(key, b64decode(file.n), b64decode(file.ct), aadOf(file));
  const inner = asObject(cjsonParse(pt), 'kit backup payload');
  exactKeys(inner, ['v', 'vault_id', 'account', 'vault_origin', 'recovery_key'], 'kit backup payload');
  checkVersion(inner, 'kit backup payload');
  const { v: _v, ...fields } = inner;
  const kit = parseKitBackupKit(fields, 'kit backup payload');
  if (kit.vault_id !== file.vault_id || kit.account !== file.account) fail('bad_request', 'kit backup payload disagrees with its header');
  return Object.freeze(kit);
}
