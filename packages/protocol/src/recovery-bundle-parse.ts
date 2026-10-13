/**
 * Wire types and untrusted-input parsers for the recovery bundle (spec §3.4, §11).
 *
 *   wire = {v:1, vault_id, bundle_seq, pw:<bundle pw wrap>, rk:<bundle rk wrap>, env:<envelope kid "bk">}
 *   pw   = {v:1, alg:"argon2id-xc20p", s, t, m, p, n, ct}   (wraps the 32-byte bundle key BK)
 *   rk   = {v:1, alg:"rk-xc20p", n, ct}
 *   plaintext = cjson({v:1, vault_id, bundle_seq, vk:{"<epoch>":b64}, owner_sign_pub, recovery_sign_sk, checkpoint})
 */
import { NONCE_BYTES, parseEnvelope, type Envelope } from './aead.js';
import { parseCheckpoint, type Checkpoint } from './checkpoints.js';
import { fail } from './errors.js';
import { SALT_BYTES, validateArgonParams } from './wrap-password.js';
import { asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export const BUNDLE_ENVELOPE_KID = 'bk';
export const MAX_BUNDLE_EPOCHS = 10_000;
const EPOCH_KEY = /^[1-9][0-9]{0,15}$/;

export interface BundlePasswordWrap {
  v: 1;
  alg: 'argon2id-xc20p';
  s: string;
  t: number;
  m: number;
  p: number;
  n: string;
  ct: string;
}

export interface BundleRecoveryWrap {
  v: 1;
  alg: 'rk-xc20p';
  n: string;
  ct: string;
}

export interface RecoveryBundleWire {
  v: 1;
  vault_id: string;
  bundle_seq: number;
  pw: BundlePasswordWrap;
  rk: BundleRecoveryWrap;
  env: Envelope;
}

export interface RecoveryBundlePlaintext {
  v: 1;
  vault_id: string;
  bundle_seq: number;
  /** Vault key per key epoch: decimal epoch -> b64 32-byte VK. */
  vk: Record<string, string>;
  owner_sign_pub: string;
  /** b64 32-byte Ed25519 seed of the owner recovery signing key (§3.5). */
  recovery_sign_sk: string;
  checkpoint: Checkpoint;
}

function parsePw(value: unknown, what: string): BundlePasswordWrap {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== 'argon2id-xc20p') fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 's', 't', 'm', 'p', 'n', 'ct'], what);
  const params = validateArgonParams({ t: obj['t'] as number, m: obj['m'] as number, p: obj['p'] as number });
  return { v: 1, alg: 'argon2id-xc20p', s: asB64(obj['s'], `${what}.s`, SALT_BYTES), ...params, n: asB64(obj['n'], `${what}.n`, NONCE_BYTES), ct: asB64(obj['ct'], `${what}.ct`, 48) };
}

function parseRk(value: unknown, what: string): BundleRecoveryWrap {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== 'rk-xc20p') fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'n', 'ct'], what);
  return { v: 1, alg: 'rk-xc20p', n: asB64(obj['n'], `${what}.n`, NONCE_BYTES), ct: asB64(obj['ct'], `${what}.ct`, 48) };
}

export function parseRecoveryBundleWire(value: unknown, what = 'recovery bundle'): RecoveryBundleWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'bundle_seq', 'pw', 'rk', 'env'], what);
  const env = parseEnvelope(obj['env'], `${what}.env`);
  if (env.kid !== BUNDLE_ENVELOPE_KID) fail('bad_request', `${what}.env.kid must be "${BUNDLE_ENVELOPE_KID}"`);
  return {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    bundle_seq: asInt(obj['bundle_seq'], `${what}.bundle_seq`, 1),
    pw: parsePw(obj['pw'], `${what}.pw`),
    rk: parseRk(obj['rk'], `${what}.rk`),
    env,
  };
}

/** Validate a vk map: 1..MAX_BUNDLE_EPOCHS entries, decimal epoch keys >= 1 without leading zeros, 32-byte values. */
export function parseVkMap(value: unknown, what: string): Record<string, string> {
  const obj = asObject(value, what);
  const keys = Object.keys(obj);
  if (keys.length === 0 || keys.length > MAX_BUNDLE_EPOCHS) fail('bad_request', `${what} must hold 1..${MAX_BUNDLE_EPOCHS} epochs`);
  const out: Record<string, string> = {};
  for (const key of keys) {
    if (!EPOCH_KEY.test(key) || !Number.isSafeInteger(Number(key))) fail('bad_request', `${what} has an invalid epoch key`);
    out[key] = asB64(obj[key], `${what}.${key}`, 32);
  }
  return out;
}

export function parseRecoveryBundlePlaintext(value: unknown, what = 'recovery bundle plaintext'): RecoveryBundlePlaintext {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  exactKeys(obj, ['v', 'vault_id', 'bundle_seq', 'vk', 'owner_sign_pub', 'recovery_sign_sk', 'checkpoint'], what);
  const vk = parseVkMap(obj['vk'], `${what}.vk`);
  const checkpoint = parseCheckpoint(obj['checkpoint'], `${what}.checkpoint`);
  if (vk[String(checkpoint.key_epoch)] === undefined) fail('bad_request', `${what}.vk lacks the checkpoint key_epoch`);
  return {
    v: 1,
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    bundle_seq: asInt(obj['bundle_seq'], `${what}.bundle_seq`, 1),
    vk,
    owner_sign_pub: asB64(obj['owner_sign_pub'], `${what}.owner_sign_pub`, 32),
    recovery_sign_sk: asB64(obj['recovery_sign_sk'], `${what}.recovery_sign_sk`, 32),
    checkpoint,
  };
}
