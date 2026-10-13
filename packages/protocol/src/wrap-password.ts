/**
 * Password wrap `argon2id-xc20p` (spec §3.4):
 *   KEK_pw = Argon2id(NFC(password), salt16, t, m KiB, p, L=32)
 *   aad    = {ctx:"akv1/pw-wrap", vault_id, key_epoch, t, m, p}
 * Parameters are validated BEFORE any KDF work, so a malicious server cannot
 * downgrade (t<2, m<19456, p<1) or exhaust the client (m>1048576, t>10, p>16).
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { b64decode, b64encode } from './base64url.js';
import { randomBytes, utf8Encode } from './bytes.js';
import { NONCE_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { fail } from './errors.js';
import { asB64, asId, asInt, asObject, checkVersion, exactKeys } from './validate.js';

export interface ArgonParams {
  t: number;
  m: number;
  p: number;
}

export const ARGON2_DEFAULTS: Readonly<ArgonParams> = { t: 3, m: 65_536, p: 1 };
export const ARGON2_BOUNDS = { tMin: 2, tMax: 10, mMin: 19_456, mMax: 1_048_576, pMin: 1, pMax: 16 } as const;
export const SALT_BYTES = 16;

export interface PasswordWrap {
  v: 1;
  alg: 'argon2id-xc20p';
  key_epoch: number;
  s: string;
  t: number;
  m: number;
  p: number;
  n: string;
  ct: string;
}

/** Throws `bad_request` if parameters are outside the accepted bounds. */
export function validateArgonParams(params: ArgonParams): ArgonParams {
  const b = ARGON2_BOUNDS;
  return {
    t: asInt(params.t, 'argon2 t', b.tMin, b.tMax),
    m: asInt(params.m, 'argon2 m', b.mMin, b.mMax),
    p: asInt(params.p, 'argon2 p', b.pMin, b.pMax),
  };
}

/** True when params are weaker than current defaults (client should re-wrap after unlock). */
export function argonNeedsUpgrade(params: ArgonParams): boolean {
  return params.t < ARGON2_DEFAULTS.t || params.m < ARGON2_DEFAULTS.m || params.p < ARGON2_DEFAULTS.p;
}

export function derivePasswordKek(password: string, salt: Uint8Array, params: ArgonParams): Uint8Array {
  if (typeof password !== 'string' || password.length === 0) fail('bad_request', 'password must be a non-empty string');
  if (salt.length !== SALT_BYTES) fail('bad_request', 'salt must be 16 bytes');
  const { t, m, p } = validateArgonParams(params);
  return argon2id(utf8Encode(password.normalize('NFC')), salt, { t, m, p, dkLen: 32 });
}

function pwAad(vaultId: string, keyEpoch: number, params: ArgonParams): object {
  return { ctx: 'akv1/pw-wrap', vault_id: vaultId, key_epoch: keyEpoch, t: params.t, m: params.m, p: params.p };
}

export function parsePasswordWrap(value: unknown, what = 'password wrap'): PasswordWrap {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== 'argon2id-xc20p') fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'key_epoch', 's', 't', 'm', 'p', 'n', 'ct'], what);
  const params = validateArgonParams({ t: obj['t'] as number, m: obj['m'] as number, p: obj['p'] as number });
  return {
    v: 1,
    alg: 'argon2id-xc20p',
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    s: asB64(obj['s'], `${what}.s`, SALT_BYTES),
    ...params,
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct: asB64(obj['ct'], `${what}.ct`, 48),
  };
}

export interface WrapWithPasswordArgs {
  vk: Uint8Array;
  vaultId: string;
  keyEpoch: number;
  password: string;
  params?: ArgonParams;
  /** Inject fixed salt / nonce (test vectors only). */
  salt?: Uint8Array;
  nonce?: Uint8Array;
}

export function wrapWithPassword(args: WrapWithPasswordArgs): PasswordWrap {
  if (args.vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  const params = validateArgonParams(args.params ?? ARGON2_DEFAULTS);
  const vaultId = asId(args.vaultId, 'vault_id');
  const keyEpoch = asInt(args.keyEpoch, 'key_epoch', 1);
  const salt = args.salt ?? randomBytes(SALT_BYTES);
  const nonce = args.nonce ?? randomBytes(NONCE_BYTES);
  const kek = derivePasswordKek(args.password, salt, params);
  const ct = xc20pSeal(kek, nonce, args.vk, pwAad(vaultId, keyEpoch, params));
  return { v: 1, alg: 'argon2id-xc20p', key_epoch: keyEpoch, s: b64encode(salt), ...params, n: b64encode(nonce), ct: b64encode(ct) };
}

export interface UnwrapWithPasswordArgs {
  wrap: unknown;
  vaultId: string;
  password: string;
}

/** Recover VK[e]; `needsUpgrade` signals a parameter upgrade (re-wrap with defaults). */
export function unwrapWithPassword(args: UnwrapWithPasswordArgs): { vk: Uint8Array; needsUpgrade: boolean } {
  const wrap = parsePasswordWrap(args.wrap);
  const kek = derivePasswordKek(args.password, b64decode(wrap.s), wrap);
  const vk = xc20pOpen(kek, b64decode(wrap.n), b64decode(wrap.ct), pwAad(asId(args.vaultId, 'vault_id'), wrap.key_epoch, wrap));
  return { vk, needsUpgrade: argonNeedsUpgrade(wrap) };
}
