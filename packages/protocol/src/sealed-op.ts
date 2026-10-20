/**
 * Sealed operations `x25519-xc20p-seal` (spec §3.6): a set or delete encrypted
 * to the epoch's seal public key, opened later by a device that holds `VK[e]`.
 *
 *   shared   = X25519(esk, seal_pub[e])                ; all-zero output rejected
 *   seal_key = HKDF(ikm=shared, salt=epk || seal_pub[e], info=utf8("akv1/seal"), L=32)
 *   aad      = {ctx:"akv1/sealed-op", vault_id, sealed_id, key_epoch, origin, ts}
 *   ct       = XC20P(seal_key, n, cjson(op), aad)
 */
import { b64decode, b64encode } from './base64url.js';
import { concatBytes, randomBytes, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse } from './canonical-json.js';
import { NONCE_BYTES, TAG_BYTES, MAX_PLAINTEXT_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { SENSITIVITIES, type Sensitivity } from './item.js';
import { MAX_ACCOUNT_LENGTH } from './membership-types.js';
import { kxKeyPairFromSecret } from './signing.js';
import { asB64, asEnum, asId, asInt, asObject, asPrintableAscii, asString, checkVersion, exactKeys } from './validate.js';
import { x25519Shared } from './wrap-x25519.js';

export const SEALED_OP_ALG = 'x25519-xc20p-seal';
export const SEALED_ORIGIN_KINDS = ['mcp'] as const;
export const SEALED_OPS = ['set', 'delete'] as const;
/** Item payload limits (UTF-16 code units, spec §3.6). */
export const MAX_ITEM_NAME = 4096;
export const MAX_ITEM_VALUE = 65_536;

export interface SealedOrigin {
  kind: (typeof SEALED_ORIGIN_KINDS)[number];
  /** MCP token `sub`, in device-record account form. */
  account: string;
  client_id: string;
  grant_id: string;
}

export type SealedOperation =
  | { op: 'set'; name: string; value: string; sensitivity?: Sensitivity }
  | { op: 'delete'; name: string };

export interface SealedOpWire {
  v: 1;
  alg: typeof SEALED_OP_ALG;
  sealed_id: string;
  vault_id: string;
  key_epoch: number;
  epk: string;
  n: string;
  ct: string;
  origin: SealedOrigin;
  ts: number;
}

const INFO = utf8Encode('akv1/seal');

export function parseSealedOrigin(value: unknown, what = 'origin'): SealedOrigin {
  const obj = asObject(value, what);
  exactKeys(obj, ['kind', 'account', 'client_id', 'grant_id'], what);
  return {
    kind: asEnum(obj['kind'], SEALED_ORIGIN_KINDS, `${what}.kind`),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    client_id: asPrintableAscii(obj['client_id'], `${what}.client_id`, 256, 1),
    grant_id: asPrintableAscii(obj['grant_id'], `${what}.grant_id`, 64, 1),
  };
}

/** Validate a (decrypted or to-be-sealed) operation object. */
export function parseSealedOperation(value: unknown, what = 'sealed operation'): SealedOperation {
  const obj = asObject(value, what);
  const op = asEnum(obj['op'], SEALED_OPS, `${what}.op`);
  const name = asString(obj['name'], `${what}.name`, MAX_ITEM_NAME, 1);
  if (op === 'delete') {
    exactKeys(obj, ['op', 'name'], what);
    return { op, name };
  }
  exactKeys(obj, ['op', 'name', 'value'], what, ['sensitivity']);
  const value_ = asString(obj['value'], `${what}.value`, MAX_ITEM_VALUE);
  if (obj['sensitivity'] === undefined) return { op, name, value: value_ };
  return { op, name, value: value_, sensitivity: asEnum(obj['sensitivity'], SENSITIVITIES, `${what}.sensitivity`) };
}

/** Structural parse of an untrusted sealed-operation wire object. */
export function parseSealedOp(value: unknown, what = 'sealed op'): SealedOpWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== SEALED_OP_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'sealed_id', 'vault_id', 'key_epoch', 'epk', 'n', 'ct', 'origin', 'ts'], what);
  const ct = asB64(obj['ct'], `${what}.ct`);
  const ctLength = b64decode(ct).length;
  if (ctLength < TAG_BYTES || ctLength > MAX_PLAINTEXT_BYTES + TAG_BYTES) fail('bad_request', `${what}.ct length out of range`);
  return {
    v: 1,
    alg: SEALED_OP_ALG,
    sealed_id: asId(obj['sealed_id'], `${what}.sealed_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    epk: asB64(obj['epk'], `${what}.epk`, 32),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct,
    origin: parseSealedOrigin(obj['origin'], `${what}.origin`),
    ts: asInt(obj['ts'], `${what}.ts`),
  };
}

function sealedAad(w: Pick<SealedOpWire, 'vault_id' | 'sealed_id' | 'key_epoch' | 'origin' | 'ts'>): object {
  return { ctx: 'akv1/sealed-op', vault_id: w.vault_id, sealed_id: w.sealed_id, key_epoch: w.key_epoch, origin: w.origin, ts: w.ts };
}

function deriveSealKey(shared: Uint8Array, epk: Uint8Array, sealPub: Uint8Array): Uint8Array {
  return hkdf32(shared, concatBytes(epk, sealPub), INFO);
}

export interface SealOpArgs {
  vaultId: string;
  keyEpoch: number;
  origin: SealedOrigin;
  /** Unix ms. */
  ts: number;
  op: SealedOperation;
}

/**
 * Fixed values for test vectors only. Reusing an ephemeral secret reuses the
 * (key, nonce) pair, so this is not re-exported from the package index.
 */
export interface SealOpVectorValues {
  sealedId?: string;
  ephemeralSecret?: Uint8Array;
  nonce?: Uint8Array;
}

/** Seal `args.op` to `seal_pub[keyEpoch]` (b64 or raw 32 bytes) with a fresh ID, ephemeral key and nonce. */
export function sealOp(sealPub: string | Uint8Array, args: SealOpArgs): SealedOpWire {
  return sealOpWithVectorValues(sealPub, args, {});
}

/** `sealOp` with injected values (test vectors only); random where omitted. */
export function sealOpWithVectorValues(sealPub: string | Uint8Array, args: SealOpArgs, fixed: SealOpVectorValues): SealedOpWire {
  const pub = typeof sealPub === 'string' ? b64decode(sealPub) : sealPub;
  if (!(pub instanceof Uint8Array) || pub.length !== 32) fail('bad_request', 'seal_pub must be 32 bytes');
  const op = parseSealedOperation(args.op);
  const header = {
    vault_id: asId(args.vaultId, 'vault_id'),
    sealed_id: asId(fixed.sealedId ?? b64encode(randomBytes(16)), 'sealed_id'),
    key_epoch: asInt(args.keyEpoch, 'key_epoch', 1),
    origin: parseSealedOrigin(args.origin),
    ts: asInt(args.ts, 'ts'),
  };
  const esk = fixed.ephemeralSecret ?? randomBytes(32);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = deriveSealKey(x25519Shared(esk, pub), epk, pub);
  const nonce = fixed.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(key, nonce, cjsonBytes(op), sealedAad(header));
  return { v: 1, alg: SEALED_OP_ALG, sealed_id: header.sealed_id, vault_id: header.vault_id, key_epoch: header.key_epoch, epk: b64encode(epk), n: b64encode(nonce), ct: b64encode(ct), origin: header.origin, ts: header.ts };
}

/**
 * The authenticated result of `openSealedOp`: the wire whose header the AEAD
 * bound and its decrypted operation, both frozen. Only `openSealedOp` produces
 * one that `checkSealedDrain` accepts.
 */
export interface OpenedSealedOp {
  readonly wire: Readonly<SealedOpWire>;
  readonly op: SealedOperation;
}

/** Results returned by `openSealedOp`; `checkSealedDrain` refuses anything else. */
const openedResults = new WeakSet<object>();

/**
 * Open a sealed operation with `SealSK[wire.key_epoch]`. Order (spec §3.6):
 * parse (`unsupported_version` / `bad_request`); `vault_id` ≠ expected
 * (`bad_request`); all-zero shared secret (`bad_request`); AEAD failure
 * (`decrypt_failed`); non-canonical or invalid operation (`bad_request`).
 */
export function openSealedOp(sealSecret: Uint8Array, value: unknown, opts: { vaultId: string }): OpenedSealedOp {
  const wire = parseSealedOp(value);
  if (wire.vault_id !== opts.vaultId) fail('bad_request', 'sealed op belongs to another vault');
  const sealPub = kxKeyPairFromSecret(sealSecret).publicKey;
  const epk = b64decode(wire.epk);
  const key = deriveSealKey(x25519Shared(sealSecret, epk), epk, sealPub);
  const pt = xc20pOpen(key, b64decode(wire.n), b64decode(wire.ct), sealedAad(wire));
  const op = Object.freeze(parseSealedOperation(cjsonParse(pt)));
  Object.freeze(wire.origin);
  const opened: OpenedSealedOp = Object.freeze({ wire: Object.freeze(wire), op });
  openedResults.add(opened);
  return opened;
}

/** How far ahead of the draining device's clock a sealed op's `ts` may be (spec §3.6). */
export const SEALED_MAX_FUTURE_MS = 300_000;

export interface SealedDrainContext {
  /** This device's account (its token `sub`, in device-record account form). */
  account: string;
  /** This device's clock, unix ms. */
  now: number;
  /** `sealed_ttl_s` from `/v1/meta`. */
  sealedTtlS: number;
  /** Whether this device already applied or refused `sealedId`. */
  seen: (sealedId: string) => boolean;
}

/**
 * Drain admission for the result of `openSealedOp` (spec §3.6 draining steps
 * 1-2), so it reads only authenticated header fields. A malformed context or a
 * value `openSealedOp` did not return is `bad_request`; then, in order:
 * `origin.account` is not this device's account (`forbidden`); the
 * `sealed_id` was already applied or refused, a replay (`conflict`); `ts`
 * more than `sealed_ttl_s` in the past or more than 300 s in the future
 * (`bad_request`). A device keeps every handled ID until `sealed_ttl_s` after
 * the later of its `ts` and the time it handled it.
 */
export function checkSealedDrain(opened: OpenedSealedOp, ctx: SealedDrainContext): void {
  const now = asInt(ctx.now, 'now');
  const ttlMs = asInt(ctx.sealedTtlS, 'sealed_ttl_s', 1, Math.floor(Number.MAX_SAFE_INTEGER / 1000)) * 1000;
  if (typeof ctx.seen !== 'function') fail('bad_request', 'sealed drain needs the seen set');
  const account = asString(ctx.account, 'account', MAX_ACCOUNT_LENGTH, 1);
  if (typeof opened !== 'object' || opened === null || !openedResults.has(opened)) {
    fail('bad_request', 'sealed drain needs an op opened by openSealedOp');
  }
  const { wire } = opened;
  if (wire.origin.account !== account) fail('forbidden', 'sealed op belongs to another account');
  if (ctx.seen(wire.sealed_id)) fail('conflict', 'sealed op already handled');
  if (now - wire.ts > ttlMs) fail('bad_request', 'sealed op expired');
  if (wire.ts - now > SEALED_MAX_FUTURE_MS) fail('bad_request', 'sealed op ts is in the future');
}
