/**
 * Write intents `x25519-xc20p-seal` (spec §3.8): the target of a human-entered write
 * that an MCP client requested, encrypted to the epoch's seal public key so the
 * Worker never stores the secret name. An enrolled browser device opens it with
 * `SealSK[e]` to show the person what they are about to write.
 *
 *   shared   = X25519(esk, seal_pub[e])                ; all-zero output rejected
 *   key      = HKDF(ikm=shared, salt=epk || seal_pub[e], info=utf8("akv1/write-intent"), L=32)
 *   aad      = {ctx:"akv1/write-intent", vault_id, request_id, key_epoch, origin, operation, ts, expires_at}
 *   ct       = XC20P(key, n, cjson({name, purpose?, sensitivity?}), aad)
 *
 * The plaintext carries no secret value: the value is typed into the dashboard
 * form and never reaches the AI client or the Worker in the clear.
 */
import { b64decode, b64encode } from './base64url.js';
import { concatBytes, randomBytes, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse } from './canonical-json.js';
import { NONCE_BYTES, TAG_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { SENSITIVITIES, type Sensitivity } from './item.js';
import { MAX_ITEM_NAME, parseSealedOrigin, type SealedOrigin } from './sealed-op.js';
import { kxKeyPairFromSecret } from './signing.js';
import { asB64, asEnum, asId, asInt, asObject, asString, checkVersion, exactKeys } from './validate.js';
import { x25519Shared } from './wrap-x25519.js';

export const WRITE_INTENT_ALG = 'x25519-xc20p-seal';
export const WRITE_INTENT_OPERATIONS = ['create', 'replace'] as const;
export type WriteIntentOperation = (typeof WRITE_INTENT_OPERATIONS)[number];
/** Max UTF-16 code units of the optional purpose shown on the form. */
export const MAX_WRITE_PURPOSE = 200;
/** Max plaintext bytes of an intent (name and purpose only). */
const MAX_INTENT_PLAINTEXT_BYTES = 16_384;

export interface WriteIntentTarget {
  name: string;
  purpose?: string;
  sensitivity?: Sensitivity;
}

export interface WriteIntentWire {
  v: 1;
  alg: typeof WRITE_INTENT_ALG;
  request_id: string;
  vault_id: string;
  key_epoch: number;
  epk: string;
  n: string;
  ct: string;
  origin: SealedOrigin;
  operation: WriteIntentOperation;
  /** Unix ms. */
  ts: number;
  /** Unix ms; the request is refused after this instant. */
  expires_at: number;
}

const INFO = utf8Encode('akv1/write-intent');

/** Validate a (decrypted or to-be-sealed) intent target. */
export function parseWriteIntentTarget(value: unknown, what = 'write intent'): WriteIntentTarget {
  const obj = asObject(value, what);
  exactKeys(obj, ['name'], what, ['purpose', 'sensitivity']);
  const out: WriteIntentTarget = { name: asString(obj['name'], `${what}.name`, MAX_ITEM_NAME, 1) };
  if (obj['purpose'] !== undefined) out.purpose = asString(obj['purpose'], `${what}.purpose`, MAX_WRITE_PURPOSE, 1);
  if (obj['sensitivity'] !== undefined) out.sensitivity = asEnum(obj['sensitivity'], SENSITIVITIES, `${what}.sensitivity`);
  return out;
}

/** Structural parse of an untrusted write-intent wire object. */
export function parseWriteIntent(value: unknown, what = 'write intent'): WriteIntentWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== WRITE_INTENT_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'request_id', 'vault_id', 'key_epoch', 'epk', 'n', 'ct', 'origin', 'operation', 'ts', 'expires_at'], what);
  const ct = asB64(obj['ct'], `${what}.ct`);
  const ctLength = b64decode(ct).length;
  if (ctLength < TAG_BYTES || ctLength > MAX_INTENT_PLAINTEXT_BYTES + TAG_BYTES) fail('bad_request', `${what}.ct length out of range`);
  const ts = asInt(obj['ts'], `${what}.ts`);
  const expiresAt = asInt(obj['expires_at'], `${what}.expires_at`);
  if (expiresAt <= ts) fail('bad_request', `${what}.expires_at must be after ts`);
  return {
    v: 1,
    alg: WRITE_INTENT_ALG,
    request_id: asId(obj['request_id'], `${what}.request_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    epk: asB64(obj['epk'], `${what}.epk`, 32),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct,
    origin: parseSealedOrigin(obj['origin'], `${what}.origin`),
    operation: asEnum(obj['operation'], WRITE_INTENT_OPERATIONS, `${what}.operation`),
    ts,
    expires_at: expiresAt,
  };
}

type Header = Pick<WriteIntentWire, 'vault_id' | 'request_id' | 'key_epoch' | 'origin' | 'operation' | 'ts' | 'expires_at'>;

function intentAad(w: Header): object {
  return {
    ctx: 'akv1/write-intent',
    vault_id: w.vault_id,
    request_id: w.request_id,
    key_epoch: w.key_epoch,
    origin: w.origin,
    operation: w.operation,
    ts: w.ts,
    expires_at: w.expires_at,
  };
}

export interface SealWriteIntentArgs {
  vaultId: string;
  keyEpoch: number;
  origin: SealedOrigin;
  operation: WriteIntentOperation;
  /** Unix ms. */
  ts: number;
  /** Unix ms; after `ts`. */
  expiresAt: number;
  target: WriteIntentTarget;
}

/** Fixed values for test vectors only (see `SealOpVectorValues`); not re-exported from the package index. */
export interface WriteIntentVectorValues {
  requestId?: string;
  ephemeralSecret?: Uint8Array;
  nonce?: Uint8Array;
}

/** Seal `args.target` to `seal_pub[keyEpoch]` (b64 or raw 32 bytes) with a fresh ID, ephemeral key and nonce. */
export function sealWriteIntent(sealPub: string | Uint8Array, args: SealWriteIntentArgs): WriteIntentWire {
  return sealWriteIntentWithVectorValues(sealPub, args, {});
}

/** `sealWriteIntent` with injected values (test vectors only); random where omitted. */
export function sealWriteIntentWithVectorValues(sealPub: string | Uint8Array, args: SealWriteIntentArgs, fixed: WriteIntentVectorValues): WriteIntentWire {
  const pub = typeof sealPub === 'string' ? b64decode(sealPub) : sealPub;
  if (!(pub instanceof Uint8Array) || pub.length !== 32) fail('bad_request', 'seal_pub must be 32 bytes');
  const target = parseWriteIntentTarget(args.target);
  const header: Header = {
    vault_id: asId(args.vaultId, 'vault_id'),
    request_id: asId(fixed.requestId ?? b64encode(randomBytes(16)), 'request_id'),
    key_epoch: asInt(args.keyEpoch, 'key_epoch', 1),
    origin: parseSealedOrigin(args.origin),
    operation: asEnum(args.operation, WRITE_INTENT_OPERATIONS, 'operation'),
    ts: asInt(args.ts, 'ts'),
    expires_at: asInt(args.expiresAt, 'expires_at'),
  };
  if (header.expires_at <= header.ts) fail('bad_request', 'expires_at must be after ts');
  const esk = fixed.ephemeralSecret ?? randomBytes(32);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, pub), concatBytes(epk, pub), INFO);
  const nonce = fixed.nonce ?? randomBytes(NONCE_BYTES);
  const plaintext = cjsonBytes(target);
  if (plaintext.length > MAX_INTENT_PLAINTEXT_BYTES) fail('bad_request', 'write intent target too large');
  const ct = xc20pSeal(key, nonce, plaintext, intentAad(header));
  return { v: 1, alg: WRITE_INTENT_ALG, ...header, epk: b64encode(epk), n: b64encode(nonce), ct: b64encode(ct) };
}

export interface OpenedWriteIntent {
  readonly wire: Readonly<WriteIntentWire>;
  readonly target: WriteIntentTarget;
}

/**
 * Open a write intent with `SealSK[wire.key_epoch]`. Order (spec §3.8): parse
 * (`unsupported_version` / `bad_request`); `vault_id` ≠ expected (`bad_request`);
 * all-zero shared secret (`bad_request`); AEAD failure (`decrypt_failed`);
 * non-canonical or invalid target (`bad_request`).
 */
export function openWriteIntent(sealSecret: Uint8Array, value: unknown, opts: { vaultId: string }): OpenedWriteIntent {
  const wire = parseWriteIntent(value);
  if (wire.vault_id !== opts.vaultId) fail('bad_request', 'write intent belongs to another vault');
  const sealPub = kxKeyPairFromSecret(sealSecret).publicKey;
  const epk = b64decode(wire.epk);
  const key = hkdf32(x25519Shared(sealSecret, epk), concatBytes(epk, sealPub), INFO);
  const pt = xc20pOpen(key, b64decode(wire.n), b64decode(wire.ct), intentAad(wire));
  const target = Object.freeze(parseWriteIntentTarget(cjsonParse(pt)));
  Object.freeze(wire.origin);
  return Object.freeze({ wire: Object.freeze(wire), target });
}
