/**
 * Input seals `x25519-xc20p-input` (spec §3.11): a secret value typed into the
 * `/input` form, sealed to a one-time X25519 key that a single online device holds in
 * memory for one input request (ADR 0004). The device rebuilds the AAD from what it
 * recorded when it issued the key, so a seal moved to another request, device,
 * account or name never opens.
 *
 *   shared   = X25519(esk, input_pub)                   ; all-zero output rejected
 *   key      = HKDF(ikm=shared, salt=epk || input_pub, info=utf8("akv1/input-seal"), L=32)
 *   aad      = {ctx:"akv1/input-seal", request_id, vault_id, account, device_id, name, purpose|null, operation, expires_at}
 *   ct       = XC20P(key, n, cjson({value, sensitivity?}), aad)
 */
import { b64decode, b64encode } from './base64url.js';
import { concatBytes, randomBytes, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse } from './canonical-json.js';
import { MAX_PLAINTEXT_BYTES, NONCE_BYTES, TAG_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { SENSITIVITIES, type Sensitivity } from './item.js';
import { MAX_ACCOUNT_LENGTH } from './membership-types.js';
import { MAX_ITEM_NAME, MAX_ITEM_VALUE } from './sealed-op.js';
import { kxKeyPairFromSecret } from './signing.js';
import { asB64, asEnum, asId, asInt, asObject, asString, asWellFormed, checkVersion, exactKeys } from './validate.js';
import { MAX_WRITE_PURPOSE, WRITE_INTENT_OPERATIONS, type WriteIntentOperation } from './write-intent.js';
import { x25519Shared } from './wrap-x25519.js';

export const INPUT_SEAL_ALG = 'x25519-xc20p-input';

/** What the device recorded when it issued the input key; every field is bound by the AAD. */
export interface InputSealContext {
  request_id: string;
  vault_id: string;
  account: string;
  device_id: string;
  name: string;
  purpose: string | null;
  operation: WriteIntentOperation;
  /** Unix ms. */
  expires_at: number;
}

/** The sealed plaintext: the typed value and an optional sensitivity. */
export interface InputSealPayload {
  value: string;
  sensitivity?: Sensitivity;
}

export interface InputSealWire {
  v: 1;
  alg: typeof INPUT_SEAL_ALG;
  request_id: string;
  epk: string;
  n: string;
  ct: string;
}

const INFO = utf8Encode('akv1/input-seal');

/** Validate an input-seal context (exact keys; `purpose` is `null` or 1..200). */
export function parseInputSealContext(value: unknown, what = 'input seal context'): InputSealContext {
  const obj = asObject(value, what);
  exactKeys(obj, ['request_id', 'vault_id', 'account', 'device_id', 'name', 'purpose', 'operation', 'expires_at'], what);
  return {
    request_id: asId(obj['request_id'], `${what}.request_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    device_id: asId(obj['device_id'], `${what}.device_id`),
    name: asString(obj['name'], `${what}.name`, MAX_ITEM_NAME, 1),
    purpose: obj['purpose'] === null ? null : asString(obj['purpose'], `${what}.purpose`, MAX_WRITE_PURPOSE, 1),
    operation: asEnum(obj['operation'], WRITE_INTENT_OPERATIONS, `${what}.operation`),
    expires_at: asInt(obj['expires_at'], `${what}.expires_at`),
  };
}

/** Validate a (decrypted or to-be-sealed) payload: exact keys `value` and optional `sensitivity`. */
export function parseInputSealPayload(value: unknown, what = 'input seal payload'): InputSealPayload {
  const obj = asObject(value, what);
  exactKeys(obj, ['value'], what, ['sensitivity']);
  const out: InputSealPayload = { value: asWellFormed(asString(obj['value'], `${what}.value`, MAX_ITEM_VALUE), `${what}.value`) };
  if (obj['sensitivity'] !== undefined) out.sensitivity = asEnum(obj['sensitivity'], SENSITIVITIES, `${what}.sensitivity`);
  return out;
}

/** Structural parse of an untrusted input-seal wire object. */
export function parseInputSeal(value: unknown, what = 'input seal'): InputSealWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== INPUT_SEAL_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'request_id', 'epk', 'n', 'ct'], what);
  const ct = asB64(obj['ct'], `${what}.ct`);
  const ctLength = b64decode(ct).length;
  if (ctLength < TAG_BYTES || ctLength > MAX_PLAINTEXT_BYTES + TAG_BYTES) fail('bad_request', `${what}.ct length out of range`);
  return {
    v: 1,
    alg: INPUT_SEAL_ALG,
    request_id: asId(obj['request_id'], `${what}.request_id`),
    epk: asB64(obj['epk'], `${what}.epk`, 32),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct,
  };
}

function inputAad(ctx: InputSealContext): object {
  return {
    ctx: 'akv1/input-seal',
    request_id: ctx.request_id,
    vault_id: ctx.vault_id,
    account: ctx.account,
    device_id: ctx.device_id,
    name: ctx.name,
    purpose: ctx.purpose,
    operation: ctx.operation,
    expires_at: ctx.expires_at,
  };
}

/** Fixed values for test vectors only (see `SealOpVectorValues`); not re-exported from the package index. */
export interface InputSealVectorValues {
  ephemeralSecret?: Uint8Array;
  nonce?: Uint8Array;
}

/** A fresh X25519 key pair for one input request; the device keeps the secret half in memory only. */
export function generateInputKeyPair(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  return kxKeyPairFromSecret(randomBytes(32));
}

/** Seal `payload` to `inputPub` (b64 or raw 32 bytes) under `ctx` with a fresh ephemeral key and nonce. */
export function sealInput(inputPub: string | Uint8Array, ctx: InputSealContext, payload: InputSealPayload): InputSealWire {
  return sealInputWithVectorValues(inputPub, ctx, payload, {});
}

/** `sealInput` with injected values (test vectors only); random where omitted. */
export function sealInputWithVectorValues(inputPub: string | Uint8Array, ctx: InputSealContext, payload: InputSealPayload, fixed: InputSealVectorValues): InputSealWire {
  const pub = typeof inputPub === 'string' ? b64decode(inputPub) : inputPub;
  if (!(pub instanceof Uint8Array) || pub.length !== 32) fail('bad_request', 'input_pub must be 32 bytes');
  const context = parseInputSealContext(ctx);
  const plaintext = cjsonBytes(parseInputSealPayload(payload));
  if (plaintext.length > MAX_PLAINTEXT_BYTES) fail('bad_request', 'input seal payload too large');
  const esk = fixed.ephemeralSecret ?? randomBytes(32);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, pub), concatBytes(epk, pub), INFO);
  const nonce = fixed.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(key, nonce, plaintext, inputAad(context));
  return { v: 1, alg: INPUT_SEAL_ALG, request_id: context.request_id, epk: b64encode(epk), n: b64encode(nonce), ct: b64encode(ct) };
}

/**
 * Open an input seal with the request's input secret under the context the device
 * recorded. Order (spec §3.11): parse (`unsupported_version` / `bad_request`);
 * `request_id` ≠ the context's (`bad_request`); all-zero shared secret
 * (`bad_request`); AEAD failure (`decrypt_failed`); non-canonical or invalid
 * payload (`bad_request`).
 */
export function openInput(inputSecret: Uint8Array, value: unknown, ctx: InputSealContext): InputSealPayload {
  const wire = parseInputSeal(value);
  const context = parseInputSealContext(ctx);
  if (wire.request_id !== context.request_id) fail('bad_request', 'input seal belongs to another request');
  const inputPub = kxKeyPairFromSecret(inputSecret).publicKey;
  const epk = b64decode(wire.epk);
  const key = hkdf32(x25519Shared(inputSecret, epk), concatBytes(epk, inputPub), INFO);
  const pt = xc20pOpen(key, b64decode(wire.n), b64decode(wire.ct), inputAad(context));
  return Object.freeze(parseInputSealPayload(cjsonParse(pt)));
}
