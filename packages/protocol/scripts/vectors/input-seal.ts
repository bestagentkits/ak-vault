/** input-seal.json */
import { cjson, kxKeyPairFromSecret, openInput, x25519Shared, type InputSealContext, type InputSealPayload, type InputSealWire } from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { concatBytes, utf8Encode } from '../../src/bytes.js';
import { hkdf32 } from '../../src/hkdf.js';
import { sealInputWithVectorValues } from '../../src/input-seal.js';
import { alicePhone, b64, BASE_TS, flipByte, id, negative, nonce, seed, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';

const TTL_MS = 600_000;
const inputPair = kxKeyPairFromSecret(seed('input-seal/input-secret'));
const otherPair = kxKeyPairFromSecret(seed('input-seal/other-input-secret'));

const CONTEXT: InputSealContext = {
  request_id: id('input-seal/request'),
  vault_id: VAULT_SHARED,
  account: 'acct_alice',
  device_id: alicePhone.record.device_id,
  name: 'STRIPE_SECRET_KEY',
  purpose: 'Billing service',
  operation: 'create',
  expires_at: BASE_TS + 3_600_000 + TTL_MS,
};

/** Encrypt an arbitrary plaintext as sealInput would, with an overridable HKDF info and AAD ctx (negative vectors). */
function rawSeal(ctx: InputSealContext, plaintext: Uint8Array, label: string, info = 'akv1/input-seal', aadCtx = 'akv1/input-seal'): InputSealWire {
  const esk = seed(`input-seal/esk/${label}`);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, inputPair.publicKey), concatBytes(epk, inputPair.publicKey), utf8Encode(info));
  const aad = { ctx: aadCtx, request_id: ctx.request_id, vault_id: ctx.vault_id, account: ctx.account, device_id: ctx.device_id, name: ctx.name, purpose: ctx.purpose, operation: ctx.operation, expires_at: ctx.expires_at };
  const n = nonce(`input-seal/${label}`);
  return { v: 1, alg: 'x25519-xc20p-input', request_id: ctx.request_id, epk: b64(epk), n: b64(n), ct: b64(xc20pSeal(key, n, plaintext, aad)) };
}

export function inputSealVectors(): Record<string, unknown> {
  const seal = (label: string, ctx: InputSealContext, payload: InputSealPayload) =>
    sealInputWithVectorValues(inputPair.publicKey, ctx, payload, { ephemeralSecret: seed(`input-seal/esk/${label}`), nonce: nonce(`input-seal/${label}`) });
  const ok = (name: string, ctx: InputSealContext, payload: InputSealPayload) => {
    const wire = seal(name, ctx, payload);
    const opened = openInput(inputPair.secretKey, wire, ctx);
    if (cjson(opened) !== cjson(payload)) throw new Error(`input-seal ${name}: round trip mismatch`);
    return { name, ephemeral_secret: b64(seed(`input-seal/esk/${name}`)), context: ctx, payload, plaintext: cjson(payload), wire };
  };
  const bad = (name: string, code: string, wire: unknown, ctx: InputSealContext = CONTEXT, secret = inputPair.secretKey, extra: Record<string, unknown> = {}) =>
    negative(name, code, { input_secret: b64(secret), context: ctx, wire, ...extra }, () => openInput(secret, wire, ctx));
  const sealBad = (name: string, code: string, ctx: unknown, payload: unknown, extra: Record<string, unknown> = {}) =>
    negative(name, code, { context: ctx, payload, ...extra }, () => sealInputWithVectorValues(inputPair.publicKey, ctx as InputSealContext, payload as InputSealPayload, {}));

  const base = ok('create', CONTEXT, { value: 'sk_test_synthetic_value_1', sensitivity: 'high' });
  const w = base.wire;
  const pt = (s: string) => utf8Encode(s);
  const otherRequest = id('input-seal/other-request');
  const bigValue = 'v'.repeat(65_536);
  return {
    version: 1,
    description:
      'Input seals x25519-xc20p-input (spec §3.11, ADR 0004): a secret value typed into the /input form, sealed to the one-time input_pub that one online device issued for one input request. ' +
      'epk = X25519(ephemeral_secret, 9); shared = X25519(ephemeral_secret, input_pub) (all-zero: bad_request); key = HKDF-SHA256(ikm=shared, salt=epk || input_pub, info=utf8("akv1/input-seal"), L=32); ' +
      'aad = cjson({"ctx":"akv1/input-seal","request_id","vault_id","account","device_id","name","purpose" (null when absent),"operation","expires_at"}) from context; ct = XChaCha20-Poly1305(key, n, cjson(payload), aad); payload = {"value", "sensitivity"?}. ' +
      'cases: sealInput(input_pub, context, payload) with the given ephemeral_secret and nonce wire.n MUST reproduce wire byte for byte, and openInput(input_secret, wire, context) MUST yield payload. ' +
      'openInput order: parse (v or alg unknown: unsupported_version; exact keys, request_id ID, epk 32 B, n 24 B, ct 16..65552 B: bad_request); wire.request_id other than context.request_id (bad_request); all-zero shared secret (bad_request); AEAD failure (decrypt_failed); pt not canonical, no value, unknown keys, value not a string or over 65536 UTF-16 code units, unknown sensitivity (bad_request). ' +
      'invalid: openInput(input_secret, wire, context) MUST fail with expect_error; a case with ct_zero_bytes replaces wire.ct with that many zero bytes. seal_invalid: sealInput MUST refuse context and payload with expect_error; value_fill sets payload.value to value_fill repeated value_length times.',
    input_secret: b64(inputPair.secretKey),
    input_pub: b64(inputPair.publicKey),
    cases: [
      base,
      ok('purpose_null', { ...CONTEXT, request_id: id('input-seal/request/2'), purpose: null }, { value: 'Grüße synthetic' }),
      ok('replace_empty_value', { ...CONTEXT, request_id: id('input-seal/request/3'), operation: 'replace', name: 'OLD_TOKEN' }, { value: '' }),
    ],
    invalid: [
      bad('wrong_input_key', 'decrypt_failed', w, CONTEXT, otherPair.secretKey),
      bad('moved_to_other_request', 'decrypt_failed', { ...w, request_id: otherRequest }, { ...CONTEXT, request_id: otherRequest }),
      bad('other_vault', 'decrypt_failed', w, { ...CONTEXT, vault_id: VAULT_PERSONAL }),
      bad('other_account', 'decrypt_failed', w, { ...CONTEXT, account: 'acct_bob' }),
      bad('other_device', 'decrypt_failed', w, { ...CONTEXT, device_id: id('input-seal/other-device') }),
      bad('other_name', 'decrypt_failed', w, { ...CONTEXT, name: 'OTHER_SECRET' }),
      bad('other_purpose', 'decrypt_failed', w, { ...CONTEXT, purpose: 'Something else' }),
      bad('purpose_null_vs_set', 'decrypt_failed', w, { ...CONTEXT, purpose: null }),
      bad('other_operation', 'decrypt_failed', w, { ...CONTEXT, operation: 'replace' }),
      bad('other_expires_at', 'decrypt_failed', w, { ...CONTEXT, expires_at: CONTEXT.expires_at + 1 }),
      bad('tampered_ct', 'decrypt_failed', { ...w, ct: flipByte(w.ct, 3) }),
      bad('tampered_epk', 'decrypt_failed', { ...w, epk: flipByte(w.epk, 1) }),
      bad('write_intent_info', 'decrypt_failed', rawSeal(CONTEXT, pt('{"value":"v"}'), 'write_intent_info', 'akv1/write-intent')),
      bad('write_intent_ctx', 'decrypt_failed', rawSeal(CONTEXT, pt('{"value":"v"}'), 'write_intent_ctx', 'akv1/input-seal', 'akv1/write-intent')),
      bad('request_id_mismatch', 'bad_request', { ...w, request_id: otherRequest }),
      bad('zero_epk', 'bad_request', { ...w, epk: b64(new Uint8Array(32)) }),
      bad('extra_wire_key', 'bad_request', { ...w, note: 'x' }),
      bad('missing_wire_key', 'bad_request', { v: w.v, alg: w.alg, request_id: w.request_id, epk: w.epk, n: w.n }),
      bad('short_epk', 'bad_request', { ...w, epk: b64(new Uint8Array(31).fill(9)) }),
      bad('short_nonce', 'bad_request', { ...w, n: b64(new Uint8Array(23)) }),
      bad('short_ct', 'bad_request', { ...w, ct: b64(new Uint8Array(15)) }),
      negative('long_ct', 'bad_request', { input_secret: b64(inputPair.secretKey), context: CONTEXT, wire: w, ct_zero_bytes: 65_553 }, () =>
        openInput(inputPair.secretKey, { ...w, ct: b64(new Uint8Array(65_553)) }, CONTEXT),
      ),
      bad('unknown_alg', 'unsupported_version', { ...w, alg: 'x25519-xc20p-seal' }),
      bad('version_2', 'unsupported_version', { ...w, v: 2 }),
      bad('non_canonical_pt', 'bad_request', rawSeal(CONTEXT, pt('{"value":"v","sensitivity":"high"}'), 'non_canonical_pt')),
      bad('extra_pt_key', 'bad_request', rawSeal(CONTEXT, pt('{"name":"A","value":"v"}'), 'extra_pt_key')),
      bad('missing_value', 'bad_request', rawSeal(CONTEXT, pt('{"sensitivity":"high"}'), 'missing_value')),
      bad('value_not_string', 'bad_request', rawSeal(CONTEXT, pt('{"value":1}'), 'value_not_string')),
      bad('unknown_sensitivity', 'bad_request', rawSeal(CONTEXT, pt('{"sensitivity":"low","value":"v"}'), 'unknown_sensitivity')),
    ],
    seal_invalid: [
      sealBad('empty_name', 'bad_request', { ...CONTEXT, name: '' }, { value: 'v' }),
      sealBad('empty_purpose', 'bad_request', { ...CONTEXT, purpose: '' }, { value: 'v' }),
      sealBad('purpose_too_long', 'bad_request', { ...CONTEXT, purpose: 'p'.repeat(201) }, { value: 'v' }),
      sealBad('unknown_operation', 'bad_request', { ...CONTEXT, operation: 'delete' }, { value: 'v' }),
      sealBad('context_extra_key', 'bad_request', { ...CONTEXT, ts: 1 }, { value: 'v' }),
      sealBad('payload_extra_key', 'bad_request', CONTEXT, { value: 'v', name: 'A' }),
      negative('plaintext_too_large', 'bad_request', { context: CONTEXT, payload: {}, value_fill: 'v', value_length: bigValue.length }, () =>
        sealInputWithVectorValues(inputPair.publicKey, CONTEXT, { value: bigValue }, {}),
      ),
    ],
  };
}
