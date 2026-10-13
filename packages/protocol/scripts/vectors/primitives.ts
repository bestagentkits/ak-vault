/** canonical-json.json, kid.json, aead.json */
import {
  assertUniqueNonces,
  cjson,
  cjsonParse,
  kid,
  openEnvelope,
  parseJson,
  sealEnvelope,
  signDetached,
  signingInput,
  signKeyPairFromSeed,
  kxKeyPairFromSecret,
  utf8Decode,
  utf8Encode,
  verifyObject,
  type JsonObject,
} from '../../src/index.js';
import { b64, flipByte, key32, negative, nonce, seed } from './fixtures.js';

const VALID_JSON: [string, string][] = [
  ['key_order', '{"b":1,"a":2,"c":{"z":true,"y":null}}'],
  ['whitespace', ' {\n "list" : [ 1 , 2 ,3 ] ,\t"s":"x" } '],
  ['empty_containers', '{"a":{},"b":[]}'],
  ['integer_bounds', '[0,9007199254740991]'],
  ['short_escapes', '"q\\"b\\\\s\\/n\\nr\\rt\\tb\\bf\\f"'],
  ['control_chars_lower_hex', '"\\u0000\\u001F\\u000b\\u007f"'],
  ['raw_unicode_not_escaped', '"<>&\\u2028\\u2029\\u00e9 é"'],
  ['surrogate_pair', '"\\ud83d\\ude00 😀"'],
  ['integer_like_keys_sorted_by_bytes', '{"1":0,"0a":1,"10":2,"9":3}'],
  ['nested_sort_byte_order', '{"a_b":1,"a":2,"a0":3,"_":4,"9":5}'],
];

const INVALID_PARSE: [string, string][] = [
  ['float', '1.5'],
  ['float_zero_fraction', '1.0'],
  ['exponent', '1e3'],
  ['negative', '-1'],
  ['too_large', '9007199254740992'],
  ['leading_zero', '01'],
  ['lone_high_surrogate', '"\\ud800"'],
  ['lone_low_surrogate', '"\\udc00x"'],
  ['duplicate_key', '{"a":1,"a":2}'],
  ['uppercase_key', '{"A":1}'],
  ['dash_key', '{"a-b":1}'],
  ['empty_key', '{"":1}'],
  ['trailing_comma', '[1,]'],
  ['trailing_data', '{} {}'],
  ['nan', 'NaN'],
  ['raw_control_char', '"a\tb"'],
];

const NON_CANONICAL: [string, string][] = [
  ['whitespace', '{"a": 1}'],
  ['unsorted_keys', '{"b":1,"a":2}'],
  ['needless_unicode_escape', '"\\u0041"'],
  ['uppercase_hex_escape', '"\\u001F"'],
  ['escaped_solidus', '"\\/"'],
  ['escaped_non_ascii', '"\\u00e9"'],
];

export function canonicalJsonVectors(): Record<string, unknown> {
  return {
    version: 1,
    description:
      'Canonical JSON (spec §2). cases: parse `input` with a strict parser (restricted grammar, any key order/whitespace) and serialize; result MUST equal `output`, and `output` MUST be accepted by the canonical-only parser. invalid[mode=parse]: the strict parser MUST reject `input`. invalid[mode=canonical]: input is valid JSON but not canonical; a canonical-only parser MUST reject it.',
    cases: VALID_JSON.map(([name, input]) => ({ name, input, output: cjson(parseJson(input)) })),
    invalid: [
      ...INVALID_PARSE.map(([name, input]) => negative(name, 'bad_request', { mode: 'parse', input }, () => cjson(parseJson(input)))),
      ...NON_CANONICAL.map(([name, input]) => negative(name, 'bad_request', { mode: 'canonical', input }, () => cjsonParse(input))),
    ],
  };
}

export function kidVectors(): Record<string, unknown> {
  const ed = ['device-a', 'device-b', 'device-c'].map((label) => {
    const kp = signKeyPairFromSeed(seed(`kid/${label}`));
    return { seed: b64(kp.secretKey), public_key: b64(kp.publicKey), kid: kid(kp.publicKey) };
  });
  const x = ['kx-a', 'kx-b'].map((label) => {
    const kp = kxKeyPairFromSecret(seed(`kid/${label}`));
    return { secret: b64(kp.secretKey), public_key: b64(kp.publicKey), kid: kid(kp.publicKey) };
  });
  const signer = signKeyPairFromSeed(seed('kid/device-a'));
  const object: JsonObject = { z: 'last', a: [1, 2], sig: 'ignored-by-signing-input', m: { b: true, a: null } };
  const signed = { ...object, sig: signDetached('akv1/record', object, signer.secretKey) };
  return {
    version: 1,
    description:
      'Key IDs and signing input (spec §2). ed25519[]: seed -> public_key (RFC 8032) and kid = device_id. x25519[]: secret -> public_key (RFC 7748) and kid. signing[]: signing_input = utf8(context)||0x0A||cjson(object minus top-level "sig") as a UTF-8 string; sig = Ed25519(seed, signing_input). invalid[]: verifying `object` under `context` with `public_key` MUST fail with expect_error.',
    ed25519: ed,
    x25519: x,
    signing: [
      { context: 'akv1/record', object, seed: b64(signer.secretKey), public_key: b64(signer.publicKey), signing_input: utf8Decode(signingInput('akv1/record', object)), sig: signed.sig },
    ],
    invalid: [
      negative('wrong_context', 'invalid_signature', { context: 'akv1/checkpoint', object: signed, public_key: b64(signer.publicKey) }, () =>
        verifyObject('akv1/checkpoint', signed, signer.publicKey),
      ),
      negative('tampered_object', 'invalid_signature', { context: 'akv1/record', object: { ...signed, z: 'changed' }, public_key: b64(signer.publicKey) }, () =>
        verifyObject('akv1/record', { ...signed, z: 'changed' }, signer.publicKey),
      ),
    ],
  };
}

export function aeadVectors(): Record<string, unknown> {
  const key = key32('aead');
  const aad: JsonObject = { ctx: 'akv1/test', vault_id: 'AAAAAAAAAAAAAAAAAAAAAA', n: 7 };
  const cases = [
    { name: 'utf8_text', plaintext: utf8Encode('hello akv1 ✓'), kid: 'e1' },
    { name: 'empty_plaintext', plaintext: new Uint8Array(0), kid: 'e1' },
    { name: 'binary_256', plaintext: Uint8Array.from({ length: 256 }, (_, i) => i), kid: 'e2' },
  ].map((c) => {
    const envelope = sealEnvelope(key, c.plaintext, aad, { kid: c.kid, nonce: nonce(`aead/${c.name}`) });
    return { name: c.name, key: b64(key), aad, aad_cjson: cjson(aad), kid: c.kid, nonce: b64(nonce(`aead/${c.name}`)), plaintext: b64(c.plaintext), envelope };
  });
  const env = cases[0]!.envelope;
  const tampered = { ...env, ct: flipByte(env.ct) };
  const open = (e: unknown, a: JsonObject = aad) => () => openEnvelope(key, e, a);
  const dupA = sealEnvelope(key, utf8Encode('first'), aad, { kid: 'e1', nonce: nonce('aead/dup') });
  const dupB = sealEnvelope(key, utf8Encode('second'), aad, { kid: 'e1', nonce: nonce('aead/dup') });
  const neg = (name: string, code: string, envelope: unknown, a: JsonObject = aad) => negative(name, code, { key: b64(key), aad: a, envelope }, open(envelope, a));
  return {
    version: 1,
    description:
      'XChaCha20-Poly1305 envelope (spec §3.1). cases: seal(key, nonce, plaintext, aad=cjson(aad)) MUST produce `envelope` exactly and open MUST return `plaintext` (b64). invalid: opening `envelope` with key and aad MUST fail with expect_error; nonce_reuse: a receiver checking `envelopes` (same key) for unique nonces MUST reject.',
    cases,
    invalid: [
      neg('tampered_ciphertext', 'decrypt_failed', tampered),
      neg('wrong_aad', 'decrypt_failed', env, { ...aad, n: 8 }),
      neg('unsupported_version', 'unsupported_version', { ...env, v: 2 }),
      neg('unknown_alg', 'unsupported_version', { ...env, alg: 'aes256gcm' }),
      neg('short_nonce', 'bad_request', { ...env, n: env.n.slice(0, 30) }),
      neg('padded_base64', 'bad_request', { ...env, n: env.n + '=' }),
      neg('extra_field', 'bad_request', { ...env, x: 1 }),
      negative('nonce_reuse', 'bad_request', { envelopes: [dupA, dupB] }, () => assertUniqueNonces([dupA, dupB])),
    ],
  };
}
