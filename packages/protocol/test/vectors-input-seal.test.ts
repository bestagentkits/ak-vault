/** Input seal vectors (spec §3.11) and the device-side key lifecycle helpers. */
import { describe, expect, it } from 'vitest';
import { b64decode, b64encode, cjson, generateInputKeyPair, kxKeyPairFromSecret, openInput, parseInputSealContext, sealInput } from '../src/index.js';
import { sealInputWithVectorValues } from '../src/input-seal.js';
import { expectCode, loadVector, named } from './helpers.js';

describe('input-seal.json', () => {
  const v = loadVector('input-seal.json');
  const secret = b64decode(v.input_secret);
  it('input_pub is the public half of input_secret', () => expect(b64encode(kxKeyPairFromSecret(secret).publicKey)).toBe(v.input_pub));
  it.each(named(v.cases))('reproduces and opens %s', (_n, c) => {
    const wire = sealInputWithVectorValues(v.input_pub, c.context, c.payload, { ephemeralSecret: b64decode(c.ephemeral_secret), nonce: b64decode(c.wire.n) });
    expect(wire).toEqual(c.wire);
    expect(cjson(c.payload)).toBe(c.plaintext);
    expect(openInput(secret, c.wire, c.context)).toEqual(c.payload);
  });
  it.each(named(v.invalid))('refuses to open %s', (_n, c) => {
    const wire = c.ct_zero_bytes === undefined ? c.wire : { ...c.wire, ct: b64encode(new Uint8Array(c.ct_zero_bytes)) };
    expectCode(() => openInput(b64decode(c.input_secret), wire, c.context), c.expect_error);
  });
  it.each(named(v.seal_invalid))('refuses to seal %s', (_n, c) => {
    const payload = c.value_fill === undefined ? c.payload : { ...c.payload, value: c.value_fill.repeat(c.value_length) };
    expectCode(() => sealInput(v.input_pub, c.context, payload), c.expect_error);
  });
  it('fresh key pairs and seals differ and open', () => {
    const ctx = v.cases[0].context;
    const a = generateInputKeyPair();
    const b = generateInputKeyPair();
    expect(b64encode(a.publicKey)).not.toBe(b64encode(b.publicKey));
    const s1 = sealInput(a.publicKey, ctx, { value: 'x' });
    const s2 = sealInput(a.publicKey, ctx, { value: 'x' });
    expect(s1.epk).not.toBe(s2.epk);
    expect(s1.n).not.toBe(s2.n);
    expect(openInput(a.secretKey, s1, ctx)).toEqual({ value: 'x' });
    expectCode(() => openInput(b.secretKey, s1, ctx), 'decrypt_failed');
  });
  it('refuses a short input_pub and a malformed context', () => {
    const ctx = v.cases[0].context;
    expectCode(() => sealInput(new Uint8Array(31), ctx, { value: 'x' }), 'bad_request');
    expectCode(() => parseInputSealContext({ ...ctx, purpose: undefined }), 'bad_request');
    expectCode(() => openInput(secret, v.cases[0].wire, { ...ctx, account: '' }), 'bad_request');
  });
  it('freezes the opened payload', () => expect(Object.isFrozen(openInput(secret, v.cases[0].wire, v.cases[0].context))).toBe(true));
});
