/** Reproduce canonical-json, kid, aead, item and wrap vectors from their inputs. */
import { describe, expect, it } from 'vitest';
import {
  assertUniqueNonces, b64decode, b64encode, cjson, cjsonParse, decodeRecoveryKey, deriveItemKey, derivePasswordKek, encodeRecoveryKey,
  itemAad, kid, kxKeyPairFromSecret, openEnvelope, openItem, parseJson, sealEnvelope, sealItem, signDetached, signKeyPairFromSeed,
  signingInput, unwrapFromDevice, unwrapWithPassword, unwrapWithRecoveryKey, utf8Decode, verifyObject, wrapToDevice, wrapWithPassword,
  wrapWithRecoveryKey, deriveRecoveryKek, x25519Shared,
} from '../src/index.js';
import { expectCode, loadVector, named, type Vec } from './helpers.js';

describe('canonical-json.json', () => {
  const v = loadVector('canonical-json.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    expect(cjson(parseJson(c.input))).toBe(c.output);
    expect(cjson(cjsonParse(c.output))).toBe(c.output);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => (c.mode === 'parse' ? cjson(parseJson(c.input)) : cjsonParse(c.input)), c.expect_error);
  });
});

describe('kid.json', () => {
  const v = loadVector('kid.json');
  it('ed25519 / x25519 keys and kids', () => {
    for (const e of v.ed25519) {
      const kp = signKeyPairFromSeed(b64decode(e.seed));
      expect(b64encode(kp.publicKey)).toBe(e.public_key);
      expect(kid(kp.publicKey)).toBe(e.kid);
    }
    for (const x of v.x25519) {
      const kp = kxKeyPairFromSecret(b64decode(x.secret));
      expect(b64encode(kp.publicKey)).toBe(x.public_key);
      expect(kid(kp.publicKey)).toBe(x.kid);
    }
  });
  it('signing input and signature', () => {
    for (const s of v.signing) {
      expect(utf8Decode(signingInput(s.context, s.object))).toBe(s.signing_input);
      expect(signDetached(s.context, s.object, b64decode(s.seed))).toBe(s.sig);
      verifyObject(s.context, { ...s.object, sig: s.sig }, s.public_key);
    }
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyObject(c.context, c.object, c.public_key), c.expect_error);
  });
});

describe('aead.json', () => {
  const v = loadVector('aead.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const key = b64decode(c.key);
    expect(cjson(c.aad)).toBe(c.aad_cjson);
    expect(sealEnvelope(key, b64decode(c.plaintext), c.aad, { kid: c.kid, nonce: b64decode(c.nonce) })).toEqual(c.envelope);
    expect(b64encode(openEnvelope(key, c.envelope, c.aad, c.kid))).toBe(c.plaintext);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    if (c.envelopes) expectCode(() => assertUniqueNonces(c.envelopes), c.expect_error);
    else expectCode(() => openEnvelope(b64decode(c.key), c.envelope, c.aad), c.expect_error);
  });
});

describe('item.json', () => {
  const v = loadVector('item.json');
  const ctx = (c: Vec) => ({ vault_id: c.vault_id, item_id: c.item_id, base_revision: c.base_revision, key_epoch: c.key_epoch, author: c.author, tombstone: c.tombstone });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const vk = b64decode(c.vk);
    expect(b64encode(deriveItemKey(vk, c.vault_id, c.item_id, c.key_epoch))).toBe(c.item_key);
    expect(cjson(itemAad(ctx(c)))).toBe(c.aad_cjson);
    expect(cjson(c.payload)).toBe(c.plaintext);
    expect(sealItem({ ...ctx(c), vk, payload: c.payload, nonce: b64decode(c.nonce) })).toEqual(c.env);
    expect(openItem({ ...ctx(c), vk, env: c.env })).toEqual(c.payload);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => openItem({ ...ctx(c), vk: b64decode(c.vk), env: c.env }), c.expect_error);
  });
});

describe('wrap-x25519.json', () => {
  const v = loadVector('wrap-x25519.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const esk = b64decode(c.ephemeral_secret);
    expect(b64encode(x25519Shared(esk, b64decode(c.recipient.kx_pub)))).toBe(c.shared);
    const wrap = wrapToDevice({ vk: b64decode(c.vk), vaultId: c.vault_id, keyEpoch: c.key_epoch, recipient: c.recipient, ephemeralSecret: esk, nonce: b64decode(c.nonce) });
    expect(wrap).toEqual(c.wrap);
    const vk = unwrapFromDevice({ wrap: c.wrap, vaultId: c.vault_id, deviceId: c.recipient.device_id, kxSecret: b64decode(c.recipient.kx_secret) });
    expect(b64encode(vk)).toBe(c.vk);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => unwrapFromDevice({ wrap: c.wrap, vaultId: c.vault_id, deviceId: c.device_id, kxSecret: b64decode(c.kx_secret) }), c.expect_error);
  });
});

describe('wrap-password.json', () => {
  const v = loadVector('wrap-password.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const params = { t: c.t, m: c.m, p: c.p };
    expect(c.password.normalize('NFC')).toBe(c.password_nfc);
    expect(b64encode(derivePasswordKek(c.password, b64decode(c.salt), params))).toBe(c.kek);
    const wrap = wrapWithPassword({ vk: b64decode(c.vk), vaultId: c.vault_id, keyEpoch: c.key_epoch, password: c.password, params, salt: b64decode(c.salt), nonce: b64decode(c.nonce) });
    expect(wrap).toEqual(c.wrap);
    const out = unwrapWithPassword({ wrap: c.wrap, vaultId: c.vault_id, password: c.password_nfc });
    expect(b64encode(out.vk)).toBe(c.vk);
    expect(out.needsUpgrade).toBe(c.needs_upgrade);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => unwrapWithPassword({ wrap: c.wrap, vaultId: c.vault_id, password: c.password }), c.expect_error);
  });
});

describe('wrap-recovery.json', () => {
  const v = loadVector('wrap-recovery.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const rk = b64decode(c.rk);
    expect(encodeRecoveryKey(rk)).toBe(c.display);
    expect(b64encode(decodeRecoveryKey(c.display))).toBe(c.rk);
    if (!c.wrap) return;
    expect(b64encode(deriveRecoveryKek(rk))).toBe(c.kek);
    expect(wrapWithRecoveryKey({ vk: b64decode(c.vk), vaultId: c.vault_id, keyEpoch: c.key_epoch, rk, nonce: b64decode(c.nonce) })).toEqual(c.wrap);
    expect(b64encode(unwrapWithRecoveryKey({ wrap: c.wrap, vaultId: c.vault_id, rk }))).toBe(c.vk);
  });
  it('decode aliases', () => {
    for (const a of v.decode_aliases) expect(b64encode(decodeRecoveryKey(a.input))).toBe(a.rk);
  });
  it.each(named(v.invalid_display))('rejects display %s', (_n, c: Vec) => {
    expectCode(() => decodeRecoveryKey(c.display), c.expect_error);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => unwrapWithRecoveryKey({ wrap: c.wrap, vaultId: c.vault_id, rk: b64decode(c.rk) }), c.expect_error);
  });
});
