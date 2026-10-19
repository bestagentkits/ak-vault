/** Remote access vectors: seal-key, sealed-op, name-tag, enroll-codes, profile, relay-frames. */
import { describe, expect, it } from 'vitest';
import {
  b64decode,
  b64encode,
  buildProof,
  buildProofAsync,
  carryForwardMeta,
  checkProfileProvenance,
  checkSealedDrain,
  checkSealKeyDocReplace,
  cjson,
  deriveSealKeyPair,
  encodeJoinCode,
  encodeOfferCode,
  isCanonicalOrigin,
  kxKeyPairFromSecret,
  nameIndexKey,
  nameTag,
  openSealedOp,
  parseJoinCode,
  parseOfferCode,
  parseRelayFrame,
  parseSealedOp,
  parseToolArgs,
  parseToolResult,
  sealOp,
  signKeyPairFromSeed,
  signObject,
  signObjectAsync,
  signRecord,
  signRecordAsync,
  unwrapFromDevice,
  unwrapFromDeviceAsync,
  utf8Encode,
  validateProfile,
  verifyHello,
  verifyResult,
  verifySealKeyDoc,
  wrapToDevice,
  x25519Shared,
  type DeviceKx,
  type DeviceSigner,
} from '../src/index.js';
import { sealOpWithVectorValues } from '../src/sealed-op.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { expectCode, loadVector, named } from './helpers.js';

const membership = loadVector('membership.json');
const sharedChain = membership.chains[0].events;

describe('seal-key.json', () => {
  const v = loadVector('seal-key.json');
  const vkOf = (b: string | null) => (b === null ? {} : { vk: b64decode(b) });
  it.each(named(v.seal_keys.map((k: { key_epoch: number }) => ({ ...k, name: `epoch ${k.key_epoch}` }))))('derives seal key of %s', (_n, k) => {
    const pair = deriveSealKeyPair(b64decode(k.vk), v.vault_id, k.key_epoch);
    expect(b64encode(pair.secretKey)).toBe(k.seal_sk);
    expect(b64encode(pair.publicKey)).toBe(k.seal_pub);
  });
  it('another vault derives another seal key', () => {
    const o = v.other_vault_seal_pub;
    expect(b64encode(deriveSealKeyPair(b64decode(o.vk), o.vault_id, o.key_epoch).publicKey)).toBe(o.seal_pub);
    expect(o.seal_pub).not.toBe(v.seal_keys[0].seal_pub);
  });
  const pinsOf = (c: { trusted_anchor?: string; witnessed_checkpoint?: { membership_seq: number; membership_head: string } }) => ({
    ...(c.trusted_anchor === undefined ? {} : { trustedAnchor: c.trusted_anchor }),
    ...(c.witnessed_checkpoint === undefined ? {} : { witnessedCheckpoint: c.witnessed_checkpoint }),
  });
  it.each(named(v.cases))('verifies %s', (_n, c) => {
    expect(verifySealKeyDoc(c.doc, sharedChain, { vaultId: v.vault_id, ...vkOf(c.vk), ...pinsOf(c) })).toEqual(c.doc);
  });
  it.each(named(v.invalid))('refuses %s', (_n, c) => {
    expectCode(() => verifySealKeyDoc(c.doc, sharedChain, { vaultId: c.vault_id, ...vkOf(c.vk), ...pinsOf(c) }), c.expect_error);
  });
  it.each(named(v.replace_cases))('replace accepts %s', (_n, c) => expect(() => checkSealKeyDocReplace(c.stored, c.incoming)).not.toThrow());
  it.each(named(v.replace_invalid))('replace refuses %s', (_n, c) => expectCode(() => checkSealKeyDocReplace(c.stored, c.incoming), c.expect_error));
});

describe('sealed-op.json', () => {
  const v = loadVector('sealed-op.json');
  const keys = loadVector('seal-key.json').seal_keys as { key_epoch: number; seal_sk: string; seal_pub: string }[];
  const key = (e: number) => keys.find((k) => k.key_epoch === e)!;
  it.each(named(v.cases))('reproduces and opens %s', (_n, c) => {
    const wire = sealOpWithVectorValues(
      key(c.key_epoch).seal_pub,
      { vaultId: c.wire.vault_id, keyEpoch: c.key_epoch, origin: c.wire.origin, ts: c.wire.ts, op: c.op },
      { sealedId: c.wire.sealed_id, ephemeralSecret: b64decode(c.ephemeral_secret), nonce: b64decode(c.wire.n) },
    );
    expect(wire).toEqual(c.wire);
    expect(cjson(c.op)).toBe(c.plaintext);
    expect(openSealedOp(b64decode(key(c.key_epoch).seal_sk), c.wire, { vaultId: c.wire.vault_id }).op).toEqual(c.op);
  });
  it.each(named(v.invalid))('refuses to open %s', (_n, c) => {
    const wire = c.ct_zero_bytes === undefined ? c.wire : { ...c.wire, ct: b64encode(new Uint8Array(c.ct_zero_bytes)) };
    expectCode(() => openSealedOp(b64decode(key(c.open_with_epoch).seal_sk), wire, { vaultId: c.vault_id }), c.expect_error);
  });
  it.each(named(v.seal_invalid))('refuses to seal %s', (_n, c) => {
    const op = c.value_fill === undefined ? c.op : { ...c.op, value: c.value_fill.repeat(c.value_length) };
    expectCode(() => sealOp(key(3).seal_pub, { vaultId: v.cases[0].wire.vault_id, keyEpoch: 3, origin: v.origin, ts: 1, op }), c.expect_error);
  });
  it('fresh seals differ and open', () => {
    const args = { vaultId: v.cases[0].wire.vault_id, keyEpoch: 3, origin: v.origin, ts: 1, op: { op: 'delete' as const, name: 'A' } };
    const a = sealOp(key(3).seal_pub, args);
    const b = sealOp(key(3).seal_pub, args);
    expect(a.epk).not.toBe(b.epk);
    expect(a.sealed_id).not.toBe(b.sealed_id);
    expect(openSealedOp(b64decode(key(3).seal_sk), a, { vaultId: args.vaultId }).op).toEqual(args.op);
  });
  type DrainCase = { account: string; now: number; sealed_ttl_s: number; seen: string[]; expect_error?: string };
  const drain = (c: DrainCase) => () =>
    checkSealedDrain(parseSealedOp(v.drain.wire), { account: c.account, now: c.now, sealedTtlS: c.sealed_ttl_s, seen: (sid) => c.seen.includes(sid) });
  it.each(named(v.drain.cases))('drain admits %s', (_n, c) => expect(drain(c)).not.toThrow());
  it.each(named(v.drain.invalid))('drain refuses %s', (_n, c) => expectCode(drain(c), c.expect_error));
  it('drain refuses a malformed context', () => {
    const base = { ...v.drain.cases[0], seen: [] };
    expectCode(drain({ ...base, sealed_ttl_s: 0 }), 'bad_request');
    expectCode(drain({ ...base, now: -1 }), 'bad_request');
  });
});

describe('name-tag.json', () => {
  const v = loadVector('name-tag.json');
  const vks = Object.fromEntries((loadVector('seal-key.json').seal_keys as { key_epoch: number; vk: string }[]).map((k) => [k.key_epoch, b64decode(k.vk)]));
  const tagOf = (t: { name: string; key_epoch: number; vault_id: string }) => nameTag(nameIndexKey(vks[t.key_epoch]!, t.vault_id, t.key_epoch), t.name);
  it('reproduces index keys', () => {
    for (const k of v.index_keys) expect(b64encode(nameIndexKey(b64decode(k.vk), k.vault_id, k.key_epoch))).toBe(k.index_key);
  });
  it('NFC and NFD spellings share a tag', () => {
    expect(v.same_tag[0].name).not.toBe(v.same_tag[1].name);
    for (const t of v.same_tag) expect(tagOf(t)).toBe(v.same_tag[0].tag);
  });
  it('another epoch or vault gives another tag', () => {
    const tags = v.distinct_tags.map(tagOf);
    expect(tags).toEqual(v.distinct_tags.map((t: { tag: string }) => t.tag));
    expect(new Set(tags).size).toBe(tags.length);
  });
  it.each(named(v.known_answers))('known answer %s', (_n, t) => expect(tagOf(t)).toBe(t.tag));
  it('refuses empty and ill-formed names', () => {
    const k = nameIndexKey(vks[3]!, v.index_keys[1].vault_id, 3);
    expectCode(() => nameTag(k, ''), 'bad_request');
    expectCode(() => nameTag(k, String.fromCharCode(0xd800)), 'bad_request');
  });
});

describe('enroll-codes.json', () => {
  const v = loadVector('enroll-codes.json');
  it('join and offer round trip byte for byte', () => {
    expect(encodeJoinCode(v.join)).toBe(v.join_code);
    expect(parseJoinCode(v.join_code)).toEqual(v.join);
    expect(encodeOfferCode(v.offer)).toBe(v.offer_code);
    expect(parseOfferCode(v.offer_code)).toEqual(v.offer);
  });
  it('a code split by whitespace parses', () => expect(parseJoinCode(v.whitespace_split)).toEqual(v.join));
  it('origin rule', () => {
    for (const o of v.origins.canonical) expect(isCanonicalOrigin(o), o).toBe(true);
    for (const o of v.origins.non_canonical) expect(isCanonicalOrigin(o), o).toBe(false);
  });
  it.each(named(v.invalid_join))('join refuses %s', (_n, c) => expectCode(() => parseJoinCode(c.code_text), c.expect_error));
  it.each(named(v.invalid_offer))('offer refuses %s', (_n, c) => expectCode(() => parseOfferCode(c.code_text), c.expect_error));
});

describe('profile.json', () => {
  const v = loadVector('profile.json');
  it.each(named(v.cases))('provenance %s', (_n, c) => {
    const out = checkProfileProvenance(c.prev, c.next, c.record, { selfDeviceId: c.self_device_id, prevOrigins: c.prev_origins });
    expect({ profile: out.profile, dropped: out.dropped, origins: out.origins }).toEqual(c.expect);
  });
  it.each(named(v.chains))('provenance chain %s', (_n, ch) => {
    let prev = ch.start.prev;
    let prevOrigins = ch.start.prev_origins;
    for (const step of ch.steps) {
      const out = checkProfileProvenance(prev, step.next, step.record, { selfDeviceId: ch.self_device_id, prevOrigins });
      expect({ profile: out.profile, dropped: out.dropped, origins: out.origins }).toEqual(step.expect);
      prev = out.profile;
      prevOrigins = out.origins;
    }
  });
  it.each(named(v.invalid))('validateProfile refuses %s', (_n, c) => expectCode(() => validateProfile(c.profile), c.expect_error));
  it('accepts values at their limits', () => expect(validateProfile(v.valid_limits)).toEqual(v.valid_limits));
  it('carry-forward drops policy and profile spellings', () => expect(carryForwardMeta(v.carry_forward.meta)).toEqual(v.carry_forward.expect));
});

describe('relay-frames.json', () => {
  const v = loadVector('relay-frames.json');
  const opts = { maxBytes: v.max_bytes };
  it.each(named(v.frames))('parses %s', (_n, c) => expect(cjson(parseRelayFrame(c.text, opts) as never)).toBe(c.text));
  it('hello and result verify', () => {
    const hello = JSON.parse(v.frames.find((f: { name: string }) => f.name === 'hello').text);
    expect(verifyHello(hello, { signPub: v.device.sign_pub, now: v.now })).toEqual(hello);
    for (const name of ['result_ok', 'result_error']) {
      const r = JSON.parse(v.frames.find((f: { name: string }) => f.name === name).text);
      expect(verifyResult(r, v.device.sign_pub)).toEqual(r);
    }
  });
  it.each(named(v.invalid_text))('refuses %s', (_n, c) => {
    const data = c.binary_utf8 === undefined ? c.text : utf8Encode(c.binary_utf8);
    expectCode(() => parseRelayFrame(data, opts), c.expect_error);
  });
  it.each(named(v.invalid_hello))('hello refuses %s', (_n, c) => expectCode(() => verifyHello(c.frame, { signPub: c.sign_pub, now: c.now }), c.expect_error));
  it.each(named(v.invalid_result))('result refuses %s', (_n, c) => expectCode(() => verifyResult(c.frame, c.sign_pub), c.expect_error));
  it.each(named(v.tool_args))('args %s', (_n, c) => expect(parseToolArgs(c.tool, c.args)).toEqual(c.args));
  it.each(named(v.tool_args_invalid))('args refuse %s', (_n, c) => {
    const args = c.value_fill === undefined ? c.args : { ...c.args, value: c.value_fill.repeat(c.value_length) };
    expectCode(() => parseToolArgs(c.tool, args), c.expect_error);
  });
  it.each(named(v.tool_results))('result %s', (_n, c) => expect(parseToolResult(c.tool, c.result)).toEqual(c.result));
  it.each(named(v.tool_results_invalid))('result refuses %s', (_n, c) => expectCode(() => parseToolResult(c.tool, c.result), c.expect_error));
});

describe('async device keys', () => {
  const sign = signKeyPairFromSeed(new Uint8Array(32).fill(7));
  const signer: DeviceSigner = { sign: async (m) => ed25519.sign(m, sign.secretKey) };
  const kxPair = kxKeyPairFromSecret(new Uint8Array(32).fill(9));
  const kx: DeviceKx = { kxPub: kxPair.publicKey, deriveShared: async (peer) => x25519Shared(kxPair.secretKey, peer) };

  it('signObjectAsync equals signObject', async () => {
    const obj = { a: 1, b: 'x' };
    expect(await signObjectAsync('akv1/relay', obj, signer)).toEqual(signObject('akv1/relay', obj, sign.secretKey));
  });
  it('signRecordAsync equals signRecord', async () => {
    const records = loadVector('records.json');
    const { sig: _sig, v: _v, ...fields } = records.sequences[0].steps[0].record;
    expect(await signRecordAsync(fields, signer)).toEqual(signRecord(fields, sign.secretKey));
  });
  it('buildProofAsync equals buildProof', async () => {
    const args = { htm: 'GET', htu: 'https://vault.example.com/v1/relay', ts: 1_767_225_600_000, token: 'synthetic-token', body: new Uint8Array(0), jti: b64encode(new Uint8Array(16).fill(1)) };
    expect(await buildProofAsync(args, signer)).toBe(buildProof({ ...args, secretKey: sign.secretKey }));
  });
  it('unwrapFromDeviceAsync equals unwrapFromDevice', async () => {
    const vaultId = b64encode(new Uint8Array(16).fill(3));
    const deviceId = b64encode(new Uint8Array(16).fill(4));
    const vk = new Uint8Array(32).fill(5);
    const wrap = wrapToDevice({ vk, vaultId, keyEpoch: 1, recipient: { device_id: deviceId, kx_pub: kxPair.publicKey } });
    const sync = unwrapFromDevice({ wrap, vaultId, deviceId, kxSecret: kxPair.secretKey });
    expect(sync).toEqual(vk);
    expect(await unwrapFromDeviceAsync({ wrap, vaultId, deviceId, kx })).toEqual(sync);
    // WebCrypto refuses a low-order point with OperationError: the all-zero case.
    const lowOrder: DeviceKx = { kxPub: kxPair.publicKey, deriveShared: async () => Promise.reject(new DOMException('low order', 'OperationError')) };
    await expect(unwrapFromDeviceAsync({ wrap, vaultId, deviceId, kx: lowOrder })).rejects.toMatchObject({ code: 'bad_request' });
  });
  it('unwrapFromDeviceAsync propagates key-store failures unchanged', async () => {
    const vaultId = b64encode(new Uint8Array(16).fill(3));
    const deviceId = b64encode(new Uint8Array(16).fill(4));
    const wrap = wrapToDevice({ vk: new Uint8Array(32).fill(5), vaultId, keyEpoch: 1, recipient: { device_id: deviceId, kx_pub: kxPair.publicKey } });
    const denied = new DOMException('key use not permitted', 'InvalidAccessError');
    const failing: DeviceKx = { kxPub: kxPair.publicKey, deriveShared: async () => Promise.reject(denied) };
    await expect(unwrapFromDeviceAsync({ wrap, vaultId, deviceId, kx: failing })).rejects.toBe(denied);
    const zero: DeviceKx = { kxPub: kxPair.publicKey, deriveShared: async () => new Uint8Array(32) };
    await expect(unwrapFromDeviceAsync({ wrap, vaultId, deviceId, kx: zero })).rejects.toMatchObject({ code: 'bad_request' });
  });
});
