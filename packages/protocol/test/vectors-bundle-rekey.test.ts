/** Reproduce recovery-bundle.json and rekey-wraps.json. */
import { describe, expect, it } from 'vitest';
import {
  b64decode, b64encode, openEnvelope, openRecoveryBundle, sealRecoveryBundle, utf8Decode, verifyMembershipChain, verifyRekeyWraps,
} from '../src/index.js';
import { expectCode, loadVector, named, type Vec } from './helpers.js';

describe('recovery-bundle.json', () => {
  const v = loadVector('recovery-bundle.json');
  const s = v.seal;
  const openArgs = (b: Vec, o: Vec) => ({
    bundle: b,
    vaultId: o.vault_id ?? s.vault_id,
    ...(o.password !== undefined ? { password: o.password } : {}),
    ...(o.rk !== undefined ? { rk: b64decode(o.rk) } : {}),
    ...(o.known_bundle_seq !== undefined ? { knownBundleSeq: o.known_bundle_seq } : {}),
  });
  it('seal reproduces the bundle and plaintext', () => {
    const vk = Object.fromEntries(Object.entries(s.vk).map(([e, k]) => [e, b64decode(k as string)]));
    const bundle = sealRecoveryBundle({
      vaultId: s.vault_id, bundleSeq: s.bundle_seq, vk, ownerSignPub: s.owner_sign_pub, recoverySignSk: b64decode(s.recovery_sign_sk),
      checkpoint: s.checkpoint, password: s.password, rk: b64decode(s.rk), params: { t: s.t, m: s.m, p: s.p },
      bundleKey: b64decode(s.bundle_key), salt: b64decode(s.salt),
      nonces: { env: b64decode(s.nonce_env), pw: b64decode(s.nonce_pw), rk: b64decode(s.nonce_rk) },
    });
    expect(bundle).toEqual(s.bundle);
    const aad = { ctx: 'akv1/recovery-bundle', vault_id: s.vault_id, bundle_seq: s.bundle_seq };
    expect(utf8Decode(openEnvelope(b64decode(s.bundle_key), s.bundle.env, aad, 'bk'))).toBe(s.plaintext_cjson);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const o = openRecoveryBundle(openArgs(c.bundle, c.open));
    expect({
      bundle_seq: o.bundle_seq,
      vk: Object.fromEntries(Object.entries(o.vk).map(([e, k]) => [e, b64encode(k)])),
      owner_sign_pub: o.owner_sign_pub,
      recovery_sign_sk: b64encode(o.recovery_sign_sk),
      recovery_sign_pub: o.recovery_sign_pub,
      checkpoint: o.checkpoint,
      needs_upgrade: o.needsUpgrade,
    }).toEqual(c.expected);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => openRecoveryBundle(openArgs(c.bundle, c.open)), c.expect_error);
  });
});

describe('rekey-wraps.json', () => {
  const v = loadVector('rekey-wraps.json');
  const run = (c: Vec) => () =>
    verifyRekeyWraps(v.events[c.event_seq], c.wraps, c.state_seq === null ? {} : { state: verifyMembershipChain(v.events.slice(0, c.state_seq + 1)) });
  it('events are the verified shared chain from membership.json', () => {
    expect(v.events).toEqual(loadVector('membership.json').chains[0].events);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    expect(run(c)()).toHaveLength(c.wraps.length);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(run(c), c.expect_error);
  });
});
