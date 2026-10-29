/** Reproduce recovery-bundle.json and rekey-wraps.json. */
import { describe, expect, it } from 'vitest';
import {
  b64decode, b64encode, LOG_START, nextLogHead, openEnvelope, recordDigest, verifyChangeLog, openRecoveryBundle, sealRecoveryBundle, unwrapFromDevice, utf8Decode, verifyDeviceWraps, verifyLoggedRecord,
  signedFences, verifyMembershipChain, verifyRekeyWraps,
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
    ...(o.recovery_sign_pub !== undefined ? { recoverySignPub: o.recovery_sign_pub } : {}),
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

describe('device-add-wraps.json', () => {
  const v = loadVector('device-add-wraps.json');
  const m = loadVector('membership.json');
  const kxSecret = (id: string) => b64decode(m.devices.find((d: Vec) => d.record.device_id === id).kx_secret);
  it('shared and personal chains are the verified chains from membership.json', () => {
    expect(v.chains.shared).toEqual(m.chains[0].events);
    expect(v.chains.personal).toEqual(m.chains[1].events);
    verifyMembershipChain(v.chains.personal_current_only);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const event = v.chains[c.chain][c.event_seq];
    const wraps = verifyDeviceWraps(event, c.wraps);
    expect(wraps).toHaveLength(c.wraps.length);
    for (const w of wraps) {
      const vk = unwrapFromDevice({ wrap: w, vaultId: event.vault_id, deviceId: w.rcpt, kxSecret: kxSecret(w.rcpt) });
      expect(b64encode(vk)).toBe(v.vault_keys[c.chain][String(w.key_epoch)]);
    }
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyDeviceWraps(v.chains[c.chain][c.event_seq], c.wraps), c.expect_error);
  });
});

describe('removal-fence.json', () => {
  const v = loadVector('removal-fence.json');
  const logOptions = (c: Vec) => ({
    from: c.from,
    complete: c.complete,
    keptHeads: new Map(Object.entries(c.kept_heads as Record<string, string>).map(([k, h]) => [Number(k), h])),
  });
  const states = { shared: verifyMembershipChain(v.chains.shared), personal: verifyMembershipChain(v.chains.personal) } as Record<string, ReturnType<typeof verifyMembershipChain>>;
  it('removals carry the signed log_fence of the removing event', () => {
    expect(states['shared']!.removals).toEqual(v.removals.shared);
    expect(states['personal']!.removals).toEqual(v.removals.personal);
    expect(states['shared']!.role_changes).toEqual(v.role_changes.shared);
    expect(states['personal']!.role_changes).toEqual(v.role_changes.personal);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    expect(verifyLoggedRecord(c.record, states[c.chain]!, c.log_seq)).toEqual(c.record);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyLoggedRecord(c.record, states[c.chain]!, c.log_seq), c.expect_error);
  });
  it.each(['shared', 'personal'])('change log %s: heads chain and every removal signs the head at its fence', (chain) => {
    const { entries, heads } = v.change_logs[chain] as { entries: Vec[]; heads: string[] };
    expect(heads[0]).toBe(LOG_START.log_head);
    entries.forEach((e, i) => {
      expect(e.log_seq).toBe(i + 1);
      expect(nextLogHead(heads[i]!, e.log_seq, e.conflict_id, recordDigest(e.record))).toBe(heads[i + 1]);
    });
    for (const f of signedFences(states[chain]!)) expect(f.log_head).toBe(heads[f.log_fence]);
    const { head, records } = verifyChangeLog(entries, states[chain]!, { complete: true });
    expect(head).toEqual({ log_seq: entries.length, log_head: heads[entries.length] });
    expect(records).toEqual(entries.map((e) => e.record));
  });
  it.each(named(v.log_cases))('log %s', (_n, c: Vec) => {
    expect(verifyChangeLog(c.entries, states[c.chain]!, logOptions(c)).head).toEqual(c.head);
  });
  it.each(named(v.log_invalid))('log rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyChangeLog(c.entries, states[c.chain]!, logOptions(c)), c.expect_error);
  });
});
