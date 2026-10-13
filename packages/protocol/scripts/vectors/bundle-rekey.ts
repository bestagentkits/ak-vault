/** recovery-bundle.json and rekey-wraps.json (added without changing earlier files). */
import {
  cjson,
  cjsonBytes,
  computeStateDigest,
  openRecoveryBundle,
  sealEnvelope,
  sealRecoveryBundle,
  signCheckpoint,
  verifyMembershipChain,
  verifyRekeyWraps,
  type JsonObject,
  type MembershipEvent,
  type X25519Wrap,
} from '../../src/index.js';
import { b64decode, derivePasswordKek, deriveRecoveryKek } from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { epoch2Wraps, epoch3Wraps, sharedChain, wrapsFor } from './membership.js';
import { alicePhone, b64, BASE_TS, flipByte, id, key32, negative, nonce, recoverySign, recoverySignPub, seed, stranger, VAULT_SHARED } from './fixtures.js';

export function recoveryBundleVectors(): Record<string, unknown> {
  const state = verifyMembershipChain(sharedChain);
  const cpFields = {
    vault_id: VAULT_SHARED, membership_seq: state.seq, membership_head: state.head, log_seq: 12,
    state_digest: computeStateDigest([{ item_id: id('item/A'), revision: 2, head: b64(seed('bundle/head/A')) }]),
    key_epoch: state.key_epoch, ts: BASE_TS + 7_200_000, author: alicePhone.record.device_id,
  };
  const checkpoint = signCheckpoint(cpFields, alicePhone.signSecret);
  const vk = { '1': key32('vk/epoch1'), '2': key32('vk/epoch2'), '3': key32('vk/epoch3') };
  const password = 'correct horse battery staple';
  const rk = seed('recovery/rk');
  const params = { t: 2, m: 19_456, p: 1 };
  const inject = (label: string) => ({
    bundleKey: key32(`bundle/${label}`),
    salt: seed(`bundle/salt/${label}`).slice(0, 16),
    nonces: { env: nonce(`bundle/env/${label}`), pw: nonce(`bundle/pw/${label}`), rk: nonce(`bundle/rk/${label}`) },
  });
  const sealArgs = { vaultId: VAULT_SHARED, bundleSeq: 3, vk, ownerSignPub: alicePhone.record.sign_pub, recoverySignSk: recoverySign.secretKey, checkpoint, password, rk, params };
  const bundle = sealRecoveryBundle({ ...sealArgs, ...inject('main') });
  const summarize = (o: ReturnType<typeof openRecoveryBundle>) => ({
    bundle_seq: o.bundle_seq,
    vk: Object.fromEntries(Object.entries(o.vk).map(([e, k]) => [e, b64(k)])),
    owner_sign_pub: o.owner_sign_pub,
    recovery_sign_sk: b64(o.recovery_sign_sk),
    recovery_sign_pub: o.recovery_sign_pub,
    checkpoint: o.checkpoint,
    needs_upgrade: o.needsUpgrade,
  });
  const expected = summarize(openRecoveryBundle({ bundle, vaultId: VAULT_SHARED, password }));
  if (expected.recovery_sign_pub !== recoverySignPub) throw new Error('recovery key mismatch');
  const i = inject('main');

  // A bundle whose checkpoint was tampered after signing (sealing it requires bypassing seal-side checks).
  const tamperedCp = { ...checkpoint, log_seq: 13 };
  const strangerCp = signCheckpoint({ ...cpFields, author: stranger.record.device_id }, stranger.signSecret);
  const badCpBundle = sealUnchecked(sealArgs, tamperedCp, 'badcp');
  const strangerCpBundle = sealUnchecked({ ...sealArgs }, strangerCp, 'strangercp');

  type OpenOpts = { password?: string; rk?: string; vault_id?: string; known_bundle_seq?: number };
  const open = (b: unknown, o: OpenOpts) => () =>
    openRecoveryBundle({
      bundle: b,
      vaultId: o.vault_id ?? VAULT_SHARED,
      ...(o.password !== undefined ? { password: o.password } : {}),
      ...(o.rk !== undefined ? { rk: b64decode(o.rk) } : {}),
      ...(o.known_bundle_seq !== undefined ? { knownBundleSeq: o.known_bundle_seq } : {}),
    });
  const bad = (name: string, code: string, b: unknown, o: OpenOpts) => negative(name, code, { bundle: b, open: o }, open(b, o));
  const flipEnv = { ...bundle, env: { ...bundle.env, ct: flipByte(bundle.env.ct, 10) } };

  return {
    version: 1,
    description:
      'Recovery bundle (spec §3.4, §11). seal: inputs (vk per epoch, owner_sign_pub, recovery_sign_sk, checkpoint, password NFC, rk, argon params, injected bundle_key/salt/nonces) MUST produce `bundle` exactly; plaintext_cjson is the sealed plaintext. env = XC20P(bundle_key, nonce_env, plaintext_cjson, aad={ctx:"akv1/recovery-bundle",vault_id,bundle_seq}) with kid "bk"; pw = XC20P(Argon2id kek, nonce_pw, bundle_key, aad={ctx:"akv1/bundle-pw-wrap",vault_id,bundle_seq,t,m,p}); rk = XC20P(KEK_rk, nonce_rk, bundle_key, aad={ctx:"akv1/bundle-rk-wrap",vault_id,bundle_seq}). cases: opening `bundle` with `open` options MUST return `expected` (vk as b64 by epoch; needs_upgrade is true only for a password open under params weaker than t=3,m=65536,p=1). invalid: opening MUST fail with expect_error (rollback when bundle_seq < known_bundle_seq, checked before any KDF; checkpoint author must be kid(owner_sign_pub) and its akv1/checkpoint signature must verify against owner_sign_pub).',
    seal: {
      vault_id: VAULT_SHARED,
      bundle_seq: 3,
      vk: expected.vk,
      owner_sign_pub: alicePhone.record.sign_pub,
      recovery_sign_sk: b64(recoverySign.secretKey),
      checkpoint,
      password,
      rk: b64(rk),
      ...params,
      bundle_key: b64(i.bundleKey),
      salt: b64(i.salt),
      nonce_env: b64(i.nonces.env),
      nonce_pw: b64(i.nonces.pw),
      nonce_rk: b64(i.nonces.rk),
      plaintext_cjson: plaintextCjson(sealArgs, checkpoint),
      bundle,
    },
    cases: [
      { name: 'open_with_password', bundle, open: { password }, expected: summarize(open(bundle, { password })()) },
      { name: 'open_with_recovery_key', bundle, open: { rk: b64(rk) }, expected: summarize(open(bundle, { rk: b64(rk) })()) },
      { name: 'open_with_equal_known_seq', bundle, open: { rk: b64(rk), known_bundle_seq: 3 }, expected: summarize(open(bundle, { rk: b64(rk), known_bundle_seq: 3 })()) },
    ],
    invalid: [
      bad('wrong_password', 'decrypt_failed', bundle, { password: 'Correct horse battery staple' }),
      bad('wrong_recovery_key', 'decrypt_failed', bundle, { rk: b64(seed('recovery/other')) }),
      bad('tampered_envelope', 'decrypt_failed', flipEnv, { rk: b64(rk) }),
      bad('tampered_bundle_seq_header', 'decrypt_failed', { ...bundle, bundle_seq: 4 }, { rk: b64(rk) }),
      bad('rollback_lower_than_known', 'rollback', bundle, { password, known_bundle_seq: 4 }),
      bad('other_vault', 'bad_request', bundle, { rk: b64(rk), vault_id: id('vault/other') }),
      bad('checkpoint_signature_invalid', 'invalid_signature', badCpBundle, { rk: b64(rk) }),
      bad('checkpoint_not_by_owner_anchor', 'forbidden', strangerCpBundle, { rk: b64(rk) }),
      bad('weak_argon_params', 'bad_request', { ...bundle, pw: { ...bundle.pw, m: 8192 } }, { password }),
      bad('unsupported_version', 'unsupported_version', { ...bundle, v: 2 }, { rk: b64(rk) }),
      bad('both_secrets_given', 'bad_request', bundle, { password, rk: b64(rk) }),
    ],
  };
}

type SealArgs = Parameters<typeof sealRecoveryBundle>[0];

function plaintextObject(args: SealArgs, checkpoint: unknown): JsonObject {
  return {
    v: 1,
    vault_id: args.vaultId,
    bundle_seq: args.bundleSeq,
    vk: Object.fromEntries(Object.entries(args.vk).map(([e, k]) => [e, b64(k)])),
    owner_sign_pub: args.ownerSignPub,
    recovery_sign_sk: b64(args.recoverySignSk),
    checkpoint: checkpoint as JsonObject,
  };
}

function plaintextCjson(args: SealArgs, checkpoint: unknown): string {
  return cjson(plaintextObject(args, checkpoint));
}

/** Seal with an arbitrary checkpoint (no seal-side checks) to build negative vectors. */
function sealUnchecked(args: SealArgs, checkpoint: unknown, label: string) {
  const bk = key32(`bundle/${label}`);
  const salt = seed(`bundle/salt/${label}`).slice(0, 16);
  const p = args.params!;
  const v = args.vaultId;
  const s = args.bundleSeq;
  const env = sealEnvelope(bk, cjsonBytes(plaintextObject(args, checkpoint)), { ctx: 'akv1/recovery-bundle', vault_id: v, bundle_seq: s }, { kid: 'bk', nonce: nonce(`bundle/env/${label}`) });
  const pw = xc20pSeal(derivePasswordKek(args.password, salt, p), nonce(`bundle/pw/${label}`), bk, { ctx: 'akv1/bundle-pw-wrap', vault_id: v, bundle_seq: s, ...p });
  const rk = xc20pSeal(deriveRecoveryKek(args.rk), nonce(`bundle/rk/${label}`), bk, { ctx: 'akv1/bundle-rk-wrap', vault_id: v, bundle_seq: s });
  return {
    v: 1, vault_id: v, bundle_seq: s,
    pw: { v: 1, alg: 'argon2id-xc20p', s: b64(salt), ...p, n: b64(nonce(`bundle/pw/${label}`)), ct: b64(pw) },
    rk: { v: 1, alg: 'rk-xc20p', n: b64(nonce(`bundle/rk/${label}`)), ct: b64(rk) },
    env,
  };
}

export function rekeyWrapsVectors(): Record<string, unknown> {
  const chain: MembershipEvent[] = sharedChain;
  const stateAt = (seq: number) => verifyMembershipChain(chain.slice(0, seq + 1));
  const run = (event: MembershipEvent, wraps: unknown[], stateSeq: number | null) => () =>
    verifyRekeyWraps(event, wraps, stateSeq === null ? {} : { state: stateAt(stateSeq) });
  const ok = (name: string, seq: number, wraps: X25519Wrap[], stateSeq: number | null) => {
    run(chain[seq]!, wraps, stateSeq)();
    return { name, event_seq: seq, state_seq: stateSeq, wraps };
  };
  const bad = (name: string, code: string, seq: number, wraps: unknown[], stateSeq: number | null) =>
    negative(name, code, { event_seq: seq, state_seq: stateSeq, wraps }, run(chain[seq]!, wraps, stateSeq));
  const reversed = [...epoch3Wraps].reverse();
  const swapped = epoch3Wraps.map((w, i) => (i === 0 ? { ...w, ct: flipByte(w.ct, 4) } : w));
  return {
    version: 1,
    description:
      'Rekey wrap sets (spec §4, §11). events: the verified shared membership chain (same as membership.json chains[0]). verifyRekeyWraps(events[event_seq], wraps, state) where state = verifyMembershipChain(events[0..state_seq]) or absent when state_seq is null. Checks in order: event is a rekey; wraps parse; each wrap key_epoch == body.new_key_epoch and rcpt unique; with state: state.seq == event.seq and state.head == hash(event), recipients are current devices (forbidden), every current device has a wrap; finally b64 sha256(cjson(wraps sorted by rcpt)) == body.wraps_digest. Wrap input order does not matter. cases MUST pass; invalid MUST fail with expect_error.',
    events: chain,
    cases: [
      ok('epoch2_with_state', 6, epoch2Wraps, 6),
      ok('epoch3_with_state', 8, epoch3Wraps, 8),
      ok('epoch3_without_state_any_order', 8, reversed, null),
    ],
    invalid: [
      bad('not_a_rekey_event', 'bad_request', 7, epoch3Wraps, null),
      bad('missing_wrap_digest_mismatch', 'bad_request', 8, epoch3Wraps.slice(1), null),
      bad('missing_wrap_with_state', 'bad_request', 8, epoch3Wraps.slice(1), 8),
      bad('substituted_wrap_digest_mismatch', 'bad_request', 8, swapped, null),
      bad('injected_recipient_with_state', 'forbidden', 8, [...epoch3Wraps, ...wrapsFor([stranger], 3, 'rekey-inj')], 8),
      bad('injected_recipient_digest_mismatch', 'bad_request', 8, [...epoch3Wraps, ...wrapsFor([stranger], 3, 'rekey-inj')], null),
      bad('wrong_epoch_wrap', 'bad_request', 8, epoch2Wraps.slice(0, 3), null),
      bad('duplicate_recipient', 'bad_request', 8, [...epoch3Wraps, epoch3Wraps[0]!], null),
      bad('state_not_at_event', 'bad_request', 6, epoch2Wraps, 8),
    ],
  };
}
