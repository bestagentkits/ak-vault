/** enroll-commit.json (spec §3.9) */
import {
  b64encode,
  cjson,
  encodeJoin2Code,
  encodeOffer2Code,
  encodeReveal2Code,
  nonceJCommit,
  parseJoin2Code,
  parseOffer2Code,
  parseReveal2Code,
  sas2Code,
  sas2Digest,
  sas2Transcript,
  sasCode,
  signCheckpoint,
  utf8Encode,
  verifyMembershipChain,
  verifyNonceJReveal,
  type Join2Code,
  type Offer2Code,
  type Reveal2Code,
  type Sas2Input,
} from '../../src/index.js';
import { alicePhone, aliceNewPhone, b64, BASE_TS, bobLaptop, device, expectCode, negative, seed, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';
import { sharedChain } from './membership.js';

const raw = (prefix: string, text: string) => prefix + b64encode(utf8Encode(text));
const json = (obj: object) => JSON.stringify(obj);
const ORIGIN = 'https://vault.example.com';

/** Deterministic 16-byte nonce number `n` of a labelled stream. */
function streamNonce(label: string, n: number): string {
  const bytes = new Uint8Array(16);
  bytes.set(seed(label).slice(0, 12));
  new DataView(bytes.buffer).setUint32(12, n, false);
  return b64(bytes);
}

export function enrollCommitVectors(): Record<string, unknown> {
  const head = verifyMembershipChain(sharedChain);
  const cpFields = { vault_id: VAULT_SHARED, membership_seq: head.seq, membership_head: head.head, log_seq: 9, state_digest: b64(seed('enroll/state')), key_epoch: head.key_epoch, ts: BASE_TS + 7_200_000, author: alicePhone.record.device_id };
  const checkpoint = signCheckpoint(cpFields, alicePhone.signSecret);
  const nonce_j = b64(seed('enroll2/nonce_j').slice(0, 16));
  const nonce_i = b64(seed('enroll2/nonce_i').slice(0, 16));
  const commit = nonceJCommit(nonce_j);

  const join: Join2Code = { account: 'acct_alice', device: aliceNewPhone.record, nonce_j_commit: commit, label: 'Alice new phone' };
  const offer: Offer2Code = {
    vault_origin: ORIGIN,
    vault_id: VAULT_SHARED,
    initiator: alicePhone.record.device_id,
    joiner: aliceNewPhone.record.device_id,
    nonce_i,
    nonce_j_commit: commit,
    trust_anchor: alicePhone.record.sign_pub,
    checkpoint,
  };
  const reveal: Reveal2Code = { vault_id: VAULT_SHARED, joiner: aliceNewPhone.record.device_id, nonce_j };
  const sas: Sas2Input = { vault_id: VAULT_SHARED, vault_origin: ORIGIN, trust_anchor: alicePhone.record.sign_pub, initiator: alicePhone.record.device_id, joiner: aliceNewPhone.record, nonce_i, nonce_j };

  const joinCode = encodeJoin2Code(join);
  const offerCode = encodeOffer2Code(offer);
  const revealCode = encodeReveal2Code(reveal);
  const joinObj = { v: 1, ctx: 'akv1/enroll-join', ...join };
  const offerObj = { v: 1, ctx: 'akv1/enroll-offer', ...offer };
  const revealObj = { v: 1, ctx: 'akv1/enroll-reveal', ...reveal };
  const text = (base: object, change: Record<string, unknown>) => cjson({ ...base, ...change } as never);
  const without = (o: Record<string, unknown>, key: string) => cjson(Object.fromEntries(Object.entries(o).filter(([k]) => k !== key)) as never);
  const machineOwner = device('alice-ci', 'acct_alice', 'owner', 'machine');
  const humanReader = device('alice-reader', 'acct_alice', 'reader');
  const otherVaultCp = signCheckpoint({ ...cpFields, vault_id: VAULT_PERSONAL }, alicePhone.signSecret);
  const origins = ['https://Vault.example.com', 'https://vault.example.com/', 'https://vault.example.com:443', 'http://vault.example.com', 'https://user@vault.example.com'];

  const badJoin = (name: string, code: string, t: string) => negative(name, code, { code_text: t }, () => parseJoin2Code(t));
  const badOffer = (name: string, code: string, t: string) => negative(name, code, { code_text: t }, () => parseOffer2Code(t));
  const badReveal = (name: string, code: string, t: string) => negative(name, code, { code_text: t }, () => parseReveal2Code(t));

  // The grinding attack the commitment closes. A forger who learns nonce_i
  // searches for a nonce_j' that makes the six digits match the target. Under
  // the uncommitted rule that search succeeds; under §3.9 the ground nonce is
  // not the committed one, so the reveal is refused before any SAS is computed.
  const target = sas2Code(sas);
  const forgedCommit = nonceJCommit(streamNonce('enroll2/forger-committed', 0));
  // Index found once by searching streamNonce('enroll2/ground', n) in order (about 10^6 tries);
  // fixed here so regenerating stays fast. A changed fixture fails the check below.
  const GROUND_INDEX = 2_354_866;
  const ground = streamNonce('enroll2/ground', GROUND_INDEX);
  if (sas2Code({ ...sas, nonce_j: ground }) !== target) throw new Error('enroll-commit: GROUND_INDEX no longer matches the sas2 fixture; search for a new index');
  if (expectCode(() => verifyNonceJReveal(forgedCommit, ground)) !== 'forbidden') throw new Error('enroll-commit: ground nonce was not refused');
  verifyNonceJReveal(commit, nonce_j);

  return {
    version: 1,
    description:
      'Committed device enrollment (spec §3.9). join = "akj2-" || b64(cjson({"v":1,"ctx":"akv1/enroll-join","account","device","nonce_j_commit","label"})); offer = "ako2-" || b64(cjson({"v":1,"ctx":"akv1/enroll-offer","vault_origin","vault_id","initiator","joiner","nonce_i","nonce_j_commit","trust_anchor","checkpoint"})); reveal = "akr2-" || b64(cjson({"v":1,"ctx":"akv1/enroll-reveal","vault_id","joiner","nonce_j"})). ' +
      'join, offer and reveal: encoding the object MUST give the code byte for byte and parsing the code MUST give the object back. Parsing follows the §3.8 order (every failure bad_request except the code own v: unsupported_version) with the keys and contexts above; nonce_j_commit is 32 bytes; a reveal names vault_id and the joiner device_id and carries a 16-byte nonce_j. ' +
      'commit: nonce_j_commit = b64(sha256(cjson({"ctx":"akv1/enroll-nonce-j","nonce_j"}))). reveal_check: verifying nonce_j against commit MUST pass when expect is ok and fail with the given code otherwise. ' +
      'sas2: transcript_text = cjson({"ctx":"akv1/sas2","vault_id","vault_origin","trust_anchor","initiator","joiner":device record,"nonce_i","nonce_j"}); code = uint32be(sha256(transcript)[0:4]) mod 10^6 as six digits; digest = b64(sha256(transcript)) is device_add.body.sas; every field changes the digits. ' +
      'ground_sas: ground_nonce_j makes the sas2 code of the case equal target_code (a six-digit match found by search) but is not the nonce_j that forged_commit commits to, so verifying it against forged_commit MUST fail with forbidden; the legacy §3.5 transcript offers no such check. ' +
      'invalid_join, invalid_offer and invalid_reveal: parsing code_text MUST fail with expect_error.',
    join,
    join_code: joinCode,
    offer,
    offer_code: offerCode,
    reveal,
    reveal_code: revealCode,
    commit: { nonce_j, nonce_j_commit: commit },
    reveal_check: [
      { name: 'matches', nonce_j_commit: commit, nonce_j, expect: 'ok' },
      { name: 'other_nonce', nonce_j_commit: commit, nonce_j: nonce_i, expect: 'forbidden' },
      { name: 'other_commit', nonce_j_commit: forgedCommit, nonce_j, expect: 'forbidden' },
    ],
    sas2: {
      input: sas,
      transcript_text: new TextDecoder().decode(sas2Transcript(sas)),
      code: target,
      digest: sas2Digest(sas),
      legacy_code: sasCode({ vault_id: sas.vault_id, initiator: sas.initiator, joiner: sas.joiner, nonce_i, nonce_j }),
      changed: [
        { name: 'origin', input: { ...sas, vault_origin: 'https://other.example.com' } },
        { name: 'trust_anchor', input: { ...sas, trust_anchor: bobLaptop.record.sign_pub } },
        { name: 'initiator', input: { ...sas, initiator: bobLaptop.record.device_id } },
        { name: 'joiner', input: { ...sas, joiner: alicePhone.record } },
        { name: 'nonce_i', input: { ...sas, nonce_i: b64(seed('enroll2/other_i').slice(0, 16)) } },
        { name: 'nonce_j', input: { ...sas, nonce_j: b64(seed('enroll2/other_j').slice(0, 16)) } },
      ].map((c) => ({ ...c, digest: sas2Digest(c.input) })),
    },
    ground_sas: { target_code: target, sas_input: sas, forged_commit: forgedCommit, ground_nonce_j: ground, expect_error: 'forbidden' },
    invalid_join: [
      badJoin('wrong_prefix', 'bad_request', 'akj1-' + joinCode.slice(5)),
      badJoin('legacy_ctx', 'bad_request', raw('akj2-', text(joinObj, { ctx: 'agentkit/akv1-join' }))),
      badJoin('extra_key', 'bad_request', raw('akj2-', text(joinObj, { extra: 1 }))),
      badJoin('plain_nonce_j', 'bad_request', raw('akj2-', cjson({ v: 1, ctx: 'akv1/enroll-join', account: join.account, device: join.device, nonce_j, label: join.label } as never))),
      badJoin('missing_commit', 'bad_request', raw('akj2-', without(joinObj, 'nonce_j_commit'))),
      badJoin('short_commit', 'bad_request', raw('akj2-', text(joinObj, { nonce_j_commit: nonce_j }))),
      badJoin('non_canonical_json', 'bad_request', raw('akj2-', json(joinObj))),
      badJoin('machine_device', 'bad_request', raw('akj2-', text(joinObj, { device: machineOwner.record }))),
      badJoin('reader_device', 'bad_request', raw('akj2-', text(joinObj, { device: humanReader.record }))),
      badJoin('non_ascii_label', 'bad_request', raw('akj2-', text(joinObj, { label: 'Téléphone' }))),
      badJoin('version_2', 'unsupported_version', raw('akj2-', text(joinObj, { v: 2 }))),
    ],
    invalid_offer: [
      badOffer('join_code_as_offer', 'bad_request', joinCode),
      badOffer('legacy_offer_shape', 'bad_request', raw('ako2-', text(offerObj, { nonce_j }))),
      badOffer('legacy_ctx', 'bad_request', raw('ako2-', text(offerObj, { ctx: 'agentkit/akv1-offer' }))),
      badOffer('missing_commit', 'bad_request', raw('ako2-', without(offerObj, 'nonce_j_commit'))),
      badOffer('short_commit', 'bad_request', raw('ako2-', text(offerObj, { nonce_j_commit: nonce_j }))),
      badOffer('short_nonce_i', 'bad_request', raw('ako2-', text(offerObj, { nonce_i: b64(seed('enroll2/short').slice(0, 15)) }))),
      ...origins.map((o, i) => badOffer(`non_canonical_origin_${i}`, 'bad_request', raw('ako2-', text(offerObj, { vault_origin: o })))),
      badOffer('checkpoint_of_other_vault', 'bad_request', raw('ako2-', text(offerObj, { checkpoint: otherVaultCp }))),
      badOffer('version_2', 'unsupported_version', raw('ako2-', text(offerObj, { v: 2 }))),
    ],
    invalid_reveal: [
      badReveal('offer_as_reveal', 'bad_request', offerCode),
      badReveal('extra_key', 'bad_request', raw('akr2-', text(revealObj, { extra: 1 }))),
      badReveal('missing_joiner', 'bad_request', raw('akr2-', without(revealObj, 'joiner'))),
      badReveal('short_nonce', 'bad_request', raw('akr2-', text(revealObj, { nonce_j: b64(seed('enroll2/short').slice(0, 15)) }))),
      badReveal('wrong_ctx', 'bad_request', raw('akr2-', text(revealObj, { ctx: 'akv1/enroll-offer' }))),
      badReveal('version_2', 'unsupported_version', raw('akr2-', text(revealObj, { v: 2 }))),
    ],
  };
}
