/** enroll-codes.json */
import {
  b64encode,
  cjson,
  isCanonicalOrigin,
  encodeJoinCode,
  encodeOfferCode,
  parseJoinCode,
  parseOfferCode,
  signCheckpoint,
  utf8Encode,
  verifyMembershipChain,
  type JoinCode,
  type OfferCode,
} from '../../src/index.js';
import { alicePhone, aliceNewPhone, b64, BASE_TS, bobLaptop, device, negative, seed, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';
import { sharedChain } from './membership.js';

/** prefix || b64(utf8(text)), for hand-written (possibly non-canonical) objects. */
const raw = (prefix: string, text: string) => prefix + b64encode(utf8Encode(text));
const json = (obj: object) => JSON.stringify(obj);

export function enrollCodeVectors(): Record<string, unknown> {
  const head = verifyMembershipChain(sharedChain);
  const cpFields = { vault_id: VAULT_SHARED, membership_seq: head.seq, membership_head: head.head, log_seq: 9, state_digest: b64(seed('enroll/state')), key_epoch: head.key_epoch, ts: BASE_TS + 7_200_000, author: alicePhone.record.device_id };
  const checkpoint = signCheckpoint(cpFields, alicePhone.signSecret);
  const join: JoinCode = { account: 'acct_alice', device: aliceNewPhone.record, nonce_j: b64(seed('enroll/nonce_j').slice(0, 16)), label: 'Alice new phone' };
  const offer: OfferCode = {
    vault_origin: 'https://vault.example.com',
    vault_id: VAULT_SHARED,
    initiator: alicePhone.record.device_id,
    joiner: aliceNewPhone.record.device_id,
    nonce_i: b64(seed('enroll/nonce_i').slice(0, 16)),
    nonce_j: join.nonce_j,
    trust_anchor: alicePhone.record.sign_pub,
    checkpoint,
  };
  const joinCode = encodeJoinCode(join);
  const offerCode = encodeOfferCode(offer);
  const joinObj = { v: 1, ctx: 'agentkit/akv1-join', ...join };
  const offerObj = { v: 1, ctx: 'agentkit/akv1-offer', ...offer };
  const joinText = (change: Record<string, unknown>) => cjson({ ...joinObj, ...change } as never);
  const offerText = (change: Record<string, unknown>) => cjson({ ...offerObj, ...change } as never);
  const without = (o: Record<string, unknown>, key: string) => cjson(Object.fromEntries(Object.entries(o).filter(([k]) => k !== key)) as never);
  const machineOwner = device('alice-ci', 'acct_alice', 'owner', 'machine');
  const otherVaultCp = signCheckpoint({ ...cpFields, vault_id: VAULT_PERSONAL }, alicePhone.signSecret);

  const badJoin = (name: string, code: string, text: string) => negative(name, code, { code_text: text }, () => parseJoinCode(text));
  const badOffer = (name: string, code: string, text: string) => negative(name, code, { code_text: text }, () => parseOfferCode(text));
  const split = `${joinCode.slice(0, 40)}\n  ${joinCode.slice(40, 90)}\t${joinCode.slice(90)}\r\n`;
  parseJoinCode(split);
  const origins = ['https://Vault.example.com', 'https://vault.example.com/', 'https://vault.example.com:443', 'http://vault.example.com', 'https://vault.example.com.', 'https://user@vault.example.com', 'https://vault.example.com/path', 'HTTPS://vault.example.com'];
  const canonical = ['https://vault.example.com', 'https://vault.example.com:8443', 'http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787', 'https://xn--bcher-kva.example'];
  if (!canonical.every(isCanonicalOrigin) || origins.some(isCanonicalOrigin)) throw new Error('enroll-codes: origin rule mismatch');
  return {
    version: 1,
    description:
      'Enrollment codes (spec §3.8). join = "akj1-" || b64(cjson({"v":1,"ctx":"agentkit/akv1-join","account","device","nonce_j","label"})); offer = "ako1-" || b64(cjson({"v":1,"ctx":"agentkit/akv1-offer","vault_origin","vault_id","initiator","joiner","nonce_i","nonce_j","trust_anchor","checkpoint"})). ' +
      'join and offer: encoding the object MUST give code byte for byte and parsing code MUST give the object back. whitespace_split parses to join. ' +
      'parse order (every failure bad_request except v): remove every Unicode White_Space character; at most 8192 bytes and the code prefix; b64 then canonical cjson with exactly the keys (v other than 1: unsupported_version); ctx is the code context; join: device parses as a device record with account = account, role owner and kind human, nonce_j 16 bytes, label 0..64 bytes of printable ASCII; offer: canonical vault_origin (https://host[:port], lowercase, no default port, trailing dot, path, query, fragment or userinfo; http only for localhost, 127.0.0.0/8, [::1]), IDs, 16-byte nonces, 32-byte trust_anchor, checkpoint parses and names vault_id. ' +
      'invalid_join and invalid_offer: parsing code_text MUST fail with expect_error. origins: canonical MUST be accepted and non_canonical refused by the origin rule.',
    join,
    join_code: joinCode,
    offer,
    offer_code: offerCode,
    whitespace_split: split,
    origins: {
      canonical,
      non_canonical: origins,
    },
    invalid_join: [
      badJoin('oversize', 'bad_request', 'akj1-' + 'A'.repeat(8192)),
      badJoin('wrong_prefix', 'bad_request', 'ako1-' + joinCode.slice(5)),
      badJoin('offer_ctx', 'bad_request', raw('akj1-', joinText({ ctx: 'agentkit/akv1-offer' }))),
      badJoin('extra_key', 'bad_request', raw('akj1-', joinText({ extra: 1 }))),
      badJoin('missing_label', 'bad_request', raw('akj1-', without(joinObj, 'label'))),
      badJoin('non_canonical_json', 'bad_request', raw('akj1-', json(joinObj))),
      badJoin('editor_device', 'bad_request', raw('akj1-', joinText({ account: 'acct_bob', device: bobLaptop.record }))),
      badJoin('machine_device', 'bad_request', raw('akj1-', joinText({ device: machineOwner.record }))),
      badJoin('device_of_other_account', 'bad_request', raw('akj1-', joinText({ account: 'acct_bob' }))),
      badJoin('non_ascii_label', 'bad_request', raw('akj1-', joinText({ label: 'Téléphone' }))),
      badJoin('label_too_long', 'bad_request', raw('akj1-', joinText({ label: 'x'.repeat(65) }))),
      badJoin('short_nonce', 'bad_request', raw('akj1-', joinText({ nonce_j: b64(seed('enroll/short').slice(0, 15)) }))),
      badJoin('not_b64', 'bad_request', 'akj1-***'),
      badJoin('version_2', 'unsupported_version', raw('akj1-', joinText({ v: 2 }))),
    ],
    invalid_offer: [
      badOffer('join_code_as_offer', 'bad_request', joinCode),
      badOffer('join_ctx', 'bad_request', raw('ako1-', offerText({ ctx: 'agentkit/akv1-join' }))),
      badOffer('extra_key', 'bad_request', raw('ako1-', offerText({ extra: 1 }))),
      badOffer('missing_checkpoint', 'bad_request', raw('ako1-', without(offerObj, 'checkpoint'))),
      ...origins.map((o, i) => badOffer(`non_canonical_origin_${i}`, 'bad_request', raw('ako1-', offerText({ vault_origin: o })))),
      badOffer('checkpoint_of_other_vault', 'bad_request', raw('ako1-', offerText({ checkpoint: otherVaultCp }))),
      badOffer('short_trust_anchor', 'bad_request', raw('ako1-', offerText({ trust_anchor: b64(seed('enroll/anchor').slice(0, 31)) }))),
      badOffer('version_2', 'unsupported_version', raw('ako1-', offerText({ v: 2 }))),
    ],
  };
}
