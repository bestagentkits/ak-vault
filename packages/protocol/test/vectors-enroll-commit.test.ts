/** enroll-commit.json: committed device enrollment (spec §3.9). */
import { describe, expect, it } from 'vitest';
import {
  encodeJoin2Code,
  encodeOffer2Code,
  encodeReveal2Code,
  nonceJCommit,
  parseJoin2Code,
  parseJoinCode,
  parseOffer2Code,
  parseOfferCode,
  parseReveal2Code,
  sas2Code,
  sas2Digest,
  sas2Transcript,
  sasCode,
  utf8Decode,
  verifyNonceJReveal,
} from '../src/index.js';
import { expectCode, loadVector, named } from './helpers.js';

describe('enroll-commit.json', () => {
  const v = loadVector('enroll-commit.json');

  it('join, offer and reveal round trip byte for byte', () => {
    expect(encodeJoin2Code(v.join)).toBe(v.join_code);
    expect(parseJoin2Code(v.join_code)).toEqual(v.join);
    expect(encodeOffer2Code(v.offer)).toBe(v.offer_code);
    expect(parseOffer2Code(v.offer_code)).toEqual(v.offer);
    expect(encodeReveal2Code(v.reveal)).toBe(v.reveal_code);
    expect(parseReveal2Code(v.reveal_code)).toEqual(v.reveal);
  });
  it('v2 and v1 codes are never accepted by the other parser', () => {
    expectCode(() => parseJoinCode(v.join_code), 'bad_request');
    expectCode(() => parseOfferCode(v.offer_code), 'bad_request');
  });
  it('commitment matches the join and offer', () => {
    expect(nonceJCommit(v.commit.nonce_j)).toBe(v.commit.nonce_j_commit);
    expect(v.join.nonce_j_commit).toBe(v.commit.nonce_j_commit);
    expect(v.offer.nonce_j_commit).toBe(v.commit.nonce_j_commit);
    expect(v.reveal.nonce_j).toBe(v.commit.nonce_j);
  });
  it.each(named(v.reveal_check))('reveal check %s', (_n, c) => {
    if (c.expect === 'ok') verifyNonceJReveal(c.nonce_j_commit, c.nonce_j);
    else expectCode(() => verifyNonceJReveal(c.nonce_j_commit, c.nonce_j), c.expect);
  });
  it('sas2 known answer', () => {
    expect(utf8Decode(sas2Transcript(v.sas2.input))).toBe(v.sas2.transcript_text);
    expect(sas2Code(v.sas2.input)).toBe(v.sas2.code);
    expect(sas2Digest(v.sas2.input)).toBe(v.sas2.digest);
  });
  it('sas2 is not the legacy code and every field changes the digest', () => {
    const { vault_id, initiator, joiner, nonce_i, nonce_j } = v.sas2.input;
    expect(sasCode({ vault_id, initiator, joiner, nonce_i, nonce_j })).toBe(v.sas2.legacy_code);
    for (const c of v.sas2.changed) {
      expect(sas2Digest(c.input), c.name).toBe(c.digest);
      expect(c.digest, c.name).not.toBe(v.sas2.digest);
    }
  });
  it('a ground nonce reproduces the six digits but is refused at the reveal', () => {
    const g = v.ground_sas;
    expect(sas2Code({ ...g.sas_input, nonce_j: g.ground_nonce_j })).toBe(g.target_code);
    expectCode(() => verifyNonceJReveal(g.forged_commit, g.ground_nonce_j), g.expect_error);
  });
  it.each(named(v.invalid_join))('join refuses %s', (_n, c) => expectCode(() => parseJoin2Code(c.code_text), c.expect_error));
  it.each(named(v.invalid_offer))('offer refuses %s', (_n, c) => expectCode(() => parseOffer2Code(c.code_text), c.expect_error));
  it.each(named(v.invalid_reveal))('reveal refuses %s', (_n, c) => expectCode(() => parseReveal2Code(c.code_text), c.expect_error));
});
