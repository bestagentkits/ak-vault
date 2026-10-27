/**
 * Committed device enrollment (spec §3.9). The joiner commits to `nonce_j` in
 * its join code (`akj2-`), the owner device answers with an offer that reveals
 * `nonce_i` (`ako2-`), and only then the joiner reveals `nonce_j` (`akr2-`).
 * A party that substitutes the join must fix its key and nonce before it knows
 * `nonce_i`, so a six-digit SAS can no longer be ground offline. The SAS also
 * covers the vault origin and the trust anchor.
 *
 *   commit     = b64(sha256(cjson({ctx:"akv1/enroll-nonce-j", nonce_j})))
 *   transcript = cjson({ctx:"akv1/sas2", vault_id, vault_origin, trust_anchor,
 *                       initiator, joiner: device, nonce_i, nonce_j})
 *   code       = uint32be(sha256(transcript)[0:4]) mod 10^6, shown as 6 digits
 *   device_add.body.sas = b64(sha256(transcript))
 */
import { b64decode, b64encode } from './base64url.js';
import { sha256 } from './bytes.js';
import { cjsonBytes } from './canonical-json.js';
import { checkJoinDevice, decodeCode, encodeCode, isCanonicalOrigin, parseEmbeddedCheckpoint } from './enroll-codes.js';
import { fail } from './errors.js';
import { parseDevice, type DeviceRecord } from './membership-types.js';
import { type Checkpoint } from './checkpoints.js';
import { asB64, asId, type Obj } from './validate.js';

export const JOIN2_CODE_PREFIX = 'akj2-';
export const OFFER2_CODE_PREFIX = 'ako2-';
export const REVEAL2_CODE_PREFIX = 'akr2-';
export const JOIN2_CODE_CONTEXT = 'akv1/enroll-join';
export const OFFER2_CODE_CONTEXT = 'akv1/enroll-offer';
export const REVEAL2_CODE_CONTEXT = 'akv1/enroll-reveal';
export const NONCE_J_COMMIT_CONTEXT = 'akv1/enroll-nonce-j';
export const SAS2_CONTEXT = 'akv1/sas2';

const JOIN2_KEYS = ['v', 'ctx', 'account', 'device', 'nonce_j_commit', 'label'] as const;
const OFFER2_KEYS = ['v', 'ctx', 'vault_origin', 'vault_id', 'initiator', 'joiner', 'nonce_i', 'nonce_j_commit', 'trust_anchor', 'checkpoint'] as const;
const REVEAL2_KEYS = ['v', 'ctx', 'vault_id', 'joiner', 'nonce_j'] as const;

export interface Join2Code {
  account: string;
  device: DeviceRecord;
  /** b64 of sha256 over the committed `nonce_j` (see {@link nonceJCommit}). */
  nonce_j_commit: string;
  label: string;
}

export interface Offer2Code {
  vault_origin: string;
  vault_id: string;
  initiator: string;
  joiner: string;
  nonce_i: string;
  nonce_j_commit: string;
  trust_anchor: string;
  checkpoint: Checkpoint;
}

export interface Reveal2Code {
  vault_id: string;
  joiner: string;
  nonce_j: string;
}

export interface Sas2Input {
  vault_id: string;
  vault_origin: string;
  /** b64 32-byte Ed25519 `sign_pub` of the genesis author. */
  trust_anchor: string;
  initiator: string;
  joiner: DeviceRecord;
  nonce_i: string;
  nonce_j: string;
}

/** The commitment the joiner puts in its join code. */
export function nonceJCommit(nonce_j: string): string {
  asB64(nonce_j, 'nonce_j', 16);
  return b64encode(sha256(cjsonBytes({ ctx: NONCE_J_COMMIT_CONTEXT, nonce_j })));
}

/**
 * Check a revealed `nonce_j` against the commitment. A mismatch is `forbidden`
 * and the initiator MUST NOT show or compute a SAS from it.
 */
export function verifyNonceJReveal(commit: string, nonce_j: string): void {
  const expected = b64decode(asB64(commit, 'nonce_j_commit', 32));
  const actual = b64decode(nonceJCommit(nonce_j));
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= (expected[i] as number) ^ (actual[i] as number);
  if (diff !== 0) fail('forbidden', 'nonce_j does not match its commitment');
}

export function sas2Transcript(input: Sas2Input): Uint8Array {
  if (!isCanonicalOrigin(input.vault_origin)) fail('bad_request', 'vault_origin is not a canonical origin');
  return cjsonBytes({
    ctx: SAS2_CONTEXT,
    vault_id: asId(input.vault_id, 'vault_id'),
    vault_origin: input.vault_origin,
    trust_anchor: asB64(input.trust_anchor, 'trust_anchor', 32),
    initiator: asId(input.initiator, 'initiator'),
    joiner: parseDevice(input.joiner, 'joiner'),
    nonce_i: asB64(input.nonce_i, 'nonce_i', 16),
    nonce_j: asB64(input.nonce_j, 'nonce_j', 16),
  });
}

/** The 6-digit code both devices display. */
export function sas2Code(input: Sas2Input): string {
  const h = sha256(sas2Transcript(input));
  const n = (((h[0] as number) << 24) >>> 0) + ((h[1] as number) << 16) + ((h[2] as number) << 8) + (h[3] as number);
  return String(n % 1_000_000).padStart(6, '0');
}

/** Value for `device_add.body.sas`. */
export function sas2Digest(input: Sas2Input): string {
  return b64encode(sha256(sas2Transcript(input)));
}

function checkJoin2(obj: Obj, what: string): Join2Code {
  return { ...checkJoinDevice(obj, what), nonce_j_commit: asB64(obj['nonce_j_commit'], `${what}.nonce_j_commit`, 32) };
}

function checkOffer2(obj: Obj, what: string): Offer2Code {
  const origin = obj['vault_origin'];
  if (typeof origin !== 'string' || !isCanonicalOrigin(origin)) fail('bad_request', `${what}.vault_origin is not a canonical origin`);
  const vaultId = asId(obj['vault_id'], `${what}.vault_id`);
  const offer: Offer2Code = {
    vault_origin: origin,
    vault_id: vaultId,
    initiator: asId(obj['initiator'], `${what}.initiator`),
    joiner: asId(obj['joiner'], `${what}.joiner`),
    nonce_i: asB64(obj['nonce_i'], `${what}.nonce_i`, 16),
    nonce_j_commit: asB64(obj['nonce_j_commit'], `${what}.nonce_j_commit`, 32),
    trust_anchor: asB64(obj['trust_anchor'], `${what}.trust_anchor`, 32),
    checkpoint: parseEmbeddedCheckpoint(obj['checkpoint'], `${what}.checkpoint`),
  };
  if (offer.checkpoint.vault_id !== vaultId) fail('bad_request', `${what}.checkpoint names another vault`);
  return offer;
}

function checkReveal2(obj: Obj, what: string): Reveal2Code {
  return {
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    joiner: asId(obj['joiner'], `${what}.joiner`),
    nonce_j: asB64(obj['nonce_j'], `${what}.nonce_j`, 16),
  };
}

export function encodeJoin2Code(join: Join2Code): string {
  const obj = { v: 1, ctx: JOIN2_CODE_CONTEXT, account: join.account, device: join.device, nonce_j_commit: join.nonce_j_commit, label: join.label };
  checkJoin2(obj, 'join code');
  return encodeCode(JOIN2_CODE_PREFIX, obj);
}

export function parseJoin2Code(code: unknown): Join2Code {
  return checkJoin2(decodeCode(code, JOIN2_CODE_PREFIX, JOIN2_CODE_CONTEXT, JOIN2_KEYS, 'join code'), 'join code');
}

export function encodeOffer2Code(offer: Offer2Code): string {
  const obj = {
    v: 1, ctx: OFFER2_CODE_CONTEXT, vault_origin: offer.vault_origin, vault_id: offer.vault_id, initiator: offer.initiator, joiner: offer.joiner,
    nonce_i: offer.nonce_i, nonce_j_commit: offer.nonce_j_commit, trust_anchor: offer.trust_anchor, checkpoint: offer.checkpoint,
  };
  checkOffer2(obj, 'offer code');
  return encodeCode(OFFER2_CODE_PREFIX, obj);
}

export function parseOffer2Code(code: unknown): Offer2Code {
  return checkOffer2(decodeCode(code, OFFER2_CODE_PREFIX, OFFER2_CODE_CONTEXT, OFFER2_KEYS, 'offer code'), 'offer code');
}

export function encodeReveal2Code(reveal: Reveal2Code): string {
  const obj = { v: 1, ctx: REVEAL2_CODE_CONTEXT, vault_id: reveal.vault_id, joiner: reveal.joiner, nonce_j: reveal.nonce_j };
  checkReveal2(obj, 'reveal code');
  return encodeCode(REVEAL2_CODE_PREFIX, obj);
}

export function parseReveal2Code(code: unknown): Reveal2Code {
  return checkReveal2(decodeCode(code, REVEAL2_CODE_PREFIX, REVEAL2_CODE_CONTEXT, REVEAL2_KEYS, 'reveal code'), 'reveal code');
}
