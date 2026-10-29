/**
 * Enrollment codes (spec §3.8): the join code a new device prints (`akj1-`) and
 * the offer code the approving owner device answers with (`ako1-`). Each is the
 * prefix followed by `b64(cjson(obj))`. They carry only public keys, nonces, IDs
 * and a signed checkpoint; the six-digit SAS authenticates the exchange.
 * Parsing checks no signature.
 */
import { b64decode, b64encode } from './base64url.js';
import { utf8Encode } from './bytes.js';
import { cjson, cjsonParse } from './canonical-json.js';
import { parseCheckpoint, type Checkpoint } from './checkpoints.js';
import { fail, isAkvError } from './errors.js';
import { MAX_ACCOUNT_LENGTH, parseDevice, type DeviceRecord } from './membership-types.js';
import { asB64, asId, asObject, asPrintableAscii, asString, exactKeys, type Obj } from './validate.js';

export const JOIN_CODE_PREFIX = 'akj1-';
export const OFFER_CODE_PREFIX = 'ako1-';
export const JOIN_CODE_CONTEXT = 'agentkit/akv1-join';
export const OFFER_CODE_CONTEXT = 'agentkit/akv1-offer';
export const MAX_ENROLL_CODE_BYTES = 8192;
export const MAX_DEVICE_LABEL_BYTES = 64;

const JOIN_KEYS = ['v', 'ctx', 'account', 'device', 'nonce_j', 'label'] as const;
const OFFER_KEYS = ['v', 'ctx', 'vault_origin', 'vault_id', 'initiator', 'joiner', 'nonce_i', 'nonce_j', 'trust_anchor', 'checkpoint'] as const;

export interface JoinCode {
  account: string;
  device: DeviceRecord;
  nonce_j: string;
  label: string;
}

export interface OfferCode {
  vault_origin: string;
  vault_id: string;
  initiator: string;
  joiner: string;
  nonce_i: string;
  nonce_j: string;
  trust_anchor: string;
  checkpoint: Checkpoint;
}

const IPV4_OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
const LOOPBACK_V4 = new RegExp(`^127\\.${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}$`);
const ORIGIN = /^(https|http):\/\/(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::([1-9][0-9]{0,4}))?$/;

/** Canonical vault origin `https://host[:port]` (`http://` only for loopback). */
export function isCanonicalOrigin(origin: string): boolean {
  if (typeof origin !== 'string' || origin.length > 2048) return false;
  const m = ORIGIN.exec(origin);
  if (!m) return false;
  const [, scheme, host, port] = m as unknown as [string, string, string, string | undefined];
  if (host.includes('..')) return false;
  if (port !== undefined) {
    const n = Number(port);
    if (n > 65_535 || (scheme === 'https' && n === 443) || (scheme === 'http' && n === 80)) return false;
  }
  if (scheme === 'http') return host === 'localhost' || host === '[::1]' || LOOPBACK_V4.test(host);
  return true;
}

export function decodeCode(code: unknown, prefix: string, ctx: string, keys: readonly string[], what: string): Obj {
  if (typeof code !== 'string') fail('bad_request', `${what} must be a string`);
  const compact = code.replace(/\p{White_Space}/gu, '');
  if (utf8Encode(compact).length > MAX_ENROLL_CODE_BYTES) fail('bad_request', `${what} is too long`);
  if (!compact.startsWith(prefix)) fail('bad_request', `${what} has the wrong prefix`);
  const obj = asObject(cjsonParse(b64decode(compact.slice(prefix.length))), what);
  exactKeys(obj, keys, what);
  if (obj['v'] !== 1) fail('unsupported_version', `${what}: unsupported version`);
  if (obj['ctx'] !== ctx) fail('bad_request', `${what} has the wrong context`);
  return obj;
}

export function checkJoinDevice(obj: Obj, what: string): { account: string; device: DeviceRecord; label: string } {
  const account = asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1);
  const device = parseDevice(obj['device'], `${what}.device`);
  if (device.account !== account || device.role !== 'owner' || device.kind !== 'human') fail('bad_request', `${what}.device must be a human owner device of the account`);
  return { account, device, label: asPrintableAscii(obj['label'], `${what}.label`, MAX_DEVICE_LABEL_BYTES) };
}

function checkJoin(obj: Obj, what: string): JoinCode {
  return { ...checkJoinDevice(obj, what), nonce_j: asB64(obj['nonce_j'], `${what}.nonce_j`, 16) };
}

/** Only the code's own `v` yields unsupported_version; an embedded checkpoint that fails to parse is bad_request. */
export function parseEmbeddedCheckpoint(value: unknown, what: string): Checkpoint {
  try {
    return parseCheckpoint(value, what);
  } catch (err) {
    if (isAkvError(err) && err.code === 'unsupported_version') fail('bad_request', `${what} does not parse`);
    throw err;
  }
}

function checkOffer(obj: Obj, what: string): OfferCode {
  const origin = obj['vault_origin'];
  if (typeof origin !== 'string' || !isCanonicalOrigin(origin)) fail('bad_request', `${what}.vault_origin is not a canonical origin`);
  const vaultId = asId(obj['vault_id'], `${what}.vault_id`);
  const offer: OfferCode = {
    vault_origin: origin,
    vault_id: vaultId,
    initiator: asId(obj['initiator'], `${what}.initiator`),
    joiner: asId(obj['joiner'], `${what}.joiner`),
    nonce_i: asB64(obj['nonce_i'], `${what}.nonce_i`, 16),
    nonce_j: asB64(obj['nonce_j'], `${what}.nonce_j`, 16),
    trust_anchor: asB64(obj['trust_anchor'], `${what}.trust_anchor`, 32),
    checkpoint: parseEmbeddedCheckpoint(obj['checkpoint'], `${what}.checkpoint`),
  };
  if (offer.checkpoint.vault_id !== vaultId) fail('bad_request', `${what}.checkpoint names another vault`);
  return offer;
}

export function encodeCode(prefix: string, obj: object): string {
  const text = prefix + b64encode(utf8Encode(cjson(obj)));
  if (text.length > MAX_ENROLL_CODE_BYTES) fail('bad_request', 'enrollment code is too long');
  return text;
}

export function encodeJoinCode(join: JoinCode): string {
  const obj = { v: 1, ctx: JOIN_CODE_CONTEXT, account: join.account, device: join.device, nonce_j: join.nonce_j, label: join.label };
  checkJoin(obj, 'join code');
  return encodeCode(JOIN_CODE_PREFIX, obj);
}

export function parseJoinCode(code: unknown): JoinCode {
  return checkJoin(decodeCode(code, JOIN_CODE_PREFIX, JOIN_CODE_CONTEXT, JOIN_KEYS, 'join code'), 'join code');
}

export function encodeOfferCode(offer: OfferCode): string {
  const obj = {
    v: 1, ctx: OFFER_CODE_CONTEXT, vault_origin: offer.vault_origin, vault_id: offer.vault_id, initiator: offer.initiator, joiner: offer.joiner,
    nonce_i: offer.nonce_i, nonce_j: offer.nonce_j, trust_anchor: offer.trust_anchor, checkpoint: offer.checkpoint,
  };
  checkOffer(obj, 'offer code');
  return encodeCode(OFFER_CODE_PREFIX, obj);
}

export function parseOfferCode(code: unknown): OfferCode {
  return checkOffer(decodeCode(code, OFFER_CODE_PREFIX, OFFER_CODE_CONTEXT, OFFER_KEYS, 'offer code'), 'offer code');
}
