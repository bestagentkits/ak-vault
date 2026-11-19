/**
 * Sandbox secret leases (spec §3.14, ADR 0007). A sandbox that is not a vault member asks
 * for named secrets; a person approves on an enrolled human device, which seals exactly
 * the approved values to the sandbox's one-time lease key. The Worker relays ciphertext
 * only: it never sees which secrets are asked for or their values.
 *
 * Request (signed by the sandbox's own request key; the subject sealed to seal_pub[e]):
 *   shared = X25519(esk, seal_pub[e])                     ; all-zero output rejected
 *   key    = HKDF(ikm=shared, salt=epk || seal_pub[e], info=utf8("akv1/lease-request"), L=32)
 *   aad    = {ctx:"akv1/lease-request", lease_id, vault_id, key_epoch, account, requester, lease_pub, ttl_s, ts, expires_at}
 *   ct     = XC20P(key, n, cjson({secrets:[{var, ref}], purpose?}), aad)
 *   sig    = Ed25519(requester_key, "akv1/lease-request", wire without sig)
 *
 * The lease code is the request digest b64(SHA-256(cjson(request))). The approver must
 * be given it out of band and the approving device refuses a request whose digest differs,
 * because the request is self-signed: nothing else ties it to the person's sandbox.
 *
 * Grant (signed by the approving device; values sealed to lease_pub):
 *   shared = X25519(esk, lease_pub)
 *   key    = HKDF(ikm=shared, salt=epk || lease_pub, info=utf8("akv1/lease-seal"), L=32)
 *   aad    = {ctx:"akv1/lease-seal", lease_id, vault_id, account, requester, lease_pub, request_digest, approver, ts, expires_at}
 *   ct     = XC20P(key, n, cjson({secrets:[{var, value}]}), aad)
 *   sig    = Ed25519(approver_key, "akv1/lease-grant", wire without sig)
 */
import { MAX_PLAINTEXT_BYTES, NONCE_BYTES, TAG_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { b64decode, b64encode } from './base64url.js';
import { concatBytes, randomBytes, sha256, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse } from './canonical-json.js';
import { signObjectAsync, type DeviceSigner } from './device-signer.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { MAX_ACCOUNT_LENGTH } from './membership-types.js';
import { MAX_ITEM_NAME, MAX_ITEM_VALUE } from './sealed-op.js';
import { SIGN_CONTEXT, deviceIdFromSignPub, kxKeyPairFromSecret, signKeyPairFromSeed, signObject, verifyObject } from './signing.js';
import { asArray, asB64, asEnum, asId, asInt, asObject, asString, asWellFormed, checkVersion, exactKeys } from './validate.js';
import { x25519Shared } from './wrap-x25519.js';

export const LEASE_REQUEST_ALG = 'x25519-xc20p-lease-req' as const;
export const LEASE_GRANT_ALG = 'x25519-xc20p-lease' as const;
export const LEASE_DECISIONS = ['allow', 'deny'] as const;
export type LeaseDecision = (typeof LEASE_DECISIONS)[number];
/** Shortest and longest lease lifetime a request may ask for, in seconds (1 minute .. 24 hours). */
export const LEASE_MIN_TTL_S = 60;
export const LEASE_MAX_TTL_S = 86_400;
/** Most secrets one lease may carry. */
export const LEASE_MAX_SECRETS = 32;
export const MAX_LEASE_PURPOSE = 200;
/** Environment variable names a lease may set: `^[A-Z_][A-Z0-9_]{0,127}$`. */
export const LEASE_VAR_PATTERN = /^[A-Z_][A-Z0-9_]{0,127}$/;
const MAX_SUBJECT_PLAINTEXT_BYTES = 16_384;
const REQUEST_INFO = utf8Encode('akv1/lease-request');
const SEAL_INFO = utf8Encode('akv1/lease-seal');

/** What the sandbox asks for: env var → secret reference (an item name), plus why. Never a value. */
export interface LeaseSubject {
  secrets: { var: string; ref: string }[];
  purpose?: string;
}

/** What the approving device seals: env var → value, a subset of the requested vars. */
export interface LeasePayload {
  secrets: { var: string; value: string }[];
}

export interface LeaseRequestWire {
  v: 1;
  alg: typeof LEASE_REQUEST_ALG;
  lease_id: string;
  vault_id: string;
  key_epoch: number;
  /** The requesting account (the token `sub`). */
  account: string;
  /** kid(requester_key): the sandbox's request device ID (not a member). */
  requester: string;
  /** b64 Ed25519 public key of the sandbox's request key. */
  requester_key: string;
  /** b64 X25519 public key the values are sealed to. */
  lease_pub: string;
  /** Lease lifetime the sandbox asks for, counted from the grant. */
  ttl_s: number;
  /** Unix ms. */
  ts: number;
  /** Unix ms; no grant is accepted at or after this instant. */
  expires_at: number;
  epk: string;
  n: string;
  ct: string;
  sig: string;
}

export interface LeaseGrantWire {
  v: 1;
  alg: typeof LEASE_GRANT_ALG;
  lease_id: string;
  vault_id: string;
  account: string;
  requester: string;
  /** b64 SHA-256 of cjson(request): the lease code. */
  request_digest: string;
  decision: LeaseDecision;
  /** device_id of the approving device; equals kid(approver_key). */
  approver: string;
  /** b64 Ed25519 public key of the approving device. */
  approver_key: string;
  /** Unix ms. */
  ts: number;
  /** Unix ms; allow only: the sandbox refuses the values at or after this instant. */
  expires_at?: number;
  epk?: string;
  n?: string;
  ct?: string;
  sig: string;
}

function asVar(value: unknown, what: string): string {
  const v = asString(value, what, 128, 1);
  if (!LEASE_VAR_PATTERN.test(v)) fail('bad_request', `${what} must match ${LEASE_VAR_PATTERN.source}`);
  return v;
}

function uniqueVars(vars: string[], what: string): void {
  if (new Set(vars).size !== vars.length) fail('bad_request', `${what} repeats a var`);
}

/** Validate a (decrypted or to-be-sealed) lease subject. */
export function parseLeaseSubject(value: unknown, what = 'lease subject'): LeaseSubject {
  const obj = asObject(value, what);
  exactKeys(obj, ['secrets'], what, ['purpose']);
  const list = asArray(obj['secrets'], `${what}.secrets`, LEASE_MAX_SECRETS);
  if (list.length === 0) fail('bad_request', `${what}.secrets is empty`);
  const secrets = list.map((entry, i) => {
    const e = asObject(entry, `${what}.secrets[${i}]`);
    exactKeys(e, ['var', 'ref'], `${what}.secrets[${i}]`);
    return { var: asVar(e['var'], `${what}.secrets[${i}].var`), ref: asWellFormed(asString(e['ref'], `${what}.secrets[${i}].ref`, MAX_ITEM_NAME, 1), `${what}.secrets[${i}].ref`) };
  });
  uniqueVars(secrets.map((s) => s.var), `${what}.secrets`);
  const out: LeaseSubject = { secrets };
  if (obj['purpose'] !== undefined) out.purpose = asWellFormed(asString(obj['purpose'], `${what}.purpose`, MAX_LEASE_PURPOSE, 1), `${what}.purpose`);
  return out;
}

/** Validate a (decrypted or to-be-sealed) lease payload. */
export function parseLeasePayload(value: unknown, what = 'lease payload'): LeasePayload {
  const obj = asObject(value, what);
  exactKeys(obj, ['secrets'], what);
  const list = asArray(obj['secrets'], `${what}.secrets`, LEASE_MAX_SECRETS);
  if (list.length === 0) fail('bad_request', `${what}.secrets is empty`);
  const secrets = list.map((entry, i) => {
    const e = asObject(entry, `${what}.secrets[${i}]`);
    exactKeys(e, ['var', 'value'], `${what}.secrets[${i}]`);
    return { var: asVar(e['var'], `${what}.secrets[${i}].var`), value: asWellFormed(asString(e['value'], `${what}.secrets[${i}].value`, MAX_ITEM_VALUE), `${what}.secrets[${i}].value`) };
  });
  uniqueVars(secrets.map((s) => s.var), `${what}.secrets`);
  return { secrets };
}

function ctLength(ct: string, max: number, what: string): void {
  const len = b64decode(ct).length;
  if (len < TAG_BYTES || len > max + TAG_BYTES) fail('bad_request', `${what}.ct length out of range`);
}

/** Structural parse of an untrusted lease request (no signature or AEAD check). */
export function parseLeaseRequest(value: unknown, what = 'lease request'): LeaseRequestWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== LEASE_REQUEST_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'lease_id', 'vault_id', 'key_epoch', 'account', 'requester', 'requester_key', 'lease_pub', 'ttl_s', 'ts', 'expires_at', 'epk', 'n', 'ct', 'sig'], what);
  const ct = asB64(obj['ct'], `${what}.ct`);
  ctLength(ct, MAX_SUBJECT_PLAINTEXT_BYTES, what);
  const ts = asInt(obj['ts'], `${what}.ts`);
  const expiresAt = asInt(obj['expires_at'], `${what}.expires_at`);
  if (expiresAt <= ts) fail('bad_request', `${what}.expires_at must be after ts`);
  const requesterKey = asB64(obj['requester_key'], `${what}.requester_key`, 32);
  const requester = asId(obj['requester'], `${what}.requester`);
  if (deviceIdFromSignPub(requesterKey) !== requester) fail('bad_request', `${what}.requester is not kid(requester_key)`);
  return {
    v: 1,
    alg: LEASE_REQUEST_ALG,
    lease_id: asId(obj['lease_id'], `${what}.lease_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    requester,
    requester_key: requesterKey,
    lease_pub: asB64(obj['lease_pub'], `${what}.lease_pub`, 32),
    ttl_s: asInt(obj['ttl_s'], `${what}.ttl_s`, LEASE_MIN_TTL_S, LEASE_MAX_TTL_S),
    ts,
    expires_at: expiresAt,
    epk: asB64(obj['epk'], `${what}.epk`, 32),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct,
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}

type RequestHeader = Pick<LeaseRequestWire, 'lease_id' | 'vault_id' | 'key_epoch' | 'account' | 'requester' | 'lease_pub' | 'ttl_s' | 'ts' | 'expires_at'>;

function requestAad(h: RequestHeader): object {
  return { ctx: 'akv1/lease-request', lease_id: h.lease_id, vault_id: h.vault_id, key_epoch: h.key_epoch, account: h.account, requester: h.requester, lease_pub: h.lease_pub, ttl_s: h.ttl_s, ts: h.ts, expires_at: h.expires_at };
}

/** b64 SHA-256 of the canonical request wire, signature included: the lease code a grant binds to. */
export function leaseRequestDigest(value: unknown): string {
  return b64encode(sha256(cjsonBytes(parseLeaseRequest(value))));
}

/** A fresh lease key (X25519) and request key (Ed25519 seed) for one lease; the sandbox keeps both in memory. */
export function generateLeaseKeys(): { leaseSecret: Uint8Array; leasePub: Uint8Array; requestSeed: Uint8Array; requestPub: Uint8Array } {
  const lease = kxKeyPairFromSecret(randomBytes(32));
  const request = signKeyPairFromSeed(randomBytes(32));
  return { leaseSecret: lease.secretKey, leasePub: lease.publicKey, requestSeed: request.secretKey, requestPub: request.publicKey };
}

export interface SealLeaseRequestArgs {
  vaultId: string;
  keyEpoch: number;
  account: string;
  /** The epoch's seal public key (b64 or raw), from the seal-key document. */
  sealPub: string | Uint8Array;
  leasePub: string | Uint8Array;
  ttlS: number;
  /** Unix ms. */
  ts: number;
  /** Unix ms; after `ts`. */
  expiresAt: number;
  subject: LeaseSubject;
}

/** Fixed values for test vectors only; not re-exported from the package index. */
export interface LeaseVectorValues {
  leaseId?: string;
  ephemeralSecret?: Uint8Array;
  nonce?: Uint8Array;
}

function key32(value: string | Uint8Array, what: string): Uint8Array {
  const bytes = typeof value === 'string' ? b64decode(value) : value;
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) fail('bad_request', `${what} must be 32 bytes`);
  return bytes;
}

/** Seal the subject to the epoch's seal key and sign the request with the sandbox's request key. */
export function sealLeaseRequest(requestSeed: Uint8Array, args: SealLeaseRequestArgs): LeaseRequestWire {
  return sealLeaseRequestWithVectorValues(requestSeed, args, {});
}

/** `sealLeaseRequest` with injected values (test vectors only); random where omitted. */
export function sealLeaseRequestWithVectorValues(requestSeed: Uint8Array, args: SealLeaseRequestArgs, fixed: LeaseVectorValues): LeaseRequestWire {
  const subject = parseLeaseSubject(args.subject);
  const sealPub = key32(args.sealPub, 'seal_pub');
  const requesterKey = signKeyPairFromSeed(requestSeed).publicKey;
  const header: RequestHeader = {
    lease_id: asId(fixed.leaseId ?? b64encode(randomBytes(16)), 'lease_id'),
    vault_id: asId(args.vaultId, 'vault_id'),
    key_epoch: asInt(args.keyEpoch, 'key_epoch', 1),
    account: asString(args.account, 'account', MAX_ACCOUNT_LENGTH, 1),
    requester: deviceIdFromSignPub(requesterKey),
    lease_pub: b64encode(key32(args.leasePub, 'lease_pub')),
    ttl_s: asInt(args.ttlS, 'ttl_s', LEASE_MIN_TTL_S, LEASE_MAX_TTL_S),
    ts: asInt(args.ts, 'ts'),
    expires_at: asInt(args.expiresAt, 'expires_at'),
  };
  if (header.expires_at <= header.ts) fail('bad_request', 'expires_at must be after ts');
  const plaintext = cjsonBytes(subject);
  if (plaintext.length > MAX_SUBJECT_PLAINTEXT_BYTES) fail('bad_request', 'lease subject too large');
  const esk = fixed.ephemeralSecret ?? randomBytes(32);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, sealPub), concatBytes(epk, sealPub), REQUEST_INFO);
  const nonce = fixed.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(key, nonce, plaintext, requestAad(header));
  const unsigned = { v: 1 as const, alg: LEASE_REQUEST_ALG, ...header, requester_key: b64encode(requesterKey), epk: b64encode(epk), n: b64encode(nonce), ct: b64encode(ct) };
  return parseLeaseRequest(signObject(SIGN_CONTEXT.leaseRequest, unsigned, requestSeed));
}

/** The signature check alone (what the Worker runs on `POST …/leases`). `invalid_signature` on failure. */
export function verifyLeaseRequestSignature(value: unknown): LeaseRequestWire {
  const wire = parseLeaseRequest(value);
  verifyObject(SIGN_CONTEXT.leaseRequest, wire, wire.requester_key);
  return wire;
}

export interface OpenLeaseRequestOptions {
  vaultId: string;
  /** The approving device's own account: a lease is answered only by its account. */
  account: string;
  /** The lease code the person typed or pasted (the request digest). */
  leaseCode: string;
}

export interface OpenedLeaseRequest {
  readonly wire: Readonly<LeaseRequestWire>;
  readonly subject: LeaseSubject;
  readonly digest: string;
}

/**
 * Approver side. Order: parse (`unsupported_version` / `bad_request`, including
 * `requester` ≠ kid(`requester_key`)); `vault_id` or `account` other than expected
 * (`bad_request`); signature under `requester_key` (`invalid_signature`); digest ≠ the
 * lease code (`forbidden`); all-zero shared secret (`bad_request`); AEAD
 * (`decrypt_failed`); subject not canonical or invalid (`bad_request`). The caller passes
 * `SealSK[key_epoch]` and checks expiry against its clock.
 */
export function openLeaseRequest(sealSecret: Uint8Array, value: unknown, opts: OpenLeaseRequestOptions): OpenedLeaseRequest {
  const wire = parseLeaseRequest(value);
  if (wire.vault_id !== opts.vaultId) fail('bad_request', 'lease request belongs to another vault');
  if (wire.account !== opts.account) fail('bad_request', 'lease request belongs to another account');
  verifyObject(SIGN_CONTEXT.leaseRequest, wire, wire.requester_key);
  const digest = leaseRequestDigest(wire);
  if (digest !== opts.leaseCode) fail('forbidden', 'lease request does not match the lease code');
  const sealPub = kxKeyPairFromSecret(sealSecret).publicKey;
  const epk = b64decode(wire.epk);
  const key = hkdf32(x25519Shared(sealSecret, epk), concatBytes(epk, sealPub), REQUEST_INFO);
  const pt = xc20pOpen(key, b64decode(wire.n), b64decode(wire.ct), requestAad(wire));
  const subject = Object.freeze(parseLeaseSubject(cjsonParse(pt)));
  return Object.freeze({ wire: Object.freeze(wire), subject, digest });
}

/** Structural parse of an untrusted grant (no signature, binding or AEAD check). */
export function parseLeaseGrant(value: unknown, what = 'lease grant'): LeaseGrantWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== LEASE_GRANT_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  const decision = asEnum(obj['decision'], LEASE_DECISIONS, `${what}.decision`);
  const keys = ['v', 'alg', 'lease_id', 'vault_id', 'account', 'requester', 'request_digest', 'decision', 'approver', 'approver_key', 'ts', 'sig'];
  exactKeys(obj, decision === 'allow' ? [...keys, 'expires_at', 'epk', 'n', 'ct'] : keys, what);
  const approverKey = asB64(obj['approver_key'], `${what}.approver_key`, 32);
  const approver = asId(obj['approver'], `${what}.approver`);
  if (deviceIdFromSignPub(approverKey) !== approver) fail('bad_request', `${what}.approver is not kid(approver_key)`);
  const out: LeaseGrantWire = {
    v: 1,
    alg: LEASE_GRANT_ALG,
    lease_id: asId(obj['lease_id'], `${what}.lease_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    account: asString(obj['account'], `${what}.account`, MAX_ACCOUNT_LENGTH, 1),
    requester: asId(obj['requester'], `${what}.requester`),
    request_digest: asB64(obj['request_digest'], `${what}.request_digest`, 32),
    decision,
    approver,
    approver_key: approverKey,
    ts: asInt(obj['ts'], `${what}.ts`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
  if (decision === 'allow') {
    out.expires_at = asInt(obj['expires_at'], `${what}.expires_at`);
    if (out.expires_at <= out.ts) fail('bad_request', `${what}.expires_at must be after ts`);
    out.epk = asB64(obj['epk'], `${what}.epk`, 32);
    out.n = asB64(obj['n'], `${what}.n`, NONCE_BYTES);
    out.ct = asB64(obj['ct'], `${what}.ct`);
    ctLength(out.ct, MAX_PLAINTEXT_BYTES, what);
  }
  return out;
}

type GrantHeader = Pick<LeaseGrantWire, 'lease_id' | 'vault_id' | 'account' | 'requester' | 'request_digest' | 'approver' | 'ts'> & { lease_pub: string; expires_at: number };

function grantAad(h: GrantHeader): object {
  return {
    ctx: 'akv1/lease-seal',
    lease_id: h.lease_id,
    vault_id: h.vault_id,
    account: h.account,
    requester: h.requester,
    lease_pub: h.lease_pub,
    request_digest: h.request_digest,
    approver: h.approver,
    ts: h.ts,
    expires_at: h.expires_at,
  };
}

export interface BuildLeaseGrantArgs {
  /** The opened request (the approving device has checked the lease code). */
  request: unknown;
  decision: LeaseDecision;
  /** Allow only: the approved values, a subset of the requested vars. */
  payload?: LeasePayload;
  /** Approver's Ed25519 public key (b64 or raw). */
  approverKey: string | Uint8Array;
  /** Unix ms; at or after the request's `ts` and before its `expires_at`. */
  ts: number;
  /** Allow only: unix ms, after `ts` and at most `ts + ttl_s` of the request; defaults to that maximum. */
  expiresAt?: number;
  /** The requested vars (from the opened subject): the payload may name only these. */
  requestedVars: readonly string[];
}

function checkPayloadVars(payload: LeasePayload, requested: readonly string[]): void {
  const allowed = new Set(requested);
  for (const s of payload.secrets) if (!allowed.has(s.var)) fail('forbidden', 'lease payload names a var the request did not ask for');
}

function unsignedGrant(args: BuildLeaseGrantArgs, fixed: LeaseVectorValues): Omit<LeaseGrantWire, 'sig'> {
  const request = parseLeaseRequest(args.request);
  const decision = asEnum(args.decision, LEASE_DECISIONS, 'decision');
  const approverKey = key32(args.approverKey, 'approver_key');
  const ts = asInt(args.ts, 'ts');
  if (ts < request.ts || ts >= request.expires_at) fail('bad_request', 'grant is outside the request lifetime');
  const base = {
    v: 1 as const,
    alg: LEASE_GRANT_ALG,
    lease_id: request.lease_id,
    vault_id: request.vault_id,
    account: request.account,
    requester: request.requester,
    request_digest: leaseRequestDigest(request),
    decision,
    approver: deviceIdFromSignPub(approverKey),
    approver_key: b64encode(approverKey),
    ts,
  };
  if (base.approver === request.requester) fail('forbidden', 'a lease cannot be granted by its requester');
  if (decision === 'deny') {
    if (args.payload !== undefined || args.expiresAt !== undefined) fail('bad_request', 'a deny carries no values or expiry');
    return base;
  }
  if (args.payload === undefined) fail('bad_request', 'an allow carries the approved values');
  const payload = parseLeasePayload(args.payload);
  checkPayloadVars(payload, args.requestedVars);
  const expiresAt = asInt(args.expiresAt ?? ts + request.ttl_s * 1000, 'expires_at');
  if (expiresAt <= ts || expiresAt > ts + request.ttl_s * 1000) fail('bad_request', 'grant expiry outside (ts, ts + ttl_s]');
  const plaintext = cjsonBytes(payload);
  if (plaintext.length > MAX_PLAINTEXT_BYTES) fail('bad_request', 'lease payload too large');
  const leasePub = b64decode(request.lease_pub);
  const esk = fixed.ephemeralSecret ?? randomBytes(32);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, leasePub), concatBytes(epk, leasePub), SEAL_INFO);
  const nonce = fixed.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(key, nonce, plaintext, grantAad({ ...base, lease_pub: request.lease_pub, expires_at: expiresAt }));
  return { ...base, expires_at: expiresAt, epk: b64encode(epk), n: b64encode(nonce), ct: b64encode(ct) };
}

/** Build and sign a grant with the approving device's key. */
export function signLeaseGrant(signSecret: Uint8Array, args: BuildLeaseGrantArgs): LeaseGrantWire {
  return signLeaseGrantWithVectorValues(signSecret, args, {});
}

/** `signLeaseGrant` with injected values (test vectors only). */
export function signLeaseGrantWithVectorValues(signSecret: Uint8Array, args: BuildLeaseGrantArgs, fixed: LeaseVectorValues): LeaseGrantWire {
  const own = b64encode(signKeyPairFromSeed(signSecret).publicKey);
  if (own !== b64encode(key32(args.approverKey, 'approver_key'))) fail('bad_request', 'approver_key is not the signing key');
  return parseLeaseGrant(signObject(SIGN_CONTEXT.leaseGrant, unsignedGrant(args, fixed), signSecret));
}

/** `signLeaseGrant` with a key held elsewhere (the browser dashboard's non-extractable key). Same bytes. */
export async function signLeaseGrantAsync(signer: DeviceSigner, args: BuildLeaseGrantArgs): Promise<LeaseGrantWire> {
  return parseLeaseGrant(await signObjectAsync(SIGN_CONTEXT.leaseGrant, unsignedGrant(args, {}), signer));
}

/**
 * Grant binding and signature checks shared by the Worker and the sandbox. Order:
 * parse (`unsupported_version` / `bad_request`); `lease_id`, `vault_id`, `account`,
 * `requester` or `request_digest` other than the request's (`bad_request`); `ts` outside
 * `[request.ts, request.expires_at)` or an allow expiry beyond `ts + ttl_s`
 * (`bad_request`); `approver` = `requester` (`forbidden`); signature under
 * `approver_key` (`invalid_signature`).
 */
export function verifyLeaseGrant(value: unknown, requestValue: unknown): LeaseGrantWire {
  const grant = parseLeaseGrant(value);
  const request = parseLeaseRequest(requestValue);
  if (grant.lease_id !== request.lease_id || grant.vault_id !== request.vault_id || grant.account !== request.account || grant.requester !== request.requester) {
    fail('bad_request', 'lease grant answers another request');
  }
  if (grant.request_digest !== leaseRequestDigest(request)) fail('bad_request', 'lease grant binds another request body');
  if (grant.ts < request.ts || grant.ts >= request.expires_at) fail('bad_request', 'lease grant is outside the request lifetime');
  if (grant.expires_at !== undefined && grant.expires_at > grant.ts + request.ttl_s * 1000) fail('bad_request', 'lease grant outlives the requested ttl_s');
  if (grant.approver === request.requester) fail('forbidden', 'a lease cannot be granted by its requester');
  verifyObject(SIGN_CONTEXT.leaseGrant, grant, grant.approver_key);
  return grant;
}

export interface OpenLeaseGrantOptions {
  /** Unix ms, the sandbox's clock. */
  now: number;
  /** The vars the sandbox asked for (it built the subject). */
  requestedVars: readonly string[];
  /** When set, the approver must be one of these device IDs (pinned out of band). */
  approvers?: readonly string[];
}

export type OpenedLeaseGrant = { decision: 'deny'; grant: LeaseGrantWire } | { decision: 'allow'; grant: LeaseGrantWire; payload: LeasePayload; expiresAt: number };

/**
 * Sandbox side. Order: `verifyLeaseGrant` steps; approver outside a pinned set
 * (`forbidden`); deny returns; `now` at or after `expires_at` (`bad_request`); all-zero
 * shared secret (`bad_request`); AEAD (`decrypt_failed`); payload not canonical or
 * invalid (`bad_request`); a var not requested (`forbidden`).
 */
export function openLeaseGrant(leaseSecret: Uint8Array, value: unknown, requestValue: unknown, opts: OpenLeaseGrantOptions): OpenedLeaseGrant {
  const grant = verifyLeaseGrant(value, requestValue);
  const request = parseLeaseRequest(requestValue);
  if (opts.approvers !== undefined && !opts.approvers.includes(grant.approver)) fail('forbidden', 'lease grant from an approver outside the pinned set');
  if (grant.decision === 'deny') return { decision: 'deny', grant };
  const expiresAt = grant.expires_at!;
  if (opts.now >= expiresAt) fail('bad_request', 'lease expired');
  const leasePub = kxKeyPairFromSecret(leaseSecret).publicKey;
  if (b64encode(leasePub) !== request.lease_pub) fail('decrypt_failed', 'lease secret does not match the request');
  const epk = b64decode(grant.epk!);
  const key = hkdf32(x25519Shared(leaseSecret, epk), concatBytes(epk, leasePub), SEAL_INFO);
  const pt = xc20pOpen(key, b64decode(grant.n!), b64decode(grant.ct!), grantAad({ ...grant, lease_pub: request.lease_pub, expires_at: expiresAt }));
  const payload = parseLeasePayload(cjsonParse(pt));
  checkPayloadVars(payload, opts.requestedVars);
  return { decision: 'allow', grant, payload, expiresAt };
}
