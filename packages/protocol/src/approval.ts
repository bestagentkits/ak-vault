/**
 * Remote access approvals (spec §3.13): a device whose local resolve found no grant
 * publishes an approval request, and the person answers it from another enrolled
 * device of the same account (a CLI device elsewhere or the `/app` browser device).
 * The server stores ciphertext and signatures only: it never sees which secret, agent
 * or project is asked about, and it cannot forge an answer, because only an enrolled
 * device key signs a decision and the requesting device verifies it before it writes a
 * local grant.
 *
 *   key  = HKDF(ikm=VK[e], salt=b64decode(request_id), info=utf8("akv1/approval-request"), L=32)
 *   aad  = {ctx:"akv1/approval-request", vault_id, request_id, key_epoch, requester, ts, expires_at}
 *   ct   = XC20P(key, n, cjson(subject), aad)
 *   sig  = Ed25519(requester sign key, "akv1/approval-request", wire without sig)
 *
 * A decision is signed under `akv1/approval-decision` and names the request by its
 * digest, so it cannot be moved to another request, device or vault, and the requester
 * accepts at most one decision per request it has open (anti-replay).
 *
 * The subject carries metadata only (secret name, agent, fingerprint, project,
 * purpose, reason); it never carries a value.
 */
import { NONCE_BYTES, TAG_BYTES, xc20pOpen, xc20pSeal } from './aead.js';
import { b64decode, b64encode } from './base64url.js';
import { randomBytes, sha256, utf8Encode } from './bytes.js';
import { cjsonBytes, cjsonParse } from './canonical-json.js';
import { fail } from './errors.js';
import { hkdf32 } from './hkdf.js';
import { MAX_ITEM_NAME } from './sealed-op.js';
import { SIGN_CONTEXT, signObject, verifyObject } from './signing.js';
import { asB64, asEnum, asId, asInt, asObject, asPrintableAscii, asString, asWellFormed, checkVersion, exactKeys } from './validate.js';

export const APPROVAL_ALG = 'xc20p' as const;
export const APPROVAL_DECISIONS = ['deny', 'allow_once', 'allow_ttl'] as const;
export type ApprovalDecisionKind = (typeof APPROVAL_DECISIONS)[number];
/** Shortest and longest "allow for a while" an approval may carry, in seconds (1 minute .. 30 days). */
export const APPROVAL_MIN_TTL_S = 60;
export const APPROVAL_MAX_TTL_S = 2_592_000;
export const MAX_APPROVAL_AGENT = 128;
export const MAX_APPROVAL_PROJECT = 1024;
export const MAX_APPROVAL_PURPOSE = 200;
export const MAX_APPROVAL_REASON = 500;
const MAX_SUBJECT_PLAINTEXT_BYTES = 16_384;
const FINGERPRINT = /^sha256:[0-9a-f]{64}$/;
const INFO = utf8Encode('akv1/approval-request');

/** What the requesting device asks the person to allow. Metadata only, never a value. */
export interface ApprovalSubject {
  /** The secret's name as the requesting device resolves it. */
  secret: string;
  /** The agent's display label (adapter name), as the device identified it. */
  agent: string;
  /** `sha256:<hex>` of the agent binary, from the device's process-tree walk. */
  fingerprint: string;
  project?: string;
  purpose?: string;
  /** Why the agent asked, in its own words; shown as untrusted text. */
  reason?: string;
  /** The longest "allow for a while" the requesting device will accept, in seconds. */
  max_ttl_s: number;
}

export interface ApprovalRequestWire {
  v: 1;
  alg: typeof APPROVAL_ALG;
  request_id: string;
  vault_id: string;
  key_epoch: number;
  /** device_id of the requesting device; it signs the request. */
  requester: string;
  n: string;
  ct: string;
  /** Unix ms. */
  ts: number;
  /** Unix ms; no decision is accepted after this instant. */
  expires_at: number;
  sig: string;
}

export interface ApprovalDecisionWire {
  v: 1;
  request_id: string;
  vault_id: string;
  requester: string;
  /** b64 SHA-256 of cjson(request wire, sig included). */
  request_digest: string;
  decision: ApprovalDecisionKind;
  /** Present exactly when `decision` is `allow_ttl`. */
  ttl_s?: number;
  /** device_id of the approving device; it signs the decision. */
  approver: string;
  /** Unix ms. */
  ts: number;
  sig: string;
}

function optionalText(obj: Record<string, unknown>, key: string, max: number, what: string): string | undefined {
  if (obj[key] === undefined) return undefined;
  return asWellFormed(asString(obj[key], `${what}.${key}`, max, 1), `${what}.${key}`);
}

/** Validate a (decrypted or to-be-sealed) approval subject. */
export function parseApprovalSubject(value: unknown, what = 'approval subject'): ApprovalSubject {
  const obj = asObject(value, what);
  exactKeys(obj, ['secret', 'agent', 'fingerprint', 'max_ttl_s'], what, ['project', 'purpose', 'reason']);
  const fingerprint = asPrintableAscii(obj['fingerprint'], `${what}.fingerprint`, 71, 71);
  if (!FINGERPRINT.test(fingerprint)) fail('bad_request', `${what}.fingerprint must be sha256:<64 hex>`);
  const out: ApprovalSubject = {
    secret: asWellFormed(asString(obj['secret'], `${what}.secret`, MAX_ITEM_NAME, 1), `${what}.secret`),
    agent: asPrintableAscii(obj['agent'], `${what}.agent`, MAX_APPROVAL_AGENT, 1),
    fingerprint,
    max_ttl_s: asInt(obj['max_ttl_s'], `${what}.max_ttl_s`, APPROVAL_MIN_TTL_S, APPROVAL_MAX_TTL_S),
  };
  const project = optionalText(obj, 'project', MAX_APPROVAL_PROJECT, what);
  const purpose = optionalText(obj, 'purpose', MAX_APPROVAL_PURPOSE, what);
  const reason = optionalText(obj, 'reason', MAX_APPROVAL_REASON, what);
  if (project !== undefined) out.project = project;
  if (purpose !== undefined) out.purpose = purpose;
  if (reason !== undefined) out.reason = reason;
  return out;
}

/** Structural parse of an untrusted approval-request wire object (no signature or AEAD check). */
export function parseApprovalRequest(value: unknown, what = 'approval request'): ApprovalRequestWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  if (obj['alg'] !== APPROVAL_ALG) fail('unsupported_version', `${what}: unsupported alg`);
  exactKeys(obj, ['v', 'alg', 'request_id', 'vault_id', 'key_epoch', 'requester', 'n', 'ct', 'ts', 'expires_at', 'sig'], what);
  const ct = asB64(obj['ct'], `${what}.ct`);
  const ctLength = b64decode(ct).length;
  if (ctLength < TAG_BYTES || ctLength > MAX_SUBJECT_PLAINTEXT_BYTES + TAG_BYTES) fail('bad_request', `${what}.ct length out of range`);
  const ts = asInt(obj['ts'], `${what}.ts`);
  const expiresAt = asInt(obj['expires_at'], `${what}.expires_at`);
  if (expiresAt <= ts) fail('bad_request', `${what}.expires_at must be after ts`);
  return {
    v: 1,
    alg: APPROVAL_ALG,
    request_id: asId(obj['request_id'], `${what}.request_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    key_epoch: asInt(obj['key_epoch'], `${what}.key_epoch`, 1),
    requester: asId(obj['requester'], `${what}.requester`),
    n: asB64(obj['n'], `${what}.n`, NONCE_BYTES),
    ct,
    ts,
    expires_at: expiresAt,
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
}

type RequestHeader = Pick<ApprovalRequestWire, 'vault_id' | 'request_id' | 'key_epoch' | 'requester' | 'ts' | 'expires_at'>;

function requestAad(w: RequestHeader): object {
  return { ctx: 'akv1/approval-request', vault_id: w.vault_id, request_id: w.request_id, key_epoch: w.key_epoch, requester: w.requester, ts: w.ts, expires_at: w.expires_at };
}

function subjectKey(vk: Uint8Array, requestId: string): Uint8Array {
  if (!(vk instanceof Uint8Array) || vk.length !== 32) fail('bad_request', 'vault key must be 32 bytes');
  return hkdf32(vk, b64decode(requestId), INFO);
}

export interface SealApprovalRequestArgs {
  vaultId: string;
  keyEpoch: number;
  /** device_id of the requesting device (the signer). */
  requester: string;
  /** Unix ms. */
  ts: number;
  /** Unix ms; after `ts`. */
  expiresAt: number;
  subject: ApprovalSubject;
}

/** Fixed values for test vectors only; not re-exported from the package index. */
export interface ApprovalVectorValues {
  requestId?: string;
  nonce?: Uint8Array;
}

/** Encrypt `args.subject` under `VK[keyEpoch]` and sign the request with the requester's device key. */
export function sealApprovalRequest(vk: Uint8Array, signSecret: Uint8Array, args: SealApprovalRequestArgs): ApprovalRequestWire {
  return sealApprovalRequestWithVectorValues(vk, signSecret, args, {});
}

/** `sealApprovalRequest` with injected values (test vectors only); random where omitted. */
export function sealApprovalRequestWithVectorValues(vk: Uint8Array, signSecret: Uint8Array, args: SealApprovalRequestArgs, fixed: ApprovalVectorValues): ApprovalRequestWire {
  const subject = parseApprovalSubject(args.subject);
  const header: RequestHeader = {
    vault_id: asId(args.vaultId, 'vault_id'),
    request_id: asId(fixed.requestId ?? b64encode(randomBytes(16)), 'request_id'),
    key_epoch: asInt(args.keyEpoch, 'key_epoch', 1),
    requester: asId(args.requester, 'requester'),
    ts: asInt(args.ts, 'ts'),
    expires_at: asInt(args.expiresAt, 'expires_at'),
  };
  if (header.expires_at <= header.ts) fail('bad_request', 'expires_at must be after ts');
  const plaintext = cjsonBytes(subject);
  if (plaintext.length > MAX_SUBJECT_PLAINTEXT_BYTES) fail('bad_request', 'approval subject too large');
  const nonce = fixed.nonce ?? randomBytes(NONCE_BYTES);
  const ct = xc20pSeal(subjectKey(vk, header.request_id), nonce, plaintext, requestAad(header));
  const unsigned = { v: 1 as const, alg: APPROVAL_ALG, ...header, n: b64encode(nonce), ct: b64encode(ct) };
  return signObject(SIGN_CONTEXT.approvalRequest, unsigned, signSecret);
}

export interface OpenedApprovalRequest {
  readonly wire: Readonly<ApprovalRequestWire>;
  readonly subject: ApprovalSubject;
}

/**
 * Verify and open an approval request. Order: parse (`unsupported_version` /
 * `bad_request`); `vault_id` ≠ expected (`bad_request`); signature under the
 * requester's `sign_pub` (`invalid_signature`); AEAD (`decrypt_failed`); subject not
 * canonical or invalid (`bad_request`). The caller resolves `requesterSignPub` from its
 * verified membership state and checks that the requester is a current human device
 * of its own account.
 */
export function openApprovalRequest(vk: Uint8Array, value: unknown, opts: { vaultId: string; requesterSignPub: Uint8Array | string }): OpenedApprovalRequest {
  const wire = parseApprovalRequest(value);
  if (wire.vault_id !== opts.vaultId) fail('bad_request', 'approval request belongs to another vault');
  verifyObject(SIGN_CONTEXT.approvalRequest, wire, opts.requesterSignPub);
  const pt = xc20pOpen(subjectKey(vk, wire.request_id), b64decode(wire.n), b64decode(wire.ct), requestAad(wire));
  const subject = Object.freeze(parseApprovalSubject(cjsonParse(pt)));
  return Object.freeze({ wire: Object.freeze(wire), subject });
}

/** b64 SHA-256 of the canonical request wire, signature included: what a decision binds to. */
export function approvalRequestDigest(value: unknown): string {
  return b64encode(sha256(cjsonBytes(parseApprovalRequest(value))));
}

/** Structural parse of an untrusted decision (no signature or binding check). */
export function parseApprovalDecision(value: unknown, what = 'approval decision'): ApprovalDecisionWire {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  const decision = asEnum(obj['decision'], APPROVAL_DECISIONS, `${what}.decision`);
  const keys = ['v', 'request_id', 'vault_id', 'requester', 'request_digest', 'decision', 'approver', 'ts', 'sig'];
  exactKeys(obj, decision === 'allow_ttl' ? [...keys, 'ttl_s'] : keys, what);
  const out: ApprovalDecisionWire = {
    v: 1,
    request_id: asId(obj['request_id'], `${what}.request_id`),
    vault_id: asId(obj['vault_id'], `${what}.vault_id`),
    requester: asId(obj['requester'], `${what}.requester`),
    request_digest: asB64(obj['request_digest'], `${what}.request_digest`, 32),
    decision,
    approver: asId(obj['approver'], `${what}.approver`),
    ts: asInt(obj['ts'], `${what}.ts`),
    sig: asB64(obj['sig'], `${what}.sig`, 64),
  };
  if (decision === 'allow_ttl') out.ttl_s = asInt(obj['ttl_s'], `${what}.ttl_s`, APPROVAL_MIN_TTL_S, APPROVAL_MAX_TTL_S);
  return out;
}

export interface SignApprovalDecisionArgs {
  /** The request being answered, exactly as fetched. */
  request: unknown;
  decision: ApprovalDecisionKind;
  /** Seconds; required for `allow_ttl`, refused otherwise. */
  ttlS?: number;
  /** device_id of the approving device (the signer). */
  approver: string;
  /** Unix ms. */
  ts: number;
}

/** Answer `args.request` and sign the answer with the approving device's key. */
export function signApprovalDecision(signSecret: Uint8Array, args: SignApprovalDecisionArgs): ApprovalDecisionWire {
  const request = parseApprovalRequest(args.request);
  const decision = asEnum(args.decision, APPROVAL_DECISIONS, 'decision');
  if ((decision === 'allow_ttl') !== (args.ttlS !== undefined)) fail('bad_request', 'ttl_s is required for allow_ttl and refused otherwise');
  const unsigned: Omit<ApprovalDecisionWire, 'sig'> = {
    v: 1,
    request_id: request.request_id,
    vault_id: request.vault_id,
    requester: request.requester,
    request_digest: approvalRequestDigest(request),
    decision,
    ...(decision === 'allow_ttl' ? { ttl_s: asInt(args.ttlS, 'ttl_s', APPROVAL_MIN_TTL_S, APPROVAL_MAX_TTL_S) } : {}),
    approver: asId(args.approver, 'approver'),
    ts: asInt(args.ts, 'ts'),
  };
  return parseApprovalDecision(signObject(SIGN_CONTEXT.approvalDecision, unsigned, signSecret));
}

export interface VerifyApprovalDecisionOptions {
  /** `sign_pub` of the device named by the decision's `approver`, from verified membership. */
  approverSignPub: Uint8Array | string;
  /** The subject's `max_ttl_s`, when the verifier opened the request (the requester always does). */
  maxTtlS?: number;
}

/**
 * Verify a decision against the request it answers. Order: parse (`unsupported_version`
 * / `bad_request`); `request_id`, `vault_id`, `requester` or `request_digest` other than
 * the request's (`bad_request`); `ts` outside `[request.ts, request.expires_at)`
 * (`bad_request`); `ttl_s` above `maxTtlS` (`bad_request`); signature under
 * `approverSignPub` (`invalid_signature`). The caller checks that `approver` is a current
 * human device of the requester's account.
 */
export function verifyApprovalDecision(value: unknown, requestValue: unknown, opts: VerifyApprovalDecisionOptions): ApprovalDecisionWire {
  const decision = parseApprovalDecision(value);
  const request = parseApprovalRequest(requestValue);
  if (decision.request_id !== request.request_id || decision.vault_id !== request.vault_id || decision.requester !== request.requester) {
    fail('bad_request', 'approval decision answers another request');
  }
  if (decision.request_digest !== approvalRequestDigest(request)) fail('bad_request', 'approval decision binds another request body');
  if (decision.ts < request.ts || decision.ts >= request.expires_at) fail('bad_request', 'approval decision is outside the request lifetime');
  if (decision.ttl_s !== undefined && opts.maxTtlS !== undefined && decision.ttl_s > opts.maxTtlS) fail('bad_request', 'approval decision exceeds the requested max_ttl_s');
  verifyObject(SIGN_CONTEXT.approvalDecision, decision, opts.approverSignPub);
  return decision;
}
