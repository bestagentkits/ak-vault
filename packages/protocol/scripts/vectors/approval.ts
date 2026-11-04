/** approval.json */
import { approvalRequestDigest, cjson, openApprovalRequest, signApprovalDecision, verifyApprovalDecision, type ApprovalRequestWire, type ApprovalSubject } from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { utf8Encode } from '../../src/bytes.js';
import { hkdf32 } from '../../src/hkdf.js';
import { b64decode } from '../../src/base64url.js';
import { SIGN_CONTEXT, signObject } from '../../src/signing.js';
import { sealApprovalRequestWithVectorValues } from '../../src/approval.js';
import { aliceLaptop, alicePhone, b64, BASE_TS, deviceFixture, flipByte, id, key32, negative, nonce, stranger, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';

const TTL_MS = 900_000;
const TS = BASE_TS + 7_200_000;
const vk = (epoch: number) => key32(`vk/epoch${epoch}`);
const FP = `sha256:${'ab'.repeat(32)}`;
const omit = (obj: object, key: string) => Object.fromEntries(Object.entries(obj).filter(([k]) => k !== key));

/** Encrypt and sign an arbitrary plaintext exactly as sealApprovalRequest would (for negative vectors it refuses). */
function rawRequest(header: Omit<ApprovalRequestWire, 'v' | 'alg' | 'n' | 'ct' | 'sig'>, plaintext: Uint8Array, label: string): ApprovalRequestWire {
  const key = hkdf32(vk(header.key_epoch), b64decode(header.request_id), utf8Encode('akv1/approval-request'));
  const aad = { ctx: 'akv1/approval-request', vault_id: header.vault_id, request_id: header.request_id, key_epoch: header.key_epoch, requester: header.requester, ts: header.ts, expires_at: header.expires_at };
  const n = nonce(`approval/${label}`);
  return signObject(SIGN_CONTEXT.approvalRequest, { v: 1 as const, alg: 'xc20p' as const, ...header, n: b64(n), ct: b64(xc20pSeal(key, n, plaintext, aad)) }, alicePhone.signSecret);
}

export function approvalVectors(): Record<string, unknown> {
  const seal = (label: string, subject: ApprovalSubject, epoch = 3) =>
    sealApprovalRequestWithVectorValues(
      vk(epoch),
      alicePhone.signSecret,
      { vaultId: VAULT_SHARED, keyEpoch: epoch, requester: alicePhone.record.device_id, ts: TS, expiresAt: TS + TTL_MS, subject },
      { requestId: id(`approval/${label}`), nonce: nonce(`approval/${label}`) },
    );
  const open = (wire: unknown, epoch = 3, vaultId = VAULT_SHARED, signPub = alicePhone.record.sign_pub) =>
    openApprovalRequest(vk(epoch), wire, { vaultId, requesterSignPub: signPub });
  const ok = (name: string, subject: ApprovalSubject, epoch = 3) => {
    const wire = seal(name, subject, epoch);
    if (cjson(open(wire, epoch).subject) !== cjson(subject)) throw new Error(`approval ${name}: round trip mismatch`);
    return { name, key_epoch: epoch, subject, plaintext: cjson(subject), wire, digest: approvalRequestDigest(wire) };
  };
  const full = ok('full', { secret: 'STRIPE_SECRET_KEY', agent: 'claude-code', fingerprint: FP, project: '/work/billing', purpose: 'deploy', reason: 'Publish the release notes', max_ttl_s: 86_400 });
  const w = full.wire;
  const header = { request_id: w.request_id, vault_id: w.vault_id, key_epoch: w.key_epoch, requester: w.requester, ts: w.ts, expires_at: w.expires_at };
  const pt = (s: string) => utf8Encode(s);
  const bad = (name: string, code: string, wire: unknown, epoch = 3, vaultId = VAULT_SHARED, signer = alicePhone) =>
    negative(name, code, { open_with_epoch: epoch, vault_id: vaultId, requester_device: signer.name, wire }, () => open(wire, epoch, vaultId, signer.record.sign_pub));
  const resign = (obj: Record<string, unknown>) => signObject(SIGN_CONTEXT.approvalRequest, obj, alicePhone.signSecret);

  const decide = (name: string, decision: 'deny' | 'allow_once' | 'allow_ttl', ttlS?: number) => {
    const wire = signApprovalDecision(aliceLaptop.signSecret, { request: w, decision, ...(ttlS !== undefined ? { ttlS } : {}), approver: aliceLaptop.record.device_id, ts: TS + 60_000 });
    verifyApprovalDecision(wire, w, { approverSignPub: aliceLaptop.record.sign_pub, maxTtlS: 86_400 });
    return { name, decision: wire };
  };
  const allowTtl = decide('allow_ttl', 'allow_ttl', 3_600);
  const d = allowTtl.decision;
  const other = seal('other', { secret: 'OTHER', agent: 'codex', fingerprint: FP, max_ttl_s: 3_600 });
  const resignD = (obj: Record<string, unknown>) => signObject(SIGN_CONTEXT.approvalDecision, obj, aliceLaptop.signSecret);
  const badD = (name: string, code: string, decision: unknown, request: unknown = w, signer = aliceLaptop, maxTtlS: number | undefined = 86_400) =>
    negative(name, code, { request, approver_device: signer.name, ...(maxTtlS !== undefined ? { max_ttl_s: maxTtlS } : {}), decision }, () =>
      verifyApprovalDecision(decision, request, { approverSignPub: signer.record.sign_pub, ...(maxTtlS !== undefined ? { maxTtlS } : {}) }),
    );

  return {
    version: 1,
    description:
      'Access approvals (spec §3.13). A requesting device encrypts the subject (metadata only, never a value) under VK[key_epoch] and signs the request; an approving device of the same account signs a decision bound to the request digest. ' +
      'key = HKDF-SHA256(ikm=VK[e], salt=b64decode(request_id), info=utf8("akv1/approval-request"), L=32) with VK[e] from seal-key.json seal_keys[].vk; aad = cjson({"ctx":"akv1/approval-request","vault_id","request_id","key_epoch","requester","ts","expires_at"}); ct = XChaCha20-Poly1305(key, n, cjson(subject), aad); sig = Ed25519 under context "akv1/approval-request" over the wire minus sig. ' +
      'digest = b64(SHA-256(cjson(request wire, sig included))). decision sig = Ed25519 under "akv1/approval-decision" over the decision minus sig. ' +
      'cases: sealApprovalRequest with the given nonce wire.n and request_id MUST reproduce wire byte for byte (Ed25519 is deterministic), openApprovalRequest MUST yield subject, and approvalRequestDigest MUST equal digest. ' +
      'openApprovalRequest order: parse (v or alg unknown: unsupported_version; exact keys, IDs, n 24 B, ct 16..16400 B, sig 64 B, expires_at > ts: bad_request); vault_id other than expected (bad_request); signature under the requester sign_pub (invalid_signature); AEAD (decrypt_failed); subject not canonical, unknown or missing keys, fingerprint not sha256:<64 hex>, max_ttl_s outside 60..2592000, empty optional text (bad_request). ' +
      'decisions: signApprovalDecision by approver alice-laptop at ts MUST reproduce decision byte for byte and verifyApprovalDecision(decision, cases[0].wire, {approver sign_pub, max_ttl_s 86400}) MUST accept it. ' +
      'verifyApprovalDecision order: parse (unsupported_version / bad_request; ttl_s present exactly for allow_ttl, 60..2592000); request_id, vault_id, requester or request_digest other than the request (bad_request); ts outside [request.ts, request.expires_at) (bad_request); ttl_s above max_ttl_s (bad_request); signature (invalid_signature). ' +
      'invalid: openApprovalRequest MUST fail with expect_error. decision_invalid: verifyApprovalDecision MUST fail with expect_error.',
    devices: [deviceFixture(alicePhone), deviceFixture(aliceLaptop), deviceFixture(stranger)],
    cases: [
      full,
      ok('minimal', { secret: 'Grüße API', agent: 'codex', fingerprint: FP, max_ttl_s: 60 }),
      ok('epoch1', { secret: 'A', agent: 'gemini', fingerprint: FP, max_ttl_s: 2_592_000 }, 1),
    ],
    decisions: [decide('deny', 'deny'), decide('allow_once', 'allow_once'), allowTtl],
    invalid: [
      bad('wrong_epoch_key', 'decrypt_failed', w, 2),
      bad('wrong_requester_key', 'invalid_signature', w, 3, VAULT_SHARED, stranger),
      bad('tampered_ct', 'invalid_signature', { ...w, ct: flipByte(w.ct, 3) }),
      bad('resigned_tampered_ct', 'decrypt_failed', resign({ ...w, ct: flipByte(w.ct, 3) })),
      bad('resigned_tampered_ts', 'decrypt_failed', resign({ ...w, ts: w.ts + 1 })),
      bad('resigned_tampered_requester', 'decrypt_failed', resign({ ...w, requester: id('device/other') })),
      bad('resigned_tampered_request_id', 'decrypt_failed', resign({ ...w, request_id: id('approval/elsewhere') })),
      bad('other_vault', 'bad_request', w, 3, VAULT_PERSONAL),
      bad('expires_not_after_ts', 'bad_request', resign({ ...w, expires_at: w.ts })),
      bad('extra_wire_key', 'bad_request', { ...w, note: 'x' }),
      bad('unknown_alg', 'unsupported_version', { ...w, alg: 'aes-gcm' }),
      bad('version_2', 'unsupported_version', { ...w, v: 2 }),
      bad('value_in_subject', 'bad_request', rawRequest(header, pt(`{"agent":"a","fingerprint":"${FP}","max_ttl_s":60,"secret":"A","value":"v"}`), 'value_in_subject')),
      bad('missing_fingerprint', 'bad_request', rawRequest(header, pt('{"agent":"a","max_ttl_s":60,"secret":"A"}'), 'missing_fingerprint')),
      bad('bad_fingerprint', 'bad_request', rawRequest(header, pt(`{"agent":"a","fingerprint":"sha256:${'AB'.repeat(32)}","max_ttl_s":60,"secret":"A"}`), 'bad_fingerprint')),
      bad('ttl_too_long', 'bad_request', rawRequest(header, pt(`{"agent":"a","fingerprint":"${FP}","max_ttl_s":2592001,"secret":"A"}`), 'ttl_too_long')),
      bad('empty_reason', 'bad_request', rawRequest(header, pt(`{"agent":"a","fingerprint":"${FP}","max_ttl_s":60,"reason":"","secret":"A"}`), 'empty_reason')),
      bad('non_canonical_subject', 'bad_request', rawRequest(header, pt(`{"secret":"A","agent":"a","fingerprint":"${FP}","max_ttl_s":60}`), 'non_canonical_subject')),
    ],
    decision_invalid: [
      badD('other_request', 'bad_request', d, other),
      badD('tampered_digest', 'bad_request', resignD({ ...d, request_digest: flipByte(d.request_digest, 0) })),
      badD('tampered_requester', 'bad_request', resignD({ ...d, requester: id('device/other') })),
      badD('before_request', 'bad_request', resignD({ ...d, ts: w.ts - 1 })),
      badD('at_expiry', 'bad_request', resignD({ ...d, ts: w.expires_at })),
      badD('ttl_over_request_max', 'bad_request', d, w, aliceLaptop, 600),
      badD('ttl_missing', 'bad_request', resignD(omit(d, 'ttl_s'))),
      badD('ttl_on_deny', 'bad_request', resignD({ ...d, decision: 'deny' })),
      badD('ttl_too_short', 'bad_request', resignD({ ...d, ttl_s: 59 })),
      badD('unknown_decision', 'bad_request', resignD({ ...d, decision: 'allow_forever' })),
      badD('tampered_decision', 'invalid_signature', { ...omit(d, 'ttl_s'), decision: 'allow_once' }),
      badD('wrong_approver_key', 'invalid_signature', d, w, stranger),
      badD('version_2', 'unsupported_version', { ...d, v: 2 }),
    ],
  };
}
