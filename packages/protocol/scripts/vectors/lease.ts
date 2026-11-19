/** lease.json */
import { deriveSealKeyPair, leaseRequestDigest, openLeaseGrant, openLeaseRequest, type LeasePayload, type LeaseRequestWire, type LeaseSubject } from '../../src/index.js';
import { xc20pSeal } from '../../src/aead.js';
import { concatBytes, utf8Encode } from '../../src/bytes.js';
import { cjson } from '../../src/canonical-json.js';
import { hkdf32 } from '../../src/hkdf.js';
import { sealLeaseRequestWithVectorValues, signLeaseGrantWithVectorValues } from '../../src/lease.js';
import { SIGN_CONTEXT, kxKeyPairFromSecret, signKeyPairFromSeed, signObject } from '../../src/signing.js';
import { x25519Shared } from '../../src/wrap-x25519.js';
import { aliceLaptop, b64, BASE_TS, deviceFixture, flipByte, id, key32, negative, nonce, seed, stranger, VAULT_PERSONAL, VAULT_SHARED } from './fixtures.js';

const TS = BASE_TS + 9_000_000;
const WINDOW_MS = 900_000;
const ACCOUNT = 'acct_alice';
const vk = (epoch: number) => key32(`vk/epoch${epoch}`);
const sealPair = (epoch: number) => deriveSealKeyPair(vk(epoch), VAULT_SHARED, epoch);
const requestSeed = seed('lease/request-key');
const leaseSecret = seed('lease/lease-key');
const otherLeaseSecret = seed('lease/other-lease-key');
const leasePub = kxKeyPairFromSecret(leaseSecret).publicKey;
const requesterKey = signKeyPairFromSeed(requestSeed).publicKey;
const omit = (obj: object, ...keys: string[]) => Object.fromEntries(Object.entries(obj).filter(([k]) => !keys.includes(k)));

function sealRequest(label: string, subject: LeaseSubject, opts: { epoch?: number; ttlS?: number; leaseKey?: Uint8Array } = {}): LeaseRequestWire {
  const epoch = opts.epoch ?? 3;
  return sealLeaseRequestWithVectorValues(
    requestSeed,
    { vaultId: VAULT_SHARED, keyEpoch: epoch, account: ACCOUNT, sealPub: sealPair(epoch).publicKey, leasePub: opts.leaseKey ?? leasePub, ttlS: opts.ttlS ?? 3_600, ts: TS, expiresAt: TS + WINDOW_MS, subject },
    { leaseId: id(`lease/${label}`), ephemeralSecret: seed(`lease/esk/${label}`), nonce: nonce(`lease/${label}`) },
  );
}

/** Re-encrypt an arbitrary subject plaintext and re-sign, exactly as sealLeaseRequest would (for subjects it refuses). */
function rawRequest(base: LeaseRequestWire, plaintext: Uint8Array, label: string): LeaseRequestWire {
  const sealPub = sealPair(base.key_epoch).publicKey;
  const esk = seed(`lease/esk/${label}`);
  const epk = kxKeyPairFromSecret(esk).publicKey;
  const key = hkdf32(x25519Shared(esk, sealPub), concatBytes(epk, sealPub), utf8Encode('akv1/lease-request'));
  const aad = { ctx: 'akv1/lease-request', lease_id: base.lease_id, vault_id: base.vault_id, key_epoch: base.key_epoch, account: base.account, requester: base.requester, lease_pub: base.lease_pub, ttl_s: base.ttl_s, ts: base.ts, expires_at: base.expires_at };
  const n = nonce(`lease/${label}`);
  return signObject(SIGN_CONTEXT.leaseRequest, { ...omit(base, 'sig'), epk: b64(epk), n: b64(n), ct: b64(xc20pSeal(key, n, plaintext, aad)) }, requestSeed) as LeaseRequestWire;
}

const resignRequest = (obj: Record<string, unknown>) => signObject(SIGN_CONTEXT.leaseRequest, omit(obj, 'sig'), requestSeed);
const resignGrant = (obj: Record<string, unknown>, secret = aliceLaptop.signSecret) => signObject(SIGN_CONTEXT.leaseGrant, omit(obj, 'sig'), secret);

export function leaseVectors(): Record<string, unknown> {
  const subjectFull: LeaseSubject = { secrets: [{ var: 'STRIPE_KEY', ref: 'STRIPE_SECRET_KEY' }, { var: 'DB_URL', ref: 'Grüße DB' }], purpose: 'nightly migration' };
  const subjectMin: LeaseSubject = { secrets: [{ var: 'TOKEN', ref: 'A' }] };
  const openReq = (wire: unknown, code: string, epoch = 3, vaultId = VAULT_SHARED, account = ACCOUNT) =>
    openLeaseRequest(sealPair(epoch).secretKey, wire, { vaultId, account, leaseCode: code });
  const reqCase = (name: string, subject: LeaseSubject, epoch = 3) => {
    const wire = sealRequest(name, subject, { epoch });
    const digest = leaseRequestDigest(wire);
    if (cjson(openReq(wire, digest, epoch).subject) !== cjson(subject)) throw new Error(`lease ${name}: round trip mismatch`);
    return { name, key_epoch: epoch, esk: b64(seed(`lease/esk/${name}`)), subject, plaintext: cjson(subject), wire, digest };
  };
  const full = reqCase('full', subjectFull);
  const w = full.wire;
  const code = full.digest;
  const requested = subjectFull.secrets.map((s) => s.var);

  const grantTs = TS + 60_000;
  const grant = (label: string, decision: 'allow' | 'deny', payload?: LeasePayload, expiresAt?: number, request: LeaseRequestWire = w, vars: readonly string[] = requested, signer = aliceLaptop) =>
    signLeaseGrantWithVectorValues(
      signer.signSecret,
      { request, decision, ...(payload ? { payload } : {}), approverKey: signer.record.sign_pub, ts: grantTs, ...(expiresAt !== undefined ? { expiresAt } : {}), requestedVars: vars },
      { ephemeralSecret: seed(`lease/grant-esk/${label}`), nonce: nonce(`lease/grant/${label}`) },
    );
  const payloadAll: LeasePayload = { secrets: [{ var: 'STRIPE_KEY', value: 'sk_test_vector_only' }, { var: 'DB_URL', value: 'postgres://u:p@h/db' }] };
  const payloadSubset: LeasePayload = { secrets: [{ var: 'DB_URL', value: '' }] };
  const grantCase = (name: string, decision: 'allow' | 'deny', payload?: LeasePayload, expiresAt?: number) => {
    const g = grant(name, decision, payload, expiresAt);
    const opened = openLeaseGrant(leaseSecret, g, w, { now: grantTs, requestedVars: requested });
    if (decision === 'allow' && opened.decision === 'allow' && cjson(opened.payload) !== cjson(payload!)) throw new Error(`lease grant ${name}: round trip mismatch`);
    return { name, now: grantTs, esk: decision === 'allow' ? b64(seed(`lease/grant-esk/${name}`)) : null, payload: payload ?? null, plaintext: payload ? cjson(payload) : null, grant: g };
  };
  const allowAll = grantCase('allow_all', 'allow', payloadAll);
  const allowSubset = grantCase('allow_subset', 'allow', payloadSubset, grantTs + 600_000);
  const deny = grantCase('deny', 'deny');
  const g = allowAll.grant;

  const badReq = (name: string, codeExpected: string, wire: unknown, leaseCode: string, epoch = 3, vaultId = VAULT_SHARED, account = ACCOUNT) =>
    negative(name, codeExpected, { open_with_epoch: epoch, vault_id: vaultId, account, lease_code: leaseCode, wire }, () => openReq(wire, leaseCode, epoch, vaultId, account));
  const self = (wire: LeaseRequestWire) => leaseRequestDigest(wire);
  const raw = (label: string, text: string) => {
    const r = rawRequest(w, utf8Encode(text), label);
    return [r, self(r)] as const;
  };

  const other = sealRequest('other', subjectMin);
  const otherKey = sealRequest('other_lease_key', subjectFull, { leaseKey: kxKeyPairFromSecret(otherLeaseSecret).publicKey });
  const badGrant = (name: string, codeExpected: string, grantWire: unknown, opts: { request?: unknown; now?: number; secret?: Uint8Array; approvers?: string[]; vars?: string[] } = {}) => {
    const request = opts.request ?? w;
    const now = opts.now ?? grantTs;
    const secret = opts.secret ?? leaseSecret;
    const vars = opts.vars ?? requested;
    return negative(
      name,
      codeExpected,
      { request, now, lease_secret: b64(secret), requested_vars: vars, ...(opts.approvers ? { approvers: opts.approvers } : {}), grant: grantWire },
      () => openLeaseGrant(secret, grantWire, request, { now, requestedVars: vars, ...(opts.approvers ? { approvers: opts.approvers } : {}) }),
    );
  };
  // A grant that seals a var the request never named: built with a widened var list, refused by the sandbox.
  const extraVar = grant('extra_var', 'allow', { secrets: [{ var: 'STRIPE_KEY', value: 'x' }, { var: 'AWS_SECRET', value: 'y' }] }, undefined, w, [...requested, 'AWS_SECRET']);
  const strangerGrant = grant('stranger', 'allow', payloadAll, undefined, w, requested, stranger);

  return {
    version: 1,
    description:
      'Sandbox secret leases (spec §3.14). A sandbox that is not a vault member seals the subject {secrets:[{var,ref}],purpose?} to seal_pub[key_epoch] (seal-key.json seal_keys, vault shared) and signs the request with its own request key; ' +
      'shared = X25519(esk, seal_pub); key = HKDF-SHA256(ikm=shared, salt=epk || seal_pub, info=utf8("akv1/lease-request"), L=32); aad = cjson({"ctx":"akv1/lease-request","lease_id","vault_id","key_epoch","account","requester","lease_pub","ttl_s","ts","expires_at"}); sig = Ed25519(request key) under "akv1/lease-request" over the wire minus sig; requester = kid(requester_key). ' +
      'The lease code is digest = b64(SHA-256(cjson(request wire, sig included))). ' +
      'A grant is signed by the approving device under "akv1/lease-grant"; allow seals {secrets:[{var,value}]} to lease_pub: shared = X25519(esk, lease_pub); key = HKDF-SHA256(ikm=shared, salt=epk || lease_pub, info=utf8("akv1/lease-seal"), L=32); aad = cjson({"ctx":"akv1/lease-seal","lease_id","vault_id","account","requester","lease_pub","request_digest","approver","ts","expires_at"}); expires_at defaults to ts + ttl_s*1000. ' +
      'requests: sealLeaseRequest with the given esk, nonce wire.n and lease_id MUST reproduce wire byte for byte; openLeaseRequest(SealSK[key_epoch], wire, {vault_id, account, lease_code: digest}) MUST yield subject; leaseRequestDigest MUST equal digest. ' +
      'openLeaseRequest order: parse (v or alg unknown: unsupported_version; exact keys, IDs, requester = kid(requester_key), lease_pub/epk 32 B, n 24 B, ct 16..16400 B, sig 64 B, ttl_s 60..86400, expires_at > ts: bad_request); vault_id or account other than expected (bad_request); signature under requester_key (invalid_signature); digest other than lease_code (forbidden); AEAD (decrypt_failed); subject not canonical, unknown or missing keys, 1..32 secrets, var ^[A-Z_][A-Z0-9_]{0,127}$, unique vars, ref 1..4096, purpose 1..200 (bad_request). ' +
      'grants: signLeaseGrant by approver alice-laptop over requests[0].wire with the given esk and nonce MUST reproduce grant byte for byte; openLeaseGrant(lease_secret, grant, requests[0].wire, {now, requested_vars: the request vars}) MUST yield payload (or deny). ' +
      'openLeaseGrant order: parse (unsupported_version / bad_request; approver = kid(approver_key); allow has exactly expires_at, epk, n, ct and deny none); lease_id, vault_id, account, requester or request_digest other than the request (bad_request); ts outside [request.ts, request.expires_at) or expires_at > ts + ttl_s*1000 (bad_request); approver = requester (forbidden); signature under approver_key (invalid_signature); approver outside a pinned approvers set (forbidden); deny returns; now >= expires_at (bad_request); lease_secret not the request lease key, or AEAD failure (decrypt_failed); payload not canonical or invalid (bad_request); a var not in requested_vars (forbidden). ' +
      'request_invalid: openLeaseRequest MUST fail with expect_error. grant_invalid: openLeaseGrant MUST fail with expect_error.',
    account: ACCOUNT,
    vault_id: VAULT_SHARED,
    request_seed: b64(requestSeed),
    requester_key: b64(requesterKey),
    lease_secret: b64(leaseSecret),
    lease_pub: b64(leasePub),
    devices: [deviceFixture(aliceLaptop), deviceFixture(stranger)],
    requests: [full, reqCase('minimal', subjectMin, 1)],
    grants: [allowAll, allowSubset, deny],
    request_invalid: [
      badReq('wrong_lease_code', 'forbidden', w, self(other)),
      badReq('wrong_epoch_seal_key', 'decrypt_failed', w, code, 2),
      badReq('tampered_ct', 'invalid_signature', { ...w, ct: flipByte(w.ct, 3) }, code),
      badReq('resigned_tampered_ct', 'decrypt_failed', resignRequest({ ...w, ct: flipByte(w.ct, 3) }), self(resignRequest({ ...w, ct: flipByte(w.ct, 3) }) as LeaseRequestWire)),
      badReq('resigned_swapped_lease_pub', 'decrypt_failed', resignRequest({ ...w, lease_pub: b64(kxKeyPairFromSecret(otherLeaseSecret).publicKey) }), self(resignRequest({ ...w, lease_pub: b64(kxKeyPairFromSecret(otherLeaseSecret).publicKey) }) as LeaseRequestWire)),
      badReq('swapped_lease_pub_same_code', 'invalid_signature', { ...w, lease_pub: b64(kxKeyPairFromSecret(otherLeaseSecret).publicKey) }, code),
      badReq('requester_not_kid', 'bad_request', { ...w, requester: id('device/other') }, code),
      badReq('other_vault', 'bad_request', w, code, 3, VAULT_PERSONAL),
      badReq('other_account', 'bad_request', w, code, 3, VAULT_SHARED, 'acct_bob'),
      badReq('ttl_too_long', 'bad_request', resignRequest({ ...w, ttl_s: 86_401 }), code),
      badReq('expires_not_after_ts', 'bad_request', resignRequest({ ...w, expires_at: w.ts }), code),
      badReq('extra_wire_key', 'bad_request', { ...w, note: 'x' }, code),
      badReq('unknown_alg', 'unsupported_version', { ...w, alg: 'x25519-xc20p-seal' }, code),
      badReq('version_2', 'unsupported_version', { ...w, v: 2 }, code),
      badReq(...(['empty_secrets', 'bad_request'] as const), ...raw('empty_secrets', '{"secrets":[]}')),
      badReq(...(['lowercase_var', 'bad_request'] as const), ...raw('lowercase_var', '{"secrets":[{"ref":"A","var":"token"}]}')),
      badReq(...(['duplicate_var', 'bad_request'] as const), ...raw('duplicate_var', '{"secrets":[{"ref":"A","var":"T"},{"ref":"B","var":"T"}]}')),
      badReq(...(['value_in_subject', 'bad_request'] as const), ...raw('value_in_subject', '{"secrets":[{"ref":"A","value":"v","var":"T"}]}')),
      badReq(...(['empty_purpose', 'bad_request'] as const), ...raw('empty_purpose', '{"purpose":"","secrets":[{"ref":"A","var":"T"}]}')),
      badReq(...(['non_canonical_subject', 'bad_request'] as const), ...raw('non_canonical_subject', '{"secrets":[{"var":"T","ref":"A"}]}')),
    ],
    grant_invalid: [
      badGrant('tampered_ct', 'invalid_signature', { ...g, ct: flipByte(g.ct!, 2) }),
      badGrant('resigned_tampered_ct', 'decrypt_failed', resignGrant({ ...g, ct: flipByte(g.ct!, 2) })),
      badGrant('resigned_tampered_expiry', 'decrypt_failed', resignGrant({ ...g, expires_at: g.expires_at! - 1 })),
      badGrant('wrong_lease_key', 'decrypt_failed', g, { secret: otherLeaseSecret }),
      badGrant('expired', 'bad_request', g, { now: g.expires_at! }),
      badGrant('replay_on_other_request', 'bad_request', g, { request: other, vars: ['TOKEN'] }),
      badGrant('replay_on_other_lease_key', 'bad_request', g, { request: otherKey }),
      badGrant('resigned_wrong_digest', 'bad_request', resignGrant({ ...g, request_digest: flipByte(g.request_digest, 0) })),
      badGrant('ttl_overrun', 'bad_request', resignGrant({ ...g, expires_at: g.ts + w.ttl_s * 1000 + 1 })),
      badGrant('before_request', 'bad_request', resignGrant({ ...g, ts: w.ts - 1 })),
      badGrant('non_approved_var', 'forbidden', extraVar),
      badGrant('self_grant', 'forbidden', resignGrant({ ...g, approver: w.requester, approver_key: w.requester_key }, requestSeed)),
      badGrant('approver_key_swapped', 'invalid_signature', { ...g, approver: stranger.record.device_id, approver_key: stranger.record.sign_pub }),
      badGrant('unpinned_approver', 'forbidden', strangerGrant, { approvers: [aliceLaptop.record.device_id] }),
      badGrant('approver_not_kid', 'bad_request', { ...g, approver: id('device/other') }),
      badGrant('deny_with_values', 'bad_request', resignGrant({ ...g, decision: 'deny' })),
      badGrant('allow_without_values', 'bad_request', resignGrant(omit(g, 'epk', 'n', 'ct', 'expires_at'))),
      badGrant('unknown_decision', 'bad_request', resignGrant({ ...g, decision: 'allow_forever' })),
      badGrant('version_2', 'unsupported_version', { ...g, v: 2 }),
      badGrant('unknown_alg', 'unsupported_version', { ...deny.grant, alg: 'x25519-xc20p-input' }),
    ],
  };
}
