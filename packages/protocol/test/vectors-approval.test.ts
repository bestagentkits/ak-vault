/** Access-approval vectors (spec §3.13): request seal/open/digest and decision sign/verify. */
import { describe, expect, it } from 'vitest';
import { approvalRequestDigest, b64decode, cjson, openApprovalRequest, sealApprovalRequest, signApprovalDecision, signApprovalDecisionAsync, verifyApprovalDecision } from '../src/index.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sealApprovalRequestWithVectorValues } from '../src/approval.js';
import { expectCode, loadVector, named } from './helpers.js';

describe('approval.json', () => {
  const v = loadVector('approval.json');
  const seal = loadVector('seal-key.json');
  const vk = (epoch: number) => b64decode(seal.seal_keys.find((k: { key_epoch: number }) => k.key_epoch === epoch).vk);
  const dev = (name: string) => v.devices.find((d: { name: string }) => d.name === name);
  const requester = dev('alice-phone');
  const approver = dev('alice-laptop');
  const first = v.cases[0].wire;

  it.each(named(v.cases))('reproduces and opens %s', (_n, c) => {
    const w = c.wire;
    const args = { vaultId: w.vault_id, keyEpoch: c.key_epoch, requester: w.requester, ts: w.ts, expiresAt: w.expires_at, subject: c.subject };
    expect(sealApprovalRequestWithVectorValues(vk(c.key_epoch), b64decode(requester.sign_seed), args, { requestId: w.request_id, nonce: b64decode(w.n) })).toEqual(w);
    expect(cjson(c.subject)).toBe(c.plaintext);
    expect(openApprovalRequest(vk(c.key_epoch), w, { vaultId: w.vault_id, requesterSignPub: requester.record.sign_pub }).subject).toEqual(c.subject);
    expect(approvalRequestDigest(w)).toBe(c.digest);
  });
  it.each(named(v.decisions))('signs and verifies %s', async (_n, c) => {
    const d = c.decision;
    const signed = signApprovalDecision(b64decode(approver.sign_seed), { request: first, decision: d.decision, ...(d.ttl_s === undefined ? {} : { ttlS: d.ttl_s }), approver: d.approver, ts: d.ts });
    expect(signed).toEqual(d);
    const seed = b64decode(approver.sign_seed);
    const async = await signApprovalDecisionAsync({ sign: async (m) => ed25519.sign(m, seed) }, { request: first, decision: d.decision, ...(d.ttl_s === undefined ? {} : { ttlS: d.ttl_s }), approver: d.approver, ts: d.ts });
    expect(async).toEqual(d);
    expect(verifyApprovalDecision(d, first, { approverSignPub: approver.record.sign_pub, maxTtlS: 86400 })).toEqual(d);
  });
  it.each(named(v.invalid))('refuses to open %s', (_n, c) => {
    expectCode(() => openApprovalRequest(vk(c.open_with_epoch), c.wire, { vaultId: c.vault_id, requesterSignPub: dev(c.requester_device).record.sign_pub }), c.expect_error);
  });
  it.each(named(v.decision_invalid))('refuses decision %s', (_n, c) => {
    expectCode(() => verifyApprovalDecision(c.decision, c.request, { approverSignPub: dev(c.approver_device).record.sign_pub, maxTtlS: c.max_ttl_s }), c.expect_error);
  });
  it('fresh seals differ and still open', () => {
    const w = first;
    const args = { vaultId: w.vault_id, keyEpoch: v.cases[0].key_epoch, requester: w.requester, ts: w.ts, expiresAt: w.expires_at, subject: v.cases[0].subject };
    const a = sealApprovalRequest(vk(args.keyEpoch), b64decode(requester.sign_seed), args);
    const b = sealApprovalRequest(vk(args.keyEpoch), b64decode(requester.sign_seed), args);
    expect(a.request_id).not.toBe(b.request_id);
    expect(a.n).not.toBe(b.n);
    expect(openApprovalRequest(vk(args.keyEpoch), a, { vaultId: w.vault_id, requesterSignPub: requester.record.sign_pub }).subject).toEqual(args.subject);
  });
  it('refuses ttl_s on a non-ttl decision and a missing one on allow_ttl', () => {
    const base = { request: first, approver: approver.record.device_id, ts: first.ts + 1 };
    expectCode(() => signApprovalDecision(b64decode(approver.sign_seed), { ...base, decision: 'allow_once', ttlS: 60 }), 'bad_request');
    expectCode(() => signApprovalDecision(b64decode(approver.sign_seed), { ...base, decision: 'allow_ttl' }), 'bad_request');
  });
});
