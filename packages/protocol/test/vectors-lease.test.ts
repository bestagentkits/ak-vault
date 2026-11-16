/** Sandbox lease vectors (spec §3.14): request seal/open/digest, grant sign/open, and every refusal. */
import { describe, expect, it } from 'vitest';
import { b64decode, cjson, generateLeaseKeys, leaseRequestDigest, openLeaseGrant, openLeaseRequest, sealLeaseRequest, signLeaseGrant, signLeaseGrantAsync, verifyLeaseRequestSignature } from '../src/index.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sealLeaseRequestWithVectorValues, signLeaseGrantWithVectorValues } from '../src/lease.js';
import { expectCode, loadVector, named } from './helpers.js';

describe('lease.json', () => {
  const v = loadVector('lease.json');
  const seal = loadVector('seal-key.json');
  const sealKey = (epoch: number) => seal.seal_keys.find((k: { key_epoch: number }) => k.key_epoch === epoch);
  const dev = (name: string) => v.devices.find((d: { name: string }) => d.name === name);
  const approver = dev('alice-laptop');
  const requestSeed = b64decode(v.request_seed);
  const leaseSecret = b64decode(v.lease_secret);
  const first = v.requests[0];
  const vars = first.subject.secrets.map((s: { var: string }) => s.var);

  it.each(named(v.requests))('reproduces and opens request %s', (_n, c) => {
    const w = c.wire;
    const args = { vaultId: w.vault_id, keyEpoch: c.key_epoch, account: w.account, sealPub: sealKey(c.key_epoch).seal_pub, leasePub: v.lease_pub, ttlS: w.ttl_s, ts: w.ts, expiresAt: w.expires_at, subject: c.subject };
    expect(sealLeaseRequestWithVectorValues(requestSeed, args, { leaseId: w.lease_id, ephemeralSecret: b64decode(c.esk), nonce: b64decode(w.n) })).toEqual(w);
    expect(cjson(c.subject)).toBe(c.plaintext);
    expect(leaseRequestDigest(w)).toBe(c.digest);
    expect(verifyLeaseRequestSignature(w)).toEqual(w);
    expect(openLeaseRequest(b64decode(sealKey(c.key_epoch).seal_sk), w, { vaultId: w.vault_id, account: w.account, leaseCode: c.digest }).subject).toEqual(c.subject);
  });

  it.each(named(v.grants))('reproduces and opens grant %s', async (_n, c) => {
    const g = c.grant;
    const args = {
      request: first.wire,
      decision: g.decision,
      ...(c.payload ? { payload: c.payload } : {}),
      approverKey: approver.record.sign_pub,
      ts: g.ts,
      ...(g.expires_at !== undefined && g.expires_at !== g.ts + first.wire.ttl_s * 1000 ? { expiresAt: g.expires_at } : {}),
      requestedVars: vars,
    };
    const fixed = c.esk ? { ephemeralSecret: b64decode(c.esk), nonce: b64decode(g.n) } : {};
    expect(signLeaseGrantWithVectorValues(b64decode(approver.sign_seed), args, fixed)).toEqual(g);
    const opened = openLeaseGrant(leaseSecret, g, first.wire, { now: c.now, requestedVars: vars });
    expect(opened.decision).toBe(g.decision);
    if (opened.decision === 'allow') {
      expect(opened.payload).toEqual(c.payload);
      expect(cjson(c.payload)).toBe(c.plaintext);
    }
    if (g.decision === 'deny') {
      const seed = b64decode(approver.sign_seed);
      expect(await signLeaseGrantAsync({ sign: async (m) => ed25519.sign(m, seed) }, args)).toEqual(g);
    }
  });

  it.each(named(v.request_invalid))('refuses request %s', (_n, c) => {
    expectCode(() => openLeaseRequest(b64decode(sealKey(c.open_with_epoch).seal_sk), c.wire, { vaultId: c.vault_id, account: c.account, leaseCode: c.lease_code }), c.expect_error);
  });

  it.each(named(v.grant_invalid))('refuses grant %s', (_n, c) => {
    expectCode(() => openLeaseGrant(b64decode(c.lease_secret), c.grant, c.request, { now: c.now, requestedVars: c.requested_vars, ...(c.approvers ? { approvers: c.approvers } : {}) }), c.expect_error);
  });

  it('round-trips fresh keys and refuses a grant by the requester itself', () => {
    const keys = generateLeaseKeys();
    const sk = sealKey(3);
    const w = sealLeaseRequest(keys.requestSeed, { vaultId: first.wire.vault_id, keyEpoch: 3, account: v.account, sealPub: sk.seal_pub, leasePub: keys.leasePub, ttlS: 60, ts: 1000, expiresAt: 61_000, subject: first.subject });
    const opened = openLeaseRequest(b64decode(sk.seal_sk), w, { vaultId: w.vault_id, account: v.account, leaseCode: leaseRequestDigest(w) });
    const payload = { secrets: [{ var: 'DB_URL', value: 'v' }] };
    const g = signLeaseGrant(b64decode(approver.sign_seed), { request: w, decision: 'allow', payload, approverKey: approver.record.sign_pub, ts: 2000, requestedVars: opened.subject.secrets.map((s) => s.var) });
    const out = openLeaseGrant(keys.leaseSecret, g, w, { now: 2000, requestedVars: ['STRIPE_KEY', 'DB_URL'] });
    expect(out.decision === 'allow' && out.payload).toEqual(payload);
    expectCode(() => signLeaseGrant(keys.requestSeed, { request: w, decision: 'deny', approverKey: keys.requestPub, ts: 2000, requestedVars: [] }), 'forbidden');
    expectCode(() => signLeaseGrant(b64decode(approver.sign_seed), { request: w, decision: 'allow', payload: { secrets: [{ var: 'OTHER', value: 'v' }] }, approverKey: approver.record.sign_pub, ts: 2000, requestedVars: ['DB_URL'] }), 'forbidden');
    expectCode(() => signLeaseGrant(b64decode(approver.sign_seed), { request: w, decision: 'allow', payload, approverKey: approver.record.sign_pub, ts: 2000, expiresAt: 2000 + 60_001, requestedVars: ['DB_URL'] }), 'bad_request');
  });
});
