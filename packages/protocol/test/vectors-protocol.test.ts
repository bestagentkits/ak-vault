/** Reproduce membership, records, checkpoints, audit, policy and proof vectors. */
import { describe, expect, it } from 'vitest';
import {
  applyRecord, authorizeRecordWrite, b64decode, buildProof, checkRollback, computeStateDigest, deriveAuditKey, deviceIdFromSignPub, effectiveGrant,
  openItem, sasCode, sasDigest, sasTranscript, signKeyPairFromSeed, b64encode, utf8Decode, validateWrapRecipients, verifyAuditChain,
  verifyAuditCheckpoint, verifyCheckpoint, verifyMembershipChain, verifyProof, verifyRecord, wrapsDigest,
  type ItemState, type VerifyChainOptions,
} from '../src/index.js';
import { expectCode, loadVector, named, type Vec } from './helpers.js';

function chainOptions(o: Vec): VerifyChainOptions {
  const out: VerifyChainOptions = {};
  if (o.trusted_anchor) out.trustedAnchor = o.trusted_anchor;
  if (o.witnessed_checkpoint) out.witnessedCheckpoint = o.witnessed_checkpoint;
  return out;
}

describe('membership.json', () => {
  const v = loadVector('membership.json');
  it('device fixtures are self-consistent', () => {
    for (const d of v.devices) {
      expect(b64encode(signKeyPairFromSeed(b64decode(d.sign_seed)).publicKey)).toBe(d.record.sign_pub);
      expect(deviceIdFromSignPub(d.record.sign_pub)).toBe(d.record.device_id);
    }
    expect(deviceIdFromSignPub(v.recovery.sign_pub)).toBe(v.recovery.author);
  });
  it.each(named(v.chains))('chain %s', (_n, c: Vec) => {
    expect(verifyMembershipChain(c.events, chainOptions(c.options))).toEqual(c.expected_state);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyMembershipChain(c.events, chainOptions(c.options)), c.expect_error);
  });
  it.each(named(v.wrap_checks))('wraps %s', (_n, c: Vec) => {
    const state = verifyMembershipChain(v.chains.find((x: Vec) => x.name === c.chain).events);
    const opts = { ...(c.options.key_epoch === null ? {} : { keyEpoch: c.options.key_epoch }), requireAll: c.options.require_all };
    if (c.expect_error) return expectCode(() => validateWrapRecipients(state, c.wraps, opts), c.expect_error);
    expect(wrapsDigest(validateWrapRecipients(state, c.wraps, opts))).toBe(c.wraps_digest);
  });
  it('rekey wraps_digest matches the published wrap set', () => {
    const chain = v.chains[0].events;
    expect(chain[8].body.wraps_digest).toBe(v.wrap_checks[0].wraps_digest);
  });
  it('sas', () => {
    for (const s of v.sas) {
      expect(utf8Decode(sasTranscript(s.input))).toBe(s.transcript);
      expect(sasCode(s.input)).toBe(s.code);
      expect(sasDigest(s.input)).toBe(s.digest);
    }
  });
});

describe('records.json', () => {
  const v = loadVector('records.json');
  it.each(named(v.sequences))('sequence %s', (_n, s: Vec) => {
    const state = verifyMembershipChain(v.memberships[s.membership]);
    const items = new Map<string, ItemState>();
    for (const step of s.steps) {
      const run = () => {
        const r = verifyRecord(step.record, state);
        authorizeRecordWrite(state, r);
        return { r, res: applyRecord(items.get(r.item_id), r, step.conflict_id ? { conflictId: step.conflict_id } : {}) };
      };
      if (step.expect_error) {
        expectCode(run, step.expect_error);
        continue;
      }
      const { r, res } = run();
      expect(res.outcome).toEqual(step.outcome);
      items.set(r.item_id, res.state);
      const opened = openItem({ ...r, vk: b64decode(v.vault_keys[String(r.key_epoch)]) });
      expect(opened).toEqual(step.payload);
    }
    const summary = [...items.values()].map((i) => ({ item_id: i.item_id, revision: i.revision, tombstone: i.tombstone, tombstone_revision: i.tombstone_revision, head: i.head, conflicts: i.conflicts.map((c) => c.conflict_id) }));
    expect(summary).toEqual(s.final_items);
    expect(computeStateDigest(items.values())).toBe(s.state_digest);
  });
});

describe('checkpoints.json', () => {
  const v = loadVector('checkpoints.json');
  const state = verifyMembershipChain(v.membership_events);
  it('state digests', () => {
    for (const c of v.state_digest_cases) {
      expect(computeStateDigest(c.rows.map(([item_id, revision, head]: [string, number, string]) => ({ item_id, revision, head })))).toBe(c.digest);
    }
    expect(v.checkpoint.state_digest).toBe(v.state_digest_cases[0].digest);
  });
  it('valid checkpoint', () => {
    expect(verifyCheckpoint(v.checkpoint, state)).toEqual(v.checkpoint);
  });
  it.each(named(v.invalid_checkpoints))('rejects checkpoint %s', (_n, c: Vec) => {
    expectCode(() => verifyCheckpoint(c.checkpoint, state), c.expect_error);
  });
  it.each(named(v.rollback.accept))('accepts %s', (_n, c: Vec) => {
    expect(() => checkRollback(v.rollback.witnessed, c.incoming)).not.toThrow();
  });
  it.each(named(v.rollback.reject))('rejects %s', (_n, c: Vec) => {
    expectCode(() => checkRollback(v.rollback.witnessed, c.incoming), c.expect_error);
  });
});

describe('audit.json', () => {
  const v = loadVector('audit.json');
  const opts = (c: Vec) => ({
    vaultKeys: (e: number) => (c.vault_key_epochs.includes(e) ? b64decode(v.vault_keys[String(e)]) : undefined),
    vaultId: v.vault_id,
    keyEpoch: c.key_epoch,
    ...(c.witnessed ? { witnessed: c.witnessed } : {}),
  });
  it('audit keys derive from the vault key of their epoch', () => {
    for (const e of Object.keys(v.vault_keys)) {
      expect(b64encode(deriveAuditKey(b64decode(v.vault_keys[e]), v.vault_id, Number(e)))).toBe(v.audit_keys[e]);
    }
  });
  it('checkpoint verifies', () => {
    verifyAuditCheckpoint(v.checkpoint, verifyMembershipChain(v.membership_events));
  });
  it.each(named(v.invalid_checkpoints))('rejects checkpoint %s', (_n, c: Vec) => {
    expectCode(() => verifyAuditCheckpoint(c.checkpoint, verifyMembershipChain(v.membership_events)), c.expect_error);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    expect(verifyAuditChain(c.entries, opts(c))).toEqual({ events: c.events, head: c.head });
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyAuditChain(c.entries, opts(c)), c.expect_error);
  });
});

describe('policy.json', () => {
  const v = loadVector('policy.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const grant = effectiveGrant(c.local, c.policy, c.sensitivity);
    expect(grant).toEqual(c.expected);
    expect(grant.ttl_s).toBeLessThanOrEqual(c.local.ttl_s);
    for (const p of grant.projects) expect(c.local.projects).toContain(p);
    for (const a of grant.agents) expect(c.local.agents).toContain(a);
    if (c.local.require_approval || c.sensitivity === 'high') expect(grant.require_approval).toBe(true);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => effectiveGrant(c.local, c.policy, c.sensitivity), c.expect_error);
  });
});

describe('proof.json', () => {
  const v = loadVector('proof.json');
  const opts = (x: Vec) => ({ htm: x.htm, htu: x.htu, token: x.token, body: b64decode(x.body), now: x.now, signPub: v.sign_pub, isReplay: (j: string) => x.seen_jtis.includes(j) });
  it('build', () => {
    const b = v.build;
    expect(buildProof({ htm: b.htm, htu: b.htu, ts: b.ts, jti: b.jti, token: b.token, body: b64decode(b.body), secretKey: b64decode(v.sign_seed) })).toBe(b.header);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    expect(verifyProof(c.header, opts(c.verify))).toEqual(c.proof);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyProof(c.header, opts(c.verify)), c.expect_error);
  });
});
