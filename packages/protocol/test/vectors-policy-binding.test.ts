/**
 * Reproduce policy-binding.json and check the binding properties the vectors
 * cannot enumerate: adding a governing policy never widens the grant, and a
 * policy item sealed for one vault never binds in another.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  effectiveGrant, isAkvError, openItem, randomBytes, randomId, resolveItemPolicy, sealItem,
  type ItemPayload, type LocalGrant,
} from '../src/index.js';
import { expectCode, loadVector, named, type Vec } from './helpers.js';

describe('policy-binding.json', () => {
  const v = loadVector('policy-binding.json');
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    const resolved = resolveItemPolicy(c.target, c.items);
    expect(resolved).toEqual({ policy: c.expected.policy, sensitivity: c.expected.sensitivity });
    expect(effectiveGrant(c.local, resolved.policy, resolved.sensitivity)).toEqual(c.expected.grant);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => resolveItemPolicy(c.target, c.items), c.expect_error);
  });
});

const TARGET = randomId();
const secretEntry = { tombstone: false, payload: { name: 'SYNTHETIC', value: 'v', meta: {}, sensitivity: 'normal' } };
const policyEntry = (rules: unknown, sensitivity = 'normal') => ({
  tombstone: false,
  payload: { name: 'p', value: '', meta: { kind: 'policy', item_ids: [TARGET], policy: rules }, sensitivity },
});

function isSubsequence(sub: readonly string[], list: readonly string[]): boolean {
  let i = 0;
  for (const x of list) if (i < sub.length && sub[i] === x) i++;
  return i === sub.length;
}

function expectNoWider(narrow: LocalGrant, wide: LocalGrant): void {
  expect(narrow.ttl_s).toBeLessThanOrEqual(wide.ttl_s);
  if (wide.require_approval) expect(narrow.require_approval).toBe(true);
  expect(isSubsequence(narrow.projects, wide.projects)).toBe(true);
  expect(isSubsequence(narrow.purposes, wide.purposes)).toBe(true);
  expect(isSubsequence(narrow.agents, wide.agents)).toBe(true);
}

describe('policy binding properties', () => {
  it('every added governing policy only narrows the grant', () => {
    const name = fc.constantFrom('proj_a', 'proj_b', 'deploy', 'claude', 'codex', '*');
    const list = fc.array(name, { maxLength: 4 });
    const grantArb = fc.record({ ttl_s: fc.nat(), require_approval: fc.boolean(), projects: list, purposes: list, agents: list });
    const rulesArb = fc.record(
      { max_ttl_s: fc.nat(), require_approval: fc.boolean(), allowed_projects: list, allowed_purposes: list, deny_agents: list },
      { requiredKeys: [] },
    );
    const policiesArb = fc.array(fc.tuple(rulesArb, fc.constantFrom('normal', 'high')), { minLength: 1, maxLength: 4 });
    fc.assert(fc.property(grantArb, policiesArb, (local, policies) => {
      const items: unknown[] = [{ item_id: TARGET, head: secretEntry, branches: [] }];
      let previous = effectiveGrant(local, null, 'normal');
      for (const [rules, sensitivity] of policies) {
        items.push({ item_id: randomId(), head: policyEntry(rules, sensitivity), branches: [] });
        const resolved = resolveItemPolicy(TARGET, items);
        const grant = effectiveGrant(local, resolved.policy, resolved.sensitivity);
        expectNoWider(grant, previous);
        expectNoWider(grant, effectiveGrant(local, rules, sensitivity as 'normal' | 'high'));
        previous = grant;
      }
    }), { numRuns: 500, seed: 7 });
  });

  it('accepts payloads exactly as openItem returns them', () => {
    const vk = randomBytes(32);
    const vaultId = randomId();
    const author = randomId();
    const policyId = randomId();
    const ctx = { vault_id: vaultId, item_id: policyId, base_revision: 0, key_epoch: 1, author, tombstone: false };
    const payload = policyEntry({ max_ttl_s: 60 }, 'high').payload as ItemPayload;
    const env = sealItem({ ...ctx, vk, payload });
    const opened = openItem({ ...ctx, vk, env });
    const resolved = resolveItemPolicy(TARGET, [
      { item_id: TARGET, head: secretEntry, branches: [] },
      { item_id: policyId, head: { tombstone: false, payload: opened }, branches: [] },
    ]);
    expect(resolved).toEqual({ policy: { max_ttl_s: 60 }, sensitivity: 'high' });
  });

  it('a policy item moved to another vault does not open, and the device then refuses every item', () => {
    const vk = randomBytes(32);
    const author = randomId();
    const policyId = randomId();
    const ctx = { vault_id: randomId(), item_id: policyId, base_revision: 0, key_epoch: 1, author, tombstone: false };
    const env = sealItem({ ...ctx, vk, payload: policyEntry({ max_ttl_s: 60 }).payload as ItemPayload });
    let payload: unknown = null;
    try {
      payload = openItem({ ...ctx, vault_id: randomId(), vk, env });
    } catch (err) {
      expect(isAkvError(err) && err.code === 'decrypt_failed').toBe(true);
    }
    expect(payload).toBeNull();
    expectCode(() => resolveItemPolicy(TARGET, [
      { item_id: TARGET, head: secretEntry, branches: [] },
      { item_id: policyId, head: { tombstone: false, payload }, branches: [] },
    ]), 'decrypt_failed');
  });

  it('does not mutate its input', () => {
    const items = [{ item_id: TARGET, head: secretEntry, branches: [] }, { item_id: randomId(), head: policyEntry({ deny_agents: ['a', 'a'] }), branches: [] }];
    const snapshot = JSON.stringify(items);
    expect(resolveItemPolicy(TARGET, items).policy).toEqual({ deny_agents: ['a'] });
    expect(JSON.stringify(items)).toBe(snapshot);
  });
});
