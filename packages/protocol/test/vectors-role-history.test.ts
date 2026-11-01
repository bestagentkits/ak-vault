/** Reproduce role-history.json, plus fail-closed checks on roles and kinds outside the closed sets. */
import { describe, expect, it } from 'vitest';
import { LOG_START, nextLogHead, recordDigest, signedFences, verifyChangeLog, verifyLoggedRecord, verifyMembershipChain, type MembershipState } from '../src/index.js';
import { expectCode, loadVector, named, type Vec } from './helpers.js';

describe('role-history.json', () => {
  const v = loadVector('role-history.json');
  const states = Object.fromEntries(Object.entries(v.chains as Record<string, unknown[]>).map(([name, chain]) => [name, verifyMembershipChain(chain)])) as Record<string, MembershipState>;
  const stateOf = (c: Vec) => states[c.chain as string]!;
  const logOptions = (c: Vec) => ({
    from: c.from,
    complete: c.complete,
    keptHeads: new Map(Object.entries(c.kept_heads as Record<string, string>).map(([k, h]) => [Number(k), h])),
  });

  it('covers a fenced chain, a chain with legacy role changes and a re-added device', () => {
    expect(Object.keys(states).sort()).toEqual(['legacy', 'readded', 'roles']);
    expect(states['legacy']!.role_changes.some((c) => c.log_fence === null && c.log_head === null)).toBe(true);
  });
  it.each(Object.keys(states))('%s: removals and role changes carry the signed fences, roles and kinds', (name) => {
    expect(states[name]!.removals).toEqual(v.removals[name]);
    expect(states[name]!.role_changes).toEqual(v.role_changes[name]);
  });
  it.each(named(v.cases))('%s', (_n, c: Vec) => {
    expect(verifyLoggedRecord(c.record, stateOf(c), c.log_seq)).toEqual(c.record);
  });
  it.each(named(v.invalid))('rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyLoggedRecord(c.record, stateOf(c), c.log_seq), c.expect_error);
  });
  it.each(Object.keys(v.change_logs as object))('change log %s: heads chain and every fence signs the head at its position', (name) => {
    const { entries, heads } = v.change_logs[name] as { entries: Vec[]; heads: string[] };
    const state = states[name]!;
    expect(heads[0]).toBe(LOG_START.log_head);
    entries.forEach((e, i) => expect(nextLogHead(heads[i]!, e.log_seq, e.conflict_id, recordDigest(e.record))).toBe(heads[i + 1]));
    for (const f of signedFences(state)) expect(f.log_head).toBe(heads[f.log_fence]);
    expect(verifyChangeLog(entries, state, { complete: true }).head).toEqual({ log_seq: entries.length, log_head: heads[entries.length] });
  });
  it.each(named(v.log_cases))('log %s', (_n, c: Vec) => {
    expect(verifyChangeLog(c.entries, stateOf(c), logOptions(c)).head).toEqual(c.head);
  });
  it.each(named(v.log_invalid))('log rejects %s', (_n, c: Vec) => {
    expectCode(() => verifyChangeLog(c.entries, stateOf(c), logOptions(c)), c.expect_error);
  });

  describe('fails closed on a role or kind outside the closed sets', () => {
    // An editor record the vectors accept, checked against a state whose author fields were altered.
    const accepted = (v.cases as Vec[]).find((c) => c.name === 'editor_at_newer_key_epoch')!;
    const state = stateOf(accepted);
    const author = accepted.record.author as string;
    const withDevice = (patch: Record<string, string>): MembershipState => ({
      ...state,
      devices: state.devices.map((d) => (d.device_id === author ? ({ ...d, ...patch } as typeof d) : d)),
    });
    it('accepts the unaltered state', () => {
      expect(verifyLoggedRecord(accepted.record, state, accepted.log_seq)).toEqual(accepted.record);
    });
    it.each([
      ['unknown role', { role: 'admin' }],
      ['unknown kind', { kind: 'robot' }],
      ['empty role', { role: '' }],
    ])('%s', (_n, patch) => {
      expectCode(() => verifyLoggedRecord(accepted.record, withDevice(patch), accepted.log_seq), 'forbidden');
    });
    it('unknown role in a role change', () => {
      const altered: MembershipState = {
        ...state,
        role_changes: state.role_changes.map((c) => (c.device_id === author ? ({ ...c, role: 'admin', prev_role: 'admin' } as unknown as typeof c) : c)),
      };
      expectCode(() => verifyLoggedRecord(accepted.record, altered, 2), 'forbidden');
    });
    it('unknown role among the candidates of a legacy span', () => {
      const c = (v.cases as Vec[]).find((x) => x.name === 'legacy_reader_in_legacy_promotion_span')!;
      const st = stateOf(c);
      expect(verifyLoggedRecord(c.record, st, c.log_seq)).toEqual(c.record);
      const altered: MembershipState = {
        ...st,
        role_changes: st.role_changes.map((r) => (r.device_id === c.record.author && r.log_fence === null ? ({ ...r, prev_role: 'admin' } as unknown as typeof r) : r)),
      };
      expectCode(() => verifyLoggedRecord(c.record, altered, c.log_seq), 'forbidden');
    });
    it('unknown kind on the removal that ends the term', () => {
      // carolPhone's key-epoch-1 term ends at her removal, which supplies the term's kind.
      const c = (v.cases as Vec[]).find((x) => x.name === 'promoted_reader_after_promotion_fence')!;
      const st = stateOf(c);
      const altered: MembershipState = { ...st, removals: st.removals.map((r) => (r.device_id === c.record.author ? ({ ...r, kind: 'robot' } as unknown as typeof r) : r)) };
      expectCode(() => verifyLoggedRecord(c.record, altered, c.log_seq), 'forbidden');
    });
  });
});
