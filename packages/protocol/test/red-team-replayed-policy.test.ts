/**
 * Red-team: a server re-serves an older revision of a portable policy item
 * (spec §5, §6, §8). A policy narrows a grant, so its older revision is the
 * wider one and the one a hostile server wants a device to apply.
 *
 * - Re-appended at a new log position, the older record is a replay
 *   (`applyRecord`: conflict), for every device.
 * - Restored below the device's witnessed position and regrown past it, the log
 *   passes `checkRollback` on checkpoints alone; `verifyChangeLog` refuses it
 *   against the head the device kept at the witnessed position.
 * - Documented limit: a device that resumes from its own cursor never re-reads
 *   the restored positions, so the log alone does not show the restore; it keeps
 *   its newer policy. Mirrors go/akv1/red_team_replayed_policy_test.go.
 *
 * Holding the policy as JSON in the item `value` is this test's layout only.
 */
import { describe, expect, it } from 'vitest';
import {
  applyRecord, b64encode, buildGenesisEvent, checkRollback, computeStateDigest, createDeviceKeys, effectiveGrant,
  LOG_START, openItem, randomBytes, randomId, sealItem, signRecord, verifyChangeLog, verifyMembershipChain,
  type ChangeLogCursor, type CheckpointView, type ItemPayload, type ItemState, type LocalGrant, type SignedRecord,
} from '../src/index.js';
import { expectCode } from './helpers.js';

const vaultId = randomId();
const vk = randomBytes(32);
const owner = createDeviceKeys({ account: 'acct-synthetic', role: 'owner', kind: 'human' });
const recovery = createDeviceKeys({ account: 'acct-synthetic', role: 'owner', kind: 'human' });
const genesis = buildGenesisEvent(
  { vault_id: vaultId, ts: 1, author: owner.record.device_id, body: { vault_kind: 'personal', owner_account: 'acct-synthetic', recovery_sign_pub: recovery.record.sign_pub, devices: [{ ...owner.record }], wraps_digest: b64encode(randomBytes(32)) } },
  owner.signSecret,
);
const state = verifyMembershipChain([genesis]);
const local: LocalGrant = { ttl_s: 3600, require_approval: false, projects: ['proj_a', 'proj_b'], purposes: ['deploy'], agents: ['claude'] };

const POLICY = randomId();
const OTHER = randomId();
const LATER = randomId();
const WIDE = { allowed_projects: ['proj_a', 'proj_b'] };
const NARROW = { allowed_projects: ['proj_a'], require_approval: true };

function record(itemId: string, base: number, value: string, kind = 'secret'): SignedRecord {
  const ctx = { vault_id: vaultId, item_id: itemId, base_revision: base, key_epoch: 1, author: owner.record.device_id, tombstone: false };
  const env = sealItem({ ...ctx, vk, payload: { name: 'ITEM', value, meta: { kind }, sensitivity: 'normal' } });
  return signRecord({ ...ctx, ts: 1, resolves: [], env }, owner.signSecret);
}

const policyV1 = record(POLICY, 0, JSON.stringify(WIDE), 'policy');
const policyV2 = record(POLICY, 1, JSON.stringify(NARROW), 'policy');
const entry = (logSeq: number, r: SignedRecord, conflictId: string | null = null) => ({ log_seq: logSeq, conflict_id: conflictId, record: r });
const honest = [entry(1, policyV1), entry(2, record(OTHER, 0, 'x1')), entry(3, policyV2)];
// Restored to position 2, then current members keep writing on the restored state.
const regrown = [...honest.slice(0, 2), entry(3, record(OTHER, 1, 'x2')), entry(4, record(LATER, 0, 'y1'))];

/** A device's full pull: verify the log, replay every record, keep the head at each position. */
function pull(entries: typeof honest, items = new Map<string, ItemState>(), from: ChangeLogCursor = LOG_START, keptHeads = new Map<number, string>()) {
  const { head, records } = verifyChangeLog(entries, state, { from, complete: true, keptHeads });
  records.forEach((r, i) => {
    const conflictId = entries[i]!.conflict_id;
    const res = applyRecord(items.get(r.item_id), r, conflictId === null ? {} : { conflictId });
    if (entries[i]!.conflict_id === null && res.outcome.status !== 'applied') throw new Error('test log is not honest');
    items.set(r.item_id, res.state);
  });
  const view: CheckpointView = { vault_id: vaultId, membership_seq: state.seq, membership_head: state.head, log_seq: head.log_seq, state_digest: computeStateDigest(items.values()), key_epoch: state.key_epoch };
  return { head, items, view };
}

/** Effective grant under the policy revision the device holds as head. */
function grantFrom(items: Map<string, ItemState>, log: typeof honest): LocalGrant {
  const item = items.get(POLICY)!;
  const r = log.map((e) => e.record).find((rec) => rec.item_id === POLICY && rec.base_revision === item.revision - 1)!;
  const payload = openItem({ ...r, vk, env: r.env }) as ItemPayload;
  return effectiveGrant(local, JSON.parse(payload.value), 'normal');
}

describe('red team: an older policy revision re-served by the server', () => {
  const witnessed = pull(honest);

  it('the device holds the newer, narrower policy', () => {
    expect(witnessed.items.get(POLICY)!.revision).toBe(2);
    expect(grantFrom(witnessed.items, honest)).toMatchObject({ projects: ['proj_a'], require_approval: true });
  });

  it('re-appended at a new position, applied or as a branch, the older record is a replay', () => {
    for (const conflictId of [null, randomId()]) {
      const log = [...honest, entry(4, policyV1, conflictId)];
      // The record is validly signed, so the log itself verifies; the replay check refuses it,
      // for a device reading the log from position 1 and for one resuming from its cursor.
      expect(verifyChangeLog(log, state, { complete: true }).head.log_seq).toBe(4);
      expectCode(() => pull(log), 'conflict');
      expectCode(() => pull([entry(4, policyV1, conflictId)], new Map(witnessed.items), witnessed.head), 'conflict');
    }
  });

  it('restored below the newer revision and regrown past the witnessed position: checkRollback alone passes it', () => {
    const served = pull(regrown);
    expect(grantFrom(served.items, regrown)).toMatchObject({ projects: ['proj_a', 'proj_b'], require_approval: false });
    expect(() => checkRollback(witnessed.view, served.view)).not.toThrow();
    expect(pull(regrown.slice(0, 3)).view.state_digest).not.toBe(witnessed.view.state_digest);
  });

  it('the head kept at the witnessed position refuses the regrown log', () => {
    const kept = new Map([[witnessed.head.log_seq, witnessed.head.log_head]]);
    expectCode(() => pull(regrown, new Map(), LOG_START, kept), 'rollback');
    expectCode(() => verifyChangeLog(regrown.slice(1), state, { from: pull(regrown.slice(0, 1)).head, complete: false, keptHeads: kept }), 'rollback');
  });

  it('a log restored behind the witnessed position is refused by the kept head and by checkRollback', () => {
    const kept = new Map([[witnessed.head.log_seq, witnessed.head.log_head]]);
    expectCode(() => pull(honest.slice(0, 2), new Map(), LOG_START, kept), 'rollback');
    expectCode(() => checkRollback(witnessed.view, pull(honest.slice(0, 2)).view), 'rollback');
  });

  it('documented limit: a device resuming from its own cursor does not see the restore, and keeps its newer policy', () => {
    const resumed = pull(regrown.slice(3), new Map(witnessed.items), witnessed.head);
    expect(resumed.head.log_seq).toBe(4);
    expect(resumed.items.get(POLICY)!.revision).toBe(2);
    expect(grantFrom(resumed.items, honest)).toMatchObject({ projects: ['proj_a'], require_approval: true });
  });
});
