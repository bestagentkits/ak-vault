/** records.json: CAS sequences, conflicts, tombstones, replay and authorization. */
import {
  applyRecord,
  authorizeRecordWrite,
  computeStateDigest,
  sealItem,
  signRecord,
  verifyMembershipChain,
  verifyRecord,
  type ItemPayload,
  type ItemState,
  type MembershipEvent,
  type SignedRecord,
  type TombstonePayload,
} from '../../src/index.js';
import { sharedChain } from './membership.js';
import { aliceLaptop, alicePhone, b64, BASE_TS, bobCi, bobLaptop, carolPhone, flipByte, id, key32, negative, nonce, stranger, VAULT_PERSONAL, VAULT_SHARED, type VectorDevice } from './fixtures.js';

export const MEMBERSHIPS: Record<string, MembershipEvent[]> = {
  base: sharedChain.slice(0, 4),
  rekey_pending: sharedChain.slice(0, 6),
  epoch3: sharedChain,
};

let counter = 0;

interface RecordSpec {
  author: VectorDevice;
  item: string;
  base: number;
  tombstone?: boolean;
  resolves?: string[];
  epoch?: number;
  vault?: string;
  value?: string;
}

/** Build a signed record with a real encrypted payload (deterministic nonce). */
export function makeRecord(spec: RecordSpec): { record: SignedRecord; payload: ItemPayload | TombstonePayload } {
  counter++;
  const tombstone = spec.tombstone ?? false;
  const epoch = spec.epoch ?? 1;
  const vault = spec.vault ?? VAULT_SHARED;
  const payload: ItemPayload | TombstonePayload = tombstone ? { deleted: true } : { name: 'API_KEY', value: spec.value ?? `value-${counter}`, meta: {}, sensitivity: 'normal' };
  const ctx = { vault_id: vault, item_id: spec.item, base_revision: spec.base, key_epoch: epoch, author: spec.author.record.device_id, tombstone };
  const env = sealItem({ ...ctx, vk: key32(`vk/epoch${epoch}`), payload, nonce: nonce(`record/${counter}`) });
  const record = signRecord({ ...ctx, ts: BASE_TS + counter * 1000, resolves: spec.resolves ?? [], env }, spec.author.signSecret);
  return { record, payload };
}

type Expect = 'applied' | 'conflict' | { error: string };
interface Step {
  name: string;
  record: unknown;
  payload?: unknown;
  conflictId?: string;
  expect: Expect;
}

function summary(s: ItemState) {
  return { item_id: s.item_id, revision: s.revision, tombstone: s.tombstone, tombstone_revision: s.tombstone_revision, head: s.head, conflicts: s.conflicts.map((c) => c.conflict_id) };
}

function sequence(name: string, membership: string, steps: Step[]) {
  const state = verifyMembershipChain(MEMBERSHIPS[membership]!);
  const items = new Map<string, ItemState>();
  const out = steps.map((step) => {
    const run = () => {
      const r = verifyRecord(step.record, state);
      authorizeRecordWrite(state, r);
      return { r, res: applyRecord(items.get(r.item_id), r, step.conflictId ? { conflictId: step.conflictId } : {}) };
    };
    const base = { record: step.record, conflict_id: step.conflictId ?? null };
    if (typeof step.expect === 'object') return negative(step.name, step.expect.error, base, run);
    const { r, res } = run();
    if (res.outcome.status !== step.expect) throw new Error(`${name}/${step.name}: expected ${step.expect}, got ${res.outcome.status}`);
    items.set(r.item_id, res.state);
    return { name: step.name, ...base, payload: step.payload ?? null, outcome: res.outcome };
  });
  return { name, membership, steps: out, final_items: [...items.values()].map(summary), state_digest: computeStateDigest(items.values()) };
}

const err = (code: string): Expect => ({ error: code });

export function recordVectors(): Record<string, unknown> {
  counter = 0;
  const A = id('item/A');
  const B = id('item/B');
  const D = id('item/D');
  const c1 = id('conflict/1');
  const mk = (s: RecordSpec, name: string, expect: Expect, conflictId?: string): Step => {
    const { record, payload } = makeRecord(s);
    return conflictId ? { name, record, payload, expect, conflictId } : { name, record, payload, expect };
  };

  const lifecycle = sequence('cas_tombstone_lifecycle', 'base', [
    mk({ author: alicePhone, item: A, base: 0 }, 'create', 'applied'),
    mk({ author: bobLaptop, item: A, base: 1 }, 'update', 'applied'),
    mk({ author: alicePhone, item: A, base: 2, tombstone: true }, 'delete', 'applied'),
    mk({ author: bobLaptop, item: A, base: 1, value: 'stale-offline-edit' }, 'stale_write_cannot_resurrect', err('tombstoned')),
    mk({ author: alicePhone, item: A, base: 3, tombstone: true }, 'delete_deleted_item', err('bad_request')),
    mk({ author: aliceLaptop, item: A, base: 3 }, 'recreate_at_tombstone_revision', 'applied'),
  ]);

  const b1 = mk({ author: alicePhone, item: B, base: 0 }, 'create', 'applied');
  const b2 = mk({ author: bobLaptop, item: B, base: 1 }, 'update', 'applied');
  const b3 = mk({ author: alicePhone, item: B, base: 1, value: 'concurrent-edit' }, 'concurrent_stale_base_preserved', 'conflict', c1);
  const conflict = sequence('conflict_branch_and_resolve', 'base', [
    b1,
    b2,
    b3,
    { ...b2, name: 'replayed_applied_record', expect: err('conflict') },
    { ...b1, name: 'replayed_older_revision', expect: err('conflict') },
    { ...b3, name: 'replayed_conflict_record', expect: err('conflict'), conflictId: id('conflict/2') },
    mk({ author: alicePhone, item: B, base: 2, resolves: [id('conflict/unknown')] }, 'resolve_unknown_branch', err('bad_request')),
    mk({ author: alicePhone, item: B, base: 2, resolves: [c1] }, 'resolve_branch', 'applied'),
    mk({ author: bobLaptop, item: id('item/never'), base: 0, tombstone: true }, 'delete_missing_item', err('bad_request')),
  ]);

  const good = makeRecord({ author: alicePhone, item: D, base: 0 });
  const kidMismatch = signRecord({ ...good.record, env: { ...good.record.env, kid: 'e2' } }, alicePhone.signSecret);
  const auth = sequence('authorization_and_validation', 'base', [
    mk({ author: carolPhone, item: D, base: 0 }, 'reader_cannot_write', err('forbidden')),
    mk({ author: bobCi, item: D, base: 0 }, 'machine_cannot_write', err('forbidden')),
    mk({ author: stranger, item: D, base: 0 }, 'non_member_author', err('forbidden')),
    { name: 'bad_signature', record: { ...good.record, sig: flipByte(good.record.sig, 7) }, expect: err('invalid_signature') },
    { name: 'tampered_base_revision', record: { ...good.record, base_revision: 5 }, expect: err('invalid_signature') },
    mk({ author: alicePhone, item: D, base: 0, epoch: 2 }, 'key_epoch_ahead_of_vault', err('bad_request')),
    { name: 'env_kid_not_epoch_tag', record: kidMismatch, expect: err('bad_request') },
    { name: 'unsupported_version', record: { ...good.record, v: 2 }, expect: err('unsupported_version') },
    mk({ author: alicePhone, item: D, base: 0, vault: VAULT_PERSONAL }, 'other_vault', err('bad_request')),
    { name: 'create', record: good.record, payload: good.payload, expect: 'applied' },
  ]);

  const rekey = sequence('writes_refused_while_rekey_required', 'rekey_pending', [mk({ author: alicePhone, item: A, base: 0 }, 'write_during_rekey_required', err('rekey_required'))]);
  const epoch3 = sequence('writes_after_rekey', 'epoch3', [
    mk({ author: bobLaptop, item: A, base: 0, epoch: 1 }, 'stale_key_epoch', err('bad_request')),
    mk({ author: bobLaptop, item: A, base: 0, epoch: 3 }, 'current_key_epoch', 'applied'),
    mk({ author: carolPhone, item: A, base: 1, epoch: 3 }, 'removed_member_author', err('forbidden')),
  ]);

  return {
    version: 1,
    description:
      'Records (spec §5). memberships: named membership chains. vault_keys: VK per key epoch (decrypt applied payloads with item AAD). Each sequence starts with empty item state; every step runs verifyRecord(record, membership state) -> authorizeRecordWrite -> applyRecord(item state, record, conflict_id). Positive steps give outcome {status:"applied",revision} or {status:"conflict",conflict_id} (CAS mismatch: record preserved as a branch, HTTP 409). Negative steps MUST throw expect_error and leave state unchanged; a replayed (already seen) record is conflict and NOT preserved. final_items summarise item state; state_digest = b64 sha256(cjson(sorted [[item_id,revision,head]])) with head = b64 sha256(record signing input).',
    memberships: MEMBERSHIPS,
    vault_keys: { '1': b64(key32('vk/epoch1')), '2': b64(key32('vk/epoch2')), '3': b64(key32('vk/epoch3')) },
    sequences: [lifecycle, conflict, auth, rekey, epoch3],
  };
}
