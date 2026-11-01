/**
 * Deterministic change logs of the membership.json chains, used by membership.ts (each
 * removal signs the head at its fence) and removal-fence.ts (log replay vectors).
 *
 * Shared vault: acct_carol is promoted from reader to editor with log_fence 4, aliceLaptop
 * is removed with log_fence 4 (key epoch 1) and acct_carol with log_fence 7 (key epoch 2). Personal vault: alicePhone is removed with log_fence 5 (key
 * epoch 1) and re-added at key epoch 2. Each log holds an applied record, a preserved
 * conflict branch and its resolution below the first fence, and records above every fence.
 */
import { LOG_START, nextLogHead, recordDigest, sealItem, signRecord, type ChangeLogCursor, type SignedRecord } from '../../src/index.js';
import { aliceLaptop, aliceNewPhone, alicePhone, BASE_TS, bobLaptop, carolPhone, id, key32, nonce, VAULT_PERSONAL, VAULT_SHARED, type VectorDevice } from './fixtures.js';

export type ChainName = 'shared' | 'personal';
export const VAULTS: Record<ChainName, string> = { shared: VAULT_SHARED, personal: VAULT_PERSONAL };

export interface LogEntry {
  log_seq: number;
  conflict_id: string | null;
  record: SignedRecord;
}

interface RecordSpec {
  label: string;
  author: VectorDevice;
  keyEpoch: number;
  item?: string;
  base?: number;
  resolves?: string[];
}

/** A signed record of `chain`'s vault, encrypted under that vault's deterministic VK[keyEpoch]. */
export function vectorRecord(chain: ChainName, spec: RecordSpec): SignedRecord {
  const vault = VAULTS[chain];
  const vk = vault === VAULT_SHARED ? key32(`vk/epoch${spec.keyEpoch}`) : key32(`vk/${vault}/epoch${spec.keyEpoch}`);
  const ctx = {
    vault_id: vault,
    item_id: id(`fence/item/${spec.item ?? spec.label}`),
    base_revision: spec.base ?? 0,
    key_epoch: spec.keyEpoch,
    author: spec.author.record.device_id,
    tombstone: false,
  };
  const env = sealItem({ ...ctx, vk, payload: { name: 'API_KEY', value: `fence-${spec.label}`, meta: {}, sensitivity: 'normal' }, nonce: nonce(`fence/record/${spec.label}`) });
  return signRecord({ ...ctx, ts: BASE_TS, resolves: spec.resolves ?? [], env }, spec.author.signSecret);
}

const SHARED_CONFLICT = id('fence/conflict/shared');
const PERSONAL_CONFLICT = id('fence/conflict/personal');

const entry = (chain: ChainName, logSeq: number, spec: RecordSpec, conflictId: string | null = null): LogEntry => ({
  log_seq: logSeq,
  conflict_id: conflictId,
  record: vectorRecord(chain, spec),
});

export const CHANGE_LOGS: Record<ChainName, LogEntry[]> = {
  shared: [
    entry('shared', 1, { label: 'log/shared/1', author: alicePhone, keyEpoch: 1, item: 'log/a' }),
    entry('shared', 2, { label: 'log/shared/2', author: aliceLaptop, keyEpoch: 1, item: 'log/b' }),
    entry('shared', 3, { label: 'log/shared/3', author: bobLaptop, keyEpoch: 1, item: 'log/a' }, SHARED_CONFLICT),
    entry('shared', 4, { label: 'log/shared/4', author: aliceLaptop, keyEpoch: 1, item: 'log/a', base: 1, resolves: [SHARED_CONFLICT] }),
    entry('shared', 5, { label: 'log/shared/5', author: bobLaptop, keyEpoch: 2, item: 'log/c' }),
    entry('shared', 6, { label: 'log/shared/6', author: bobLaptop, keyEpoch: 2, item: 'log/b', base: 1 }),
    entry('shared', 7, { label: 'log/shared/7', author: carolPhone, keyEpoch: 2, item: 'log/c', base: 1 }),
    entry('shared', 8, { label: 'log/shared/8', author: bobLaptop, keyEpoch: 3, item: 'log/d' }),
  ],
  personal: [
    entry('personal', 1, { label: 'log/personal/1', author: alicePhone, keyEpoch: 1, item: 'log/p1' }),
    entry('personal', 2, { label: 'log/personal/2', author: alicePhone, keyEpoch: 1, item: 'log/p2' }),
    entry('personal', 3, { label: 'log/personal/3', author: aliceNewPhone, keyEpoch: 1, item: 'log/p1', base: 1 }),
    entry('personal', 4, { label: 'log/personal/4', author: alicePhone, keyEpoch: 1, item: 'log/p1', base: 1 }, PERSONAL_CONFLICT),
    entry('personal', 5, { label: 'log/personal/5', author: aliceNewPhone, keyEpoch: 1, item: 'log/p1', base: 2, resolves: [PERSONAL_CONFLICT] }),
    entry('personal', 6, { label: 'log/personal/6', author: aliceNewPhone, keyEpoch: 2, item: 'log/p3' }),
    entry('personal', 7, { label: 'log/personal/7', author: alicePhone, keyEpoch: 2, item: 'log/p2', base: 1 }),
  ],
};

/** heads[n] = log_head at position n (heads[0] = ""), computed with nextLogHead. */
export function logHeads(entries: readonly LogEntry[]): string[] {
  const heads = [LOG_START.log_head];
  for (const e of entries) heads.push(nextLogHead(heads[heads.length - 1]!, e.log_seq, e.conflict_id, recordDigest(e.record)));
  return heads;
}

export const LOG_HEADS: Record<ChainName, string[]> = { shared: logHeads(CHANGE_LOGS.shared), personal: logHeads(CHANGE_LOGS.personal) };

/** The signed removal fence `{log_fence, log_head}` at position `logSeq` of `chain`'s log. */
export function fenceAt(chain: ChainName, logSeq: number): { log_fence: number; log_head: string } {
  return { log_fence: logSeq, log_head: LOG_HEADS[chain][logSeq]! };
}

export function cursorAt(chain: ChainName, logSeq: number): ChangeLogCursor {
  return { log_seq: logSeq, log_head: LOG_HEADS[chain][logSeq]! };
}
