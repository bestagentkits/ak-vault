/**
 * Persistent device state, one entry per account: the non-extractable key
 * objects, the join nonce, and once an offer is accepted, the enrollment (vault,
 * trust anchor, offer checkpoint) and the highest position this device verified
 * itself. Nothing here is secret in bytes: no token, vault key, name or value is
 * ever stored. The store lives in IndexedDB; tests use the in-memory one.
 */
import { parseCheckpoint, type Checkpoint } from '@ak-vault/protocol';
import { deviceIdOf, isDeviceKeyMaterial, type DeviceKeyMaterial } from './webcrypto-device-keys.js';

/** A position this device verified itself, from position 1 (never a server value). */
export interface WitnessedState {
  membership_seq: number;
  membership_head: string;
  log_seq: number;
  log_head: string;
  key_epoch: number;
}

/**
 * True when `a` is behind `b` on any counter. Verified positions only move
 * forward, so a stored position is replaced only by one at least as far along.
 */
export function isWitnessedOlder(a: WitnessedState, b: WitnessedState): boolean {
  return a.membership_seq < b.membership_seq || a.log_seq < b.log_seq || a.key_epoch < b.key_epoch;
}

/**
 * True when two positions reached the same sequence with different heads: one
 * history cannot produce both, so the server showed two verified histories.
 */
export function isWitnessedFork(a: WitnessedState, b: WitnessedState): boolean {
  return (a.membership_seq === b.membership_seq && a.membership_head !== b.membership_head) || (a.log_seq === b.log_seq && a.log_head !== b.log_head);
}

/**
 * Component-wise furthest position: membership, log and key epoch each keep the
 * higher counter with its head. Two verified pulls can be ahead on different
 * components (membership is read before the log), and each chain was verified on
 * its own, so neither component may be forgotten. Null when a component reached
 * the same counter with a different head (a fork).
 */
export function mergeWitnessed(a: WitnessedState, b: WitnessedState): WitnessedState | null {
  if (isWitnessedFork(a, b)) return null;
  const m = a.membership_seq >= b.membership_seq ? a : b;
  const l = a.log_seq >= b.log_seq ? a : b;
  return { membership_seq: m.membership_seq, membership_head: m.membership_head, log_seq: l.log_seq, log_head: l.log_head, key_epoch: Math.max(a.key_epoch, b.key_epoch) };
}

function sameWitnessed(a: WitnessedState, b: WitnessedState): boolean {
  return a.membership_seq === b.membership_seq && a.membership_head === b.membership_head && a.log_seq === b.log_seq && a.log_head === b.log_head && a.key_epoch === b.key_epoch;
}

/** Result of {@link DeviceStore.advance}; `stored` is what the store held when it decided. */
export interface AdvanceResult {
  /** `saved`: written (the merged position). `older`: nothing newer than the stored position, nothing written. `fork`: a counter reached again with another head, nothing written. `stale`: the entry is gone or re-enrolled, nothing written. */
  outcome: 'saved' | 'older' | 'fork' | 'stale';
  stored: StoredDevice | null;
  /** The position the store holds after the call (null for `stale`). */
  position: WitnessedState | null;
}

/**
 * Decide, from the stored entry alone, how `next` changes its position. Pure so
 * the memory and IndexedDB stores share one rule. Only the enrollment of the same
 * device and enrollment may advance; the rest of the entry is kept.
 */
export function decideAdvance(stored: StoredDevice | null, next: StoredDevice): { outcome: AdvanceResult['outcome']; write: StoredDevice | null; position: WitnessedState | null } {
  const enrollment = next.enrollment;
  const current = stored?.enrollment;
  if (!stored || !enrollment || !current || deviceIdOf(stored.keys) !== deviceIdOf(next.keys) || current.vaultId !== enrollment.vaultId || current.nonceI !== enrollment.nonceI || stored.nonceJ !== next.nonceJ) {
    return { outcome: 'stale', write: null, position: null };
  }
  const have = current.witnessed;
  const want = enrollment.witnessed;
  if (!want) return { outcome: 'older', write: null, position: have };
  const merged = have ? mergeWitnessed(have, want) : want;
  if (!merged) return { outcome: 'fork', write: null, position: have };
  if (have && sameWitnessed(merged, have) && !sameWitnessed(want, have)) return { outcome: 'older', write: null, position: have };
  return { outcome: 'saved', write: { ...stored, enrollment: { ...enrollment, witnessed: merged } }, position: merged };
}

export interface Enrollment {
  origin: string;
  vaultId: string;
  /** Device ID of the approving owner device. */
  initiator: string;
  nonceI: string;
  /** b64 genesis author `sign_pub`, from the offer. */
  trustAnchor: string;
  offerCheckpoint: Checkpoint;
  /** The six-digit SAS shown when the offer was accepted. */
  sas: string;
  /** True once the chain carries this device's `device_add` with the matching SAS digest. */
  confirmed: boolean;
  witnessed: WitnessedState | null;
}

export interface StoredDevice {
  v: 1;
  account: string;
  keys: DeviceKeyMaterial;
  label: string;
  nonceJ: string;
  enrollment: Enrollment | null;
}

export interface DeviceStore {
  get(account: string): Promise<StoredDevice | null>;
  put(device: StoredDevice): Promise<void>;
  /**
   * Compare-and-save of the verified position, atomic against every other tab:
   * the read, the {@link decideAdvance} rule and the write happen in one step.
   */
  advance(next: StoredDevice): Promise<AdvanceResult>;
  delete(account: string): Promise<void>;
}

function isString(v: unknown): v is string {
  return typeof v === 'string';
}

function isCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

function parseWitnessed(value: unknown): WitnessedState | null | undefined {
  if (value === null) return null;
  if (typeof value !== 'object') return undefined;
  const w = value as Record<string, unknown>;
  if (!isCount(w['membership_seq']) || !isString(w['membership_head']) || !isCount(w['log_seq']) || !isString(w['log_head']) || !isCount(w['key_epoch'])) {
    return undefined;
  }
  return { membership_seq: w['membership_seq'], membership_head: w['membership_head'], log_seq: w['log_seq'], log_head: w['log_head'], key_epoch: w['key_epoch'] };
}

function parseEnrollment(value: unknown): Enrollment | null | undefined {
  if (value === null) return null;
  if (typeof value !== 'object') return undefined;
  const e = value as Record<string, unknown>;
  const witnessed = parseWitnessed(e['witnessed']);
  if (witnessed === undefined) return undefined;
  if (!isString(e['origin']) || !isString(e['vaultId']) || !isString(e['initiator']) || !isString(e['nonceI']) || !isString(e['trustAnchor'])) return undefined;
  if (!isString(e['sas']) || typeof e['confirmed'] !== 'boolean') return undefined;
  let offerCheckpoint: Checkpoint;
  try {
    offerCheckpoint = parseCheckpoint(e['offerCheckpoint']);
  } catch {
    return undefined;
  }
  return {
    origin: e['origin'], vaultId: e['vaultId'], initiator: e['initiator'], nonceI: e['nonceI'], trustAnchor: e['trustAnchor'],
    offerCheckpoint, sas: e['sas'], confirmed: e['confirmed'], witnessed,
  };
}

/** Validate a stored entry; anything malformed reads as absent (the device starts over). */
export function parseStoredDevice(value: unknown, account: string): StoredDevice | null {
  if (typeof value !== 'object' || value === null) return null;
  const d = value as Record<string, unknown>;
  if (d['v'] !== 1 || d['account'] !== account || !isDeviceKeyMaterial(d['keys']) || !isString(d['label']) || !isString(d['nonceJ'])) return null;
  const enrollment = parseEnrollment(d['enrollment']);
  if (enrollment === undefined) return null;
  return { v: 1, account, keys: d['keys'], label: d['label'], nonceJ: d['nonceJ'], enrollment };
}

export function memoryDeviceStore(): DeviceStore & { entries: Map<string, StoredDevice> } {
  const entries = new Map<string, StoredDevice>();
  return {
    entries,
    async get(account) {
      return parseStoredDevice(entries.get(account) ?? null, account);
    },
    async put(device) {
      entries.set(device.account, structuredClone(device));
    },
    async advance(next) {
      const stored = parseStoredDevice(entries.get(next.account) ?? null, next.account);
      const { outcome, write, position } = decideAdvance(stored, next);
      if (write) entries.set(next.account, structuredClone(write));
      return { outcome, stored, position };
    },
    async delete(account) {
      entries.delete(account);
    },
  };
}

const DB_NAME = 'akv-dashboard';
const STORE = 'devices';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb request failed'));
  });
}

function openDb(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: 'account' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb open failed'));
    req.onblocked = () => reject(new Error('indexeddb open blocked'));
  });
}

async function withStore<T>(factory: IDBFactory, mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb(factory);
  try {
    const tx = db.transaction(STORE, mode);
    const done = new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error ?? new Error('indexeddb transaction aborted'));
      tx.onerror = () => reject(tx.error ?? new Error('indexeddb transaction failed'));
    });
    const result = await request(run(tx.objectStore(STORE)));
    await done;
    return result;
  } finally {
    db.close();
  }
}

/** Read, decide and write in one `readwrite` transaction, so no other tab interleaves. */
async function advanceInTransaction(factory: IDBFactory, next: StoredDevice): Promise<AdvanceResult> {
  const db = await openDb(factory);
  try {
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    return await new Promise<AdvanceResult>((resolve, reject) => {
      let result: AdvanceResult | null = null;
      tx.oncomplete = () => (result ? resolve(result) : reject(new Error('indexeddb transaction ended without a decision')));
      tx.onabort = () => reject(tx.error ?? new Error('indexeddb transaction aborted'));
      tx.onerror = () => reject(tx.error ?? new Error('indexeddb transaction failed'));
      const read = store.get(next.account) as IDBRequest<unknown>;
      read.onerror = () => reject(read.error ?? new Error('indexeddb request failed'));
      // The write is issued inside the read's own callback, where the transaction is certainly active.
      read.onsuccess = () => {
        const stored = parseStoredDevice(read.result, next.account);
        const { outcome, write, position } = decideAdvance(stored, next);
        result = { outcome, stored, position };
        if (write) store.put(write);
      };
    });
  } finally {
    db.close();
  }
}

export function indexedDbDeviceStore(factory: IDBFactory = indexedDB): DeviceStore {
  return {
    async get(account) {
      return parseStoredDevice(await withStore(factory, 'readonly', (s) => s.get(account) as IDBRequest<unknown>), account);
    },
    async put(device) {
      await withStore(factory, 'readwrite', (s) => s.put(device));
    },
    advance: (next) => advanceInTransaction(factory, next),
    async delete(account) {
      await withStore(factory, 'readwrite', (s) => s.delete(account));
    },
  };
}
