/**
 * The browser half of a human-only write request (spec §9.9). An AI client asked
 * for a secret to be created or replaced and received only a request ID; the ID
 * reaches this page in the URL fragment, which no server sees. Here the request is
 * read, its sealed target name is opened with the vault's seal key (derived from the
 * vault key this device holds), and the person types the value, which is sealed and
 * signed locally by the ordinary item write. The request calls carry no value.
 */
import { b64decodeLength, deriveSealKeyPair, openSealedOp } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { AkvClient } from './akv-client.js';
import type { VaultSnapshot } from './vault-sync.js';

export type WriteOperation = 'create' | 'replace';

/** What the form needs, all read from the verified snapshot and the opened target. */
export interface WriteRequestView {
  requestId: string;
  operation: WriteOperation;
  name: string;
  sensitivity: 'normal' | 'high' | null;
  expiresAt: number;
}

/** The request ID the page keeps across the sign-in redirect (never a value). */
export interface WriteRequestStore {
  get(): string | null;
  set(rid: string): void;
  clear(): void;
}

const KEY = 'akv.write-request';

export function sessionWriteRequestStore(storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>): WriteRequestStore {
  return {
    get: () => {
      try {
        const v = storage.getItem(KEY);
        return v !== null && isRequestId(v) ? v : null;
      } catch {
        return null;
      }
    },
    set: (rid) => {
      try {
        storage.setItem(KEY, rid);
      } catch {
        /* a blocked store only costs the resume after sign-in */
      }
    },
    clear: () => {
      try {
        storage.removeItem(KEY);
      } catch {
        /* nothing to clear */
      }
    },
  };
}

export function memoryWriteRequestStore(): WriteRequestStore & { value: string | null } {
  const store = {
    value: null as string | null,
    get: () => store.value,
    set: (rid: string) => {
      store.value = rid;
    },
    clear: () => {
      store.value = null;
    },
  };
  return store;
}

export function isRequestId(value: string): boolean {
  try {
    b64decodeLength(value, 16);
    return true;
  } catch {
    return false;
  }
}

/** The request ID in `#write=<id>`, or null when the fragment is not one. */
export function requestIdFromHash(hash: string): string | null {
  const m = /^#write=([A-Za-z0-9_-]+)$/.exec(hash);
  return m && isRequestId(m[1]!) ? m[1]! : null;
}

function asObject(v: unknown): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new AppError('server');
  return v as Record<string, unknown>;
}

const path = (rid: string, action?: string): string => `/v1/write-intents/${encodeURIComponent(rid)}${action ? `/${action}` : ''}`;

/**
 * Read a pending request and open its target. Refuses (`write_request_gone`) a
 * request for another vault, one this device cannot open, or one whose sealed target
 * is not an MCP-originated set with an empty value.
 */
export async function loadWriteRequest(client: AkvClient, snapshot: VaultSnapshot, rid: string): Promise<WriteRequestView> {
  const body = asObject(await client.get(path(rid)));
  const target = asObject(body['target']);
  const epoch = target['key_epoch'];
  if (body['vault_id'] !== snapshot.vaultId || typeof epoch !== 'number') throw new AppError('write_request_gone');
  if (body['operation'] !== 'create' && body['operation'] !== 'replace') throw new AppError('server');
  const vk = snapshot.vaultKeys.get(epoch);
  if (!vk) throw new AppError('item_unreadable');
  let opened;
  try {
    opened = openSealedOp(deriveSealKeyPair(vk, snapshot.vaultId, epoch).secretKey, target, { vaultId: snapshot.vaultId });
  } catch {
    throw new AppError('write_request_gone');
  }
  const op = opened.op;
  if (opened.wire.origin.kind !== 'mcp' || op.op !== 'set' || op.value !== '') throw new AppError('write_request_gone');
  const sensitivity = body['sensitivity'];
  const expiresAt = body['expires_at'];
  if (typeof expiresAt !== 'number' || typeof body['request_id'] !== 'string' || body['request_id'] !== rid) throw new AppError('server');
  return {
    requestId: rid,
    operation: body['operation'],
    name: op.name,
    sensitivity: sensitivity === 'normal' || sensitivity === 'high' ? sensitivity : null,
    expiresAt,
  };
}

/** Bind this device, the item and the revision to the request; a moved head makes the server refuse. */
export async function claimWriteRequest(client: AkvClient, rid: string, itemId: string, baseRevision: number): Promise<void> {
  await client.post(path(rid, 'claim'), { item_id: itemId, base_revision: baseRevision });
}

/** Tell the server the record is written; it checks the vault's head and answers with the status. */
export async function completeWriteRequest(client: AkvClient, rid: string): Promise<string> {
  const body = asObject(await client.post(path(rid, 'complete')));
  return typeof body['status'] === 'string' ? body['status'] : 'failed';
}

export async function failWriteRequest(client: AkvClient, rid: string, reason: 'conflict' | 'failed'): Promise<void> {
  await client.post(path(rid, 'fail'), { reason });
}

export async function cancelWriteRequest(client: AkvClient, rid: string): Promise<void> {
  await client.post(path(rid, 'cancel'));
}
