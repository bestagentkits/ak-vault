/**
 * Human write requests (spec §3.9): an MCP client asked for a secret it must
 * never see, and the person types the value here. The link carries only two
 * opaque IDs in the fragment (`#write=<request_id>&vault=<vault_id>`); the
 * secret name is inside the sealed write intent, which this device opens with
 * `SealSK[e]` derived from its own `VK[e]`. Nothing from the request is trusted
 * until the intent opens and its header matches what the server answered.
 */
import {
  b64decodeLength,
  deriveSealKeyPair,
  openWriteIntent,
  type Sensitivity,
  type WriteIntentOperation,
} from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { AkvClient } from './akv-client.js';
import { validItemName, validMetaText } from './item-names.js';
import type { VaultSnapshot } from './vault-sync.js';

export interface WriteLink {
  requestId: string;
  vaultId: string;
}

/** What the person is shown and what the write needs. Never holds a value. */
export interface OpenedWriteRequest {
  requestId: string;
  operation: WriteIntentOperation;
  /** The requesting MCP client, printable ASCII (shown as text only). */
  clientId: string;
  /** Unix ms. */
  expiresAt: number;
  name: string;
  purpose: string | null;
  sensitivity: Sensitivity | null;
}

/** Outcomes and reasons this device may report; the Worker accepts no others. */
export type WriteCloseOutcome = { outcome: 'cancelled'; reason: 'user_cancelled' } | { outcome: 'failed'; reason: 'already_exists' | 'not_found' | 'device_error' };

/** A canonical 16-byte base64url ID (22 characters, strict decode). */
export function isOpaqueId(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{22}$/.test(value)) return false;
  try {
    b64decodeLength(value, 16);
    return true;
  } catch {
    return false;
  }
}

const LINK_FRAGMENT = /^#write=([A-Za-z0-9_-]{22})&vault=([A-Za-z0-9_-]{22})$/;

/** True when a fragment is meant as a write link (well formed or not), so it is cleared from the address bar. */
export function isWriteFragment(hash: string): boolean {
  return hash.startsWith('#write=');
}

/** Parse `#write=<request_id>&vault=<vault_id>` exactly; anything else is null. */
export function parseWriteLink(hash: string): WriteLink | null {
  const m = LINK_FRAGMENT.exec(hash);
  if (!m || !isOpaqueId(m[1]!) || !isOpaqueId(m[2]!)) return null;
  return { requestId: m[1]!, vaultId: m[2]! };
}

function requestPath(link: WriteLink): string {
  return `/v1/vaults/${encodeURIComponent(link.vaultId)}/write-requests/${encodeURIComponent(link.requestId)}`;
}

export async function fetchWriteRequest(client: AkvClient, link: WriteLink): Promise<unknown> {
  return client.get(requestPath(link));
}

export async function closeWriteRequest(client: AkvClient, link: WriteLink, close: WriteCloseOutcome): Promise<void> {
  await client.post(`${requestPath(link)}/close`, { outcome: close.outcome, reason: close.reason });
}

const PRINTABLE = /^[\x20-\x7e]{1,256}$/;

/**
 * Open the server's answer for `link` against the verified snapshot. Refused
 * (`vault_verification_failed`) when anything differs from the sealed header:
 * another vault, request, operation, client, expiry or account. A key epoch this
 * device never held is `item_unreadable`; a name or purpose that could pose as
 * different text is `invalid_name`.
 */
export function openWriteRequest(snapshot: VaultSnapshot, link: WriteLink, raw: unknown): OpenedWriteRequest {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new AppError('vault_verification_failed');
  const body = raw as Record<string, unknown>;
  const { request_id: requestId, operation, client_id: clientId, expires_at: expiresAt, intent } = body;
  if (link.vaultId !== snapshot.vaultId || requestId !== link.requestId) throw new AppError('vault_verification_failed');
  if (operation !== 'create' && operation !== 'replace') throw new AppError('vault_verification_failed');
  if (typeof clientId !== 'string' || !PRINTABLE.test(clientId)) throw new AppError('vault_verification_failed');
  if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt)) throw new AppError('vault_verification_failed');
  const epoch = typeof intent === 'object' && intent !== null ? (intent as Record<string, unknown>)['key_epoch'] : undefined;
  if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 1) throw new AppError('vault_verification_failed');
  const vk = snapshot.vaultKeys.get(epoch);
  if (!vk) throw new AppError('item_unreadable');
  const seal = deriveSealKeyPair(vk, snapshot.vaultId, epoch);
  let opened;
  try {
    opened = openWriteIntent(seal.secretKey, intent, { vaultId: snapshot.vaultId });
  } catch {
    throw new AppError('vault_verification_failed');
  } finally {
    seal.secretKey.fill(0);
  }
  const { wire, target } = opened;
  if (
    wire.request_id !== link.requestId ||
    wire.operation !== operation ||
    wire.expires_at !== expiresAt ||
    wire.origin.client_id !== clientId ||
    wire.origin.account !== snapshot.self.account
  ) {
    throw new AppError('vault_verification_failed');
  }
  if (!validItemName(target.name)) throw new AppError('invalid_name');
  if (target.purpose !== undefined && !validMetaText(target.purpose)) throw new AppError('invalid_name');
  return {
    requestId: link.requestId,
    operation,
    clientId,
    expiresAt,
    name: target.name,
    purpose: target.purpose ?? null,
    sensitivity: target.sensitivity ?? null,
  };
}
