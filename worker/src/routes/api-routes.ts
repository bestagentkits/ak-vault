/**
 * `/v1/vaults/...` route table: method + path -> vault op and the route template
 * used in operational logs. IDs in the path must be canonical b64 of 16 bytes.
 * The remote-access routes (spec §9.6) match only when remote access is enabled;
 * otherwise they are unknown paths (404).
 */
import { b64decodeLength } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';
import type { VaultOp } from '../vault/vault-request.js';

export interface MatchedRoute {
  op: VaultOp;
  template: string;
  vaultId: string;
  itemId?: string;
  sealedId?: string;
}

const COLLECTIONS: Record<string, Partial<Record<string, VaultOp>>> = {
  membership: { GET: 'membership.get', POST: 'membership.post' },
  wraps: { GET: 'wraps.get' },
  changes: { GET: 'changes.get' },
  checkpoints: { GET: 'checkpoints.get', POST: 'checkpoints.post' },
  audit: { GET: 'audit.get', POST: 'audit.post' },
  recovery: { GET: 'recovery.get', PUT: 'recovery.put' },
};

const REMOTE_COLLECTIONS: Record<string, Partial<Record<string, VaultOp>>> = {
  lookup: { GET: 'lookup.get' },
  'seal-key': { GET: 'sealkey.get', PUT: 'sealkey.put' },
  sealed: { GET: 'sealed.get' },
};

function opaqueId(value: string): string {
  try {
    b64decodeLength(value, 16);
  } catch {
    throw new ApiError('bad_request', { message: 'malformed id in path' });
  }
  return value;
}

/** Match `/v1/vaults/...`; returns null for paths that are not vault routes (404). */
export function matchVaultRoute(method: string, pathname: string, opts: { remoteAccess: boolean }): MatchedRoute | null {
  const parts = pathname.split('/');
  // ['', 'v1', 'vaults', vid, collection?, itemId?]
  if (parts.length < 4 || parts[1] !== 'v1' || parts[2] !== 'vaults' || !parts[3]) return null;
  const vid = parts[3];
  if (parts.length === 4) {
    if (method !== 'PUT') return null;
    return { op: 'genesis', template: 'PUT /v1/vaults/:vid', vaultId: opaqueId(vid) };
  }
  const collection = parts[4]!;
  if (collection === 'items' && parts.length === 6 && parts[5]) {
    const op: VaultOp | undefined = method === 'GET' ? 'item.get' : method === 'PUT' ? 'item.put' : undefined;
    if (!op) return null;
    return { op, template: `${method} /v1/vaults/:vid/items/:iid`, vaultId: opaqueId(vid), itemId: opaqueId(parts[5]) };
  }
  if (opts.remoteAccess && collection === 'sealed' && parts.length === 7 && parts[5] && parts[6] === 'ack') {
    if (method !== 'POST') return null;
    return { op: 'sealed.ack', template: 'POST /v1/vaults/:vid/sealed/:sid/ack', vaultId: opaqueId(vid), sealedId: opaqueId(parts[5]) };
  }
  if (parts.length !== 5) return null;
  const op = COLLECTIONS[collection]?.[method] ?? (opts.remoteAccess ? REMOTE_COLLECTIONS[collection]?.[method] : undefined);
  if (!op) return null;
  return { op, template: `${method} /v1/vaults/:vid/${collection}`, vaultId: opaqueId(vid) };
}
