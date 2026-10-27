/**
 * The structured-clonable request the Worker hands to a vault Durable Object
 * after token and revocation checks. The object re-checks everything that needs
 * vault state: membership, proof of possession, scope and role.
 */
import type { VerifiedClaims } from '../auth/jwt-verify.js';

export const VAULT_OPS = [
  'genesis',
  'membership.get',
  'membership.post',
  'wraps.get',
  'item.get',
  'item.put',
  'changes.get',
  'checkpoints.get',
  'checkpoints.post',
  'audit.get',
  'audit.post',
  'recovery.get',
  'recovery.put',
  // Remote access (spec §9.6), routed only where it is enabled.
  'lookup.get',
  'sealkey.get',
  'sealkey.put',
  'sealed.get',
  'sealed.ack',
  // Human write requests (spec §9.6), routed only where remote access is enabled.
  'writereq.get',
  'writereq.close',
] as const;
export type VaultOp = (typeof VAULT_OPS)[number];

export interface VaultRequest {
  op: VaultOp;
  vaultId: string;
  itemId?: string;
  /** `sealed_id` path segment of `POST …/sealed/{sealed_id}/ack`. */
  sealedId?: string;
  /** `request_id` path segment of `…/write-requests/{request_id}`, or the `write_request` query of an item PUT. */
  writeRequestId?: string;
  method: string;
  /** Exact request URL compared with the proof `htu`. */
  htu: string;
  /** Path used in the idempotency request hash. */
  path: string;
  query: Record<string, string>;
  /** Every query parameter in order, repeats included (`lookup` pairs `tag` with `key_epoch`). */
  queryList: [string, string][];
  token: string;
  proof: string;
  idempotencyKey: string | null;
  /** `AKV-Device-Key` header: the caller's sign_pub, used only by a not-yet-enrolled device reading the recovery bundle or membership. */
  deviceKey: string | null;
  body: Uint8Array;
  claims: VerifiedClaims;
  nowMs: number;
  /** Whether the deployment enables remote access (gates the item PUT `name_tag` wrapper). */
  remoteAccess: boolean;
}

/** Ops that mutate state: Idempotency-Key is required and the handler runs in one transaction. */
export function isMutation(op: VaultOp): boolean {
  return op === 'genesis' || op === 'sealed.ack' || op === 'writereq.close' || op.endsWith('.post') || op.endsWith('.put');
}
