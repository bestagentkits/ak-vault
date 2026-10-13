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
  'wraps.post',
  'item.get',
  'item.put',
  'changes.get',
  'checkpoints.get',
  'checkpoints.post',
  'audit.get',
  'audit.post',
  'recovery.get',
  'recovery.put',
] as const;
export type VaultOp = (typeof VAULT_OPS)[number];

export interface VaultRequest {
  op: VaultOp;
  vaultId: string;
  itemId?: string;
  method: string;
  /** Exact request URL compared with the proof `htu`. */
  htu: string;
  /** Path used in the idempotency request hash. */
  path: string;
  query: Record<string, string>;
  token: string;
  proof: string;
  idempotencyKey: string | null;
  body: Uint8Array;
  claims: VerifiedClaims;
  nowMs: number;
}

/** Ops that mutate state: Idempotency-Key is required and the handler runs in one transaction. */
export function isMutation(op: VaultOp): boolean {
  return op === 'genesis' || op.endsWith('.post') || op.endsWith('.put');
}
