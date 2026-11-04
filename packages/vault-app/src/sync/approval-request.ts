/**
 * Remote secret-access approvals (spec §3.13): one of the person's devices asked
 * to use a secret and is waiting; this browser device reads the request and signs
 * an answer. The link carries only two opaque IDs in the fragment
 * (`#approval=<request_id>&vault=<vault_id>`). The subject (secret name, agent,
 * project, reason) is sealed under `VK[e]`, so the server sees none of it; nothing
 * is shown until the requester's signature verifies against this device's own
 * verified membership and the subject opens. No secret value is ever involved.
 */
import {
  approvalRequestDigest,
  openApprovalRequest,
  signApprovalDecisionAsync,
  type ApprovalDecisionKind,
  type ApprovalSubject,
  type DeviceSigner,
} from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { AkvClient } from './akv-client.js';
import { isOpaqueId } from './write-request.js';
import type { VaultSnapshot } from './vault-sync.js';

export interface ApprovalLink {
  requestId: string;
  vaultId: string;
}

/** What the person is shown. Every text field came out of the verified, opened subject. */
export interface OpenedApproval {
  requestId: string;
  /** device_id of the requesting device (a current human device of this account). */
  requester: string;
  subject: ApprovalSubject;
  /** Unix ms. */
  expiresAt: number;
  /** The request wire exactly as fetched; the decision binds its digest. */
  wire: unknown;
}

/** "Allow for a while" choices offered, in seconds; each is capped by the request's `max_ttl_s`. */
export const ALLOW_TTL_CHOICES_S = [900, 3600, 28_800] as const;

const LINK_FRAGMENT = /^#approval=([A-Za-z0-9_-]{22})&vault=([A-Za-z0-9_-]{22})$/;

/** True when a fragment is meant as an approval link (well formed or not), so it is cleared from the address bar. */
export function isApprovalFragment(hash: string): boolean {
  return hash.startsWith('#approval=');
}

/** Parse `#approval=<request_id>&vault=<vault_id>` exactly; anything else is null. */
export function parseApprovalLink(hash: string): ApprovalLink | null {
  const m = LINK_FRAGMENT.exec(hash);
  if (!m || !isOpaqueId(m[1]!) || !isOpaqueId(m[2]!)) return null;
  return { requestId: m[1]!, vaultId: m[2]! };
}

function requestPath(link: ApprovalLink): string {
  return `/v1/vaults/${encodeURIComponent(link.vaultId)}/approval-requests/${encodeURIComponent(link.requestId)}`;
}

export async function fetchApproval(client: AkvClient, link: ApprovalLink): Promise<unknown> {
  return client.get(requestPath(link));
}

/** IDs of the account's pending approvals in `vaultId`, newest first, for the dashboard list. */
export async function listPendingApprovals(client: AkvClient, vaultId: string): Promise<ApprovalLink[]> {
  const raw = await client.get(`/v1/vaults/${encodeURIComponent(vaultId)}/approval-requests?state=pending`);
  const list = typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>)['approvals'] : undefined;
  if (!Array.isArray(list)) throw new AppError('vault_verification_failed');
  const links: ApprovalLink[] = [];
  for (const entry of list) {
    const id = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>)['request_id'] : undefined;
    if (typeof id === 'string' && isOpaqueId(id)) links.push({ requestId: id, vaultId });
  }
  return links;
}

/**
 * Verify and open the server's answer for `link`. Refused (`vault_verification_failed`)
 * when the request is not pending, names another vault or request, comes from a device
 * that is not a current device of this account, is asked of a device that cannot
 * answer (not a human owner/editor), or does not verify and open. A
 * key epoch this device never held is `item_unreadable`.
 */
export function openApproval(snapshot: VaultSnapshot, link: ApprovalLink, raw: unknown, nowMs: number = Date.now()): OpenedApproval {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new AppError('vault_verification_failed');
  const body = raw as Record<string, unknown>;
  if (link.vaultId !== snapshot.vaultId || body['request_id'] !== link.requestId || body['state'] !== 'pending') throw new AppError('vault_verification_failed');
  const wire = body['request'];
  const fields = typeof wire === 'object' && wire !== null ? (wire as Record<string, unknown>) : {};
  const requester = snapshot.state.devices.find((d) => d.device_id === fields['requester']);
  // Any current device of this account may ask (a background job's machine device included);
  // only a human owner/editor answers, and never for itself.
  const self = snapshot.state.devices.find((d) => d.device_id === snapshot.self.device_id);
  const canAnswer = !!self && self.kind === 'human' && (self.role === 'owner' || self.role === 'editor');
  if (!canAnswer || !requester || requester.account !== snapshot.self.account || requester.device_id === snapshot.self.device_id) {
    throw new AppError('vault_verification_failed');
  }
  const epoch = fields['key_epoch'];
  if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 1) throw new AppError('vault_verification_failed');
  const vk = snapshot.vaultKeys.get(epoch);
  if (!vk) throw new AppError('item_unreadable');
  let opened;
  try {
    opened = openApprovalRequest(vk, wire, { vaultId: snapshot.vaultId, requesterSignPub: requester.sign_pub });
  } catch {
    throw new AppError('vault_verification_failed');
  }
  if (opened.wire.request_id !== link.requestId || opened.wire.expires_at <= nowMs) throw new AppError('vault_verification_failed');
  return { requestId: link.requestId, requester: requester.device_id, subject: opened.subject, expiresAt: opened.wire.expires_at, wire };
}

/** The "allow for a while" choices this request accepts. */
export function ttlChoices(opened: OpenedApproval): number[] {
  return ALLOW_TTL_CHOICES_S.filter((s) => s <= opened.subject.max_ttl_s);
}

/** Sign `decision` with this device's key and send it; the server accepts one decision per request. */
export async function decideApproval(args: {
  client: AkvClient;
  snapshot: VaultSnapshot;
  signer: DeviceSigner;
  opened: OpenedApproval;
  decision: ApprovalDecisionKind;
  ttlS?: number;
  nowMs?: number;
}): Promise<void> {
  const { opened, decision } = args;
  if (decision === 'allow_ttl' && (args.ttlS === undefined || args.ttlS > opened.subject.max_ttl_s)) throw new AppError('vault_verification_failed');
  const signed = await signApprovalDecisionAsync(args.signer, {
    request: opened.wire,
    decision,
    ...(decision === 'allow_ttl' ? { ttlS: args.ttlS } : {}),
    approver: args.snapshot.self.device_id,
    ts: args.nowMs ?? Date.now(),
  });
  if (signed.request_digest !== approvalRequestDigest(opened.wire)) throw new AppError('vault_verification_failed');
  await args.client.post(`${requestPath({ requestId: opened.requestId, vaultId: args.snapshot.vaultId })}/decision`, { decision: signed });
}
