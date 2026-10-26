/**
 * Encrypted audit appends for the dashboard (spec §7). The dashboard writes an
 * entry after a rotation state change lands, under the audit key of the vault's
 * current key epoch. An entry is `{v:1, type, item_id, device_id, ts}` in the
 * shared event envelope (spec §7.1): a reader that does not define a `rotation_*`
 * type keeps its envelope only, never refusing the chain. It names the action, the
 * opaque item id, the author device and the time. It never carries an item name, a value, a provider or
 * any other metadata: the audit key holder learns that a rotation step happened
 * to an item, not what the item is.
 *
 * The signed item revision stays the authoritative record of the change. The
 * audit append is a second, best-effort record: a failure is reported to the
 * caller and never undoes the write.
 */
import { appendAuditEntry, auditEntryHash, parseAuditEventEnvelope, parseEnvelope, type AuditHead, type JsonObject } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import { isVaultApiError, type AkvClient } from './akv-client.js';
import type { VaultSnapshot } from './vault-sync.js';

export const ROTATION_AUDIT_ACTIONS = [
  'rotation_started',
  'rotation_vault_written',
  'rotation_revoked',
  'rotation_paused',
  'rotation_resumed',
  'rotation_failed',
  'rotation_cancelled',
  'rotation_cleared',
] as const;
export type RotationAuditAction = (typeof ROTATION_AUDIT_ACTIONS)[number];

/** Attempts when another device moved the chain head between the read and the append. */
const MAX_ATTEMPTS = 3;
/** Largest cursor the audit route accepts: a page past the end, so only the head comes back. */
const PAST_END_CURSOR = Number.MAX_SAFE_INTEGER;

function readHead(res: unknown): AuditHead | null {
  const head = typeof res === 'object' && res !== null ? (res as Record<string, unknown>)['head'] : undefined;
  if (head === null) return null;
  if (typeof head !== 'object' || head === undefined) throw new AppError('server');
  const { seq, head: hash } = head as Record<string, unknown>;
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0 || typeof hash !== 'string') throw new AppError('server');
  return { seq, head: hash };
}

/**
 * Read the head and check that the stored entry at that position hashes to it.
 * This catches a server whose head and entry disagree; it does not stop a server
 * that serves a consistent but truncated or forked chain (see the threat model).
 */
async function verifiedHead(client: AkvClient, base: string): Promise<AuditHead | null> {
  const head = readHead(await client.get(`${base}?cursor=${PAST_END_CURSOR}&limit=1`));
  if (head === null) return null;
  const page = (await client.get(`${base}?cursor=${head.seq}&limit=1`)) as { entries?: { seq?: unknown; entry?: unknown }[] } | null;
  const tail = page?.entries?.[0];
  if (!tail || tail.seq !== head.seq || auditEntryHash(parseEnvelope(tail.entry, 'audit entry')) !== head.head) throw new AppError('audit_failed');
  return head;
}

/** Append one rotation entry to the vault's audit stream; throws `audit_failed` when it cannot. */
export async function appendRotationAudit(args: { client: AkvClient; snapshot: VaultSnapshot; action: RotationAuditAction; itemId: string; nowMs: number }): Promise<void> {
  const { client, snapshot } = args;
  const keyEpoch = snapshot.state.key_epoch;
  const vk = snapshot.vaultKeys.get(keyEpoch);
  if (!vk || snapshot.state.rekey_required) throw new AppError('audit_failed');
  const base = `/v1/vaults/${encodeURIComponent(snapshot.vaultId)}/audit`;
  const event: JsonObject = { v: 1, type: args.action, item_id: args.itemId, device_id: snapshot.self.device_id, ts: args.nowMs };
  try {
    // Never seal an event other readers would refuse: it would stop their appends (spec §7.1).
    parseAuditEventEnvelope(event);
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const head = await verifiedHead(client, base);
      const { entry } = appendAuditEntry({ vk, vaultId: snapshot.vaultId, keyEpoch, head, event });
      try {
        await client.post(base, { start_seq: head ? head.seq + 1 : 0, prev: head ? head.head : '', entries: [entry] });
        return;
      } catch (err) {
        // Another device appended first: read the new head and seal again.
        if (isVaultApiError(err, 'conflict') && attempt < MAX_ATTEMPTS - 1) continue;
        throw err;
      }
    }
  } catch {
    throw new AppError('audit_failed');
  }
}
