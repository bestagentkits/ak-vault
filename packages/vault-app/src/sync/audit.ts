/**
 * Encrypted audit entries for rotation state changes (spec §7). Each entry
 * names the action, the opaque item ID, the acting device and the time, and
 * nothing else: never the item name, a value, a provider or a credential hint.
 * Entries are sealed under the audit key of the current key epoch, chained to
 * the stored head; the Worker refuses a stale head with `conflict`, and one
 * re-read then re-seal covers a concurrent append.
 *
 * The audit append follows the signed item revision, which is the record of the
 * change. A failed append never undoes or hides that revision; the caller says
 * so plainly.
 */
import { appendAuditEntry, type AuditHead, type JsonObject } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import { isVaultApiError, type AkvClient } from './akv-client.js';
import type { VaultSnapshot } from './vault-sync.js';

export type RotationAuditAction = 'rotation_started' | 'rotation_resumed' | 'rotation_vault_written' | 'rotation_revoked' | 'rotation_paused' | 'rotation_failed' | 'rotation_cancelled' | 'rotation_cleared';

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new AppError('server');
  return value as Record<string, unknown>;
}

function parseHead(value: unknown): AuditHead | null {
  if (value === null) return null;
  const h = asRecord(value);
  const seq = h['seq'];
  const head = h['head'];
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0 || typeof head !== 'string') throw new AppError('server');
  return { seq, head };
}

async function storedHead(client: AkvClient, vaultId: string): Promise<AuditHead | null> {
  const body = asRecord(await client.get(`/v1/vaults/${encodeURIComponent(vaultId)}/audit?cursor=0&limit=1`));
  return parseHead(body['head'] ?? null);
}

/** Append one rotation entry. Resolves true when the Worker stored it; false when it could not be recorded. */
export async function appendRotationAudit(args: { client: AkvClient; snapshot: VaultSnapshot; action: RotationAuditAction; itemId: string; nowMs: number }): Promise<boolean> {
  const { client, snapshot } = args;
  const vk = snapshot.vaultKeys.get(snapshot.state.key_epoch);
  if (!vk) return false;
  const event: JsonObject = { v: 1, action: args.action, item_id: args.itemId, device: snapshot.self.device_id, ts: args.nowMs };
  try {
    for (let attempt = 0; attempt < 2; attempt++) {
      const head = await storedHead(client, snapshot.vaultId);
      const { entry } = appendAuditEntry({ vk, vaultId: snapshot.vaultId, keyEpoch: snapshot.state.key_epoch, head, event });
      try {
        await client.post(`/v1/vaults/${encodeURIComponent(snapshot.vaultId)}/audit`, { start_seq: head ? head.seq + 1 : 0, prev: head ? head.head : '', entries: [entry] });
        return true;
      } catch (err) {
        if (isVaultApiError(err, 'conflict') && attempt === 0) continue;
        throw err;
      }
    }
  } catch {
    return false;
  }
  return false;
}
