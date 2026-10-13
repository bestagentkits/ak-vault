/**
 * The only operational logger. It emits exactly: route template, HTTP status,
 * stable error code, latency, and a short hash prefix of the vault ID. It never
 * receives request/response bodies, tokens, proofs, idempotency keys, item IDs or
 * names, so it cannot leak them (data classification "Logs, traces and metrics").
 * The encrypted audit stream is separate and stored only in the vault object.
 */
import { sha256, utf8Encode } from '@ak-vault/protocol';

export interface OperationalLogEntry {
  route: string;
  status: number;
  code?: string | undefined;
  ms: number;
  vaultId?: string | undefined;
}

/** First 8 bytes of sha256("akv1/log-vault\n" + vault_id), hex: correlates without exposing the ID. */
export function vaultLogTag(vaultId: string): string {
  const digest = sha256(utf8Encode(`akv1/log-vault\n${vaultId}`)).subarray(0, 8);
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function logRequest(entry: OperationalLogEntry): void {
  const line: Record<string, string | number> = { route: entry.route, status: entry.status, ms: entry.ms };
  if (entry.code) line['code'] = entry.code;
  if (entry.vaultId) line['vault'] = vaultLogTag(entry.vaultId);
  console.log(JSON.stringify(line));
}
