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

function logTag(context: string, value: string): string {
  const digest = sha256(utf8Encode(`${context}\n${value}`)).subarray(0, 8);
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** First 8 bytes of sha256("akv1/log-vault\n" + vault_id), hex: correlates without exposing the ID. */
export function vaultLogTag(vaultId: string): string {
  return logTag('akv1/log-vault', vaultId);
}

/** Hashed account (token `sub`) for log lines and the relay audit. */
export function accountLogTag(sub: string): string {
  return logTag('akv1/log-account', sub);
}

/** Hashed MCP `client_id` for log lines and the relay audit. */
export function clientLogTag(clientId: string): string {
  return logTag('akv1/log-client', clientId);
}

/**
 * A relay connection event: the event name, the close code the server sent, and
 * the hashed account. Never frames, arguments, results, tokens or IDs.
 */
export function logRelayEvent(entry: { event: 'close'; code: number; sub: string }): void {
  console.log(JSON.stringify({ route: 'relay', event: entry.event, code: entry.code, account: accountLogTag(entry.sub) }));
}

export function logRequest(entry: OperationalLogEntry): void {
  const line: Record<string, string | number> = { route: entry.route, status: entry.status, ms: entry.ms };
  if (entry.code) line['code'] = entry.code;
  if (entry.vaultId) line['vault'] = vaultLogTag(entry.vaultId);
  console.log(JSON.stringify(line));
}
