/**
 * `tools/call` execution (spec §9.8): per-client rate budget, vault selection and
 * the account's membership check, relay to an online device of the account, and
 * the sealed fallback for `set`/`delete` when no device is online (spec §3.6).
 *
 * Arguments may carry a `set` value and results carry names and metadata: this is
 * the ADR 0002 D7 transit. Neither is logged, stored, audited or put in an error;
 * the log line and audit row carry the tool, a stable outcome code, latency and
 * hashed client/account only. Every result passes an output guard first, so no
 * tool can return a field named `value` or `secret` outside profile metadata.
 */
import { parseToolResult, sealOp, type JsonObject, type RelayErrorCode, type RelayTool, type Role, type SealedOperation } from '@ak-vault/protocol';
import type { McpClaims } from '../auth/jwt-verify.js';
import type { Env } from '../env.js';
import { accountLogTag, clientLogTag, logMcpCall } from '../http/operational-logger.js';
import { REMOTE_ACCESS_LIMITS } from '../limits.js';
import { relayStub, type RelayOutcome } from '../relay/relay-rpc.js';
import { splitArgs } from './tools.js';

/** Stable tool error codes: the device codes (§9.7) plus the MCP-only ones (§10). */
export type ToolErrorCode = RelayErrorCode | 'no_device_online' | 'device_timeout' | 'sealed_queue_full' | 'rate_limited';

export interface CallToolResult {
  content: { type: 'text'; text: string }[];
  structuredContent: Record<string, unknown>;
  isError: boolean;
}

const RELAY_HINT = 'Start `ak secrets sync now --watch --relay` on one of your devices.';

const MESSAGES: Record<ToolErrorCode, string> = {
  denied: 'The device refused this call.',
  pending_approval: 'The request is pending: approve it on one of your devices with `ak secrets approve`, then retry.',
  not_found: 'No secret matches.',
  invalid_args: 'The arguments do not match the tool input schema.',
  conflict: 'The secret changed concurrently; the device kept both versions as a conflict.',
  unsupported: 'The online device does not offer this tool.',
  internal: 'Internal error.',
  no_device_online: RELAY_HINT,
  device_timeout: 'The device did not answer in time; the outcome is unknown.',
  sealed_queue_full: 'The queue of writes waiting for a device is full. Start a device to drain it.',
  rate_limited: 'Too many calls. Retry after retry_after_s seconds.',
};

const NO_SEAL_KEY = 'No device is online and the vault has no seal key for writes yet. Run `ak secrets sync now` once on an owner device, or start `ak secrets sync now --watch --relay`.';
const VAULT_REQUIRED = 'Pass vault_id: your online devices hold several vaults, or none is online to choose one.';
const VAULT_UNKNOWN = 'vault_id does not name a vault this account can use.';
const VAULT_AUTO_UNKNOWN = 'The vault your online device holds is not one this account can use. Pass vault_id.';

function toolResult(structured: Record<string, unknown>, isError: boolean): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured, isError };
}

interface Outcome {
  result: CallToolResult;
  /** Stable code for the log line and audit row. */
  code: string;
}

function fail(code: ToolErrorCode, opts: { message?: string; extra?: Record<string, number> } = {}): Outcome {
  return { result: toolResult({ code, message: opts.message ?? MESSAGES[code], ...opts.extra }, true), code };
}

function ok(structured: Record<string, unknown>, code = 'ok'): Outcome {
  return { result: toolResult(structured, false), code };
}

/**
 * Defense in depth for the relay contract (spec §9.7 "A result MUST NOT contain an
 * item value"): the result must have its tool's exact shape, and the only `value`
 * keys allowed are a profile field's. Anything else is refused as `internal`.
 */
export function guardResult(tool: RelayTool, result: unknown): JsonObject | null {
  let parsed: JsonObject;
  try {
    parsed = parseToolResult(tool, result);
  } catch {
    return null;
  }
  const clean = (node: unknown, path: string[]): boolean => {
    if (Array.isArray(node)) return node.every((v, i) => clean(v, [...path, String(i)]));
    if (typeof node !== 'object' || node === null) return true;
    for (const [key, child] of Object.entries(node)) {
      const lower = key.toLowerCase();
      if (lower === 'secret') return false;
      if (lower === 'value' && path[path.length - 2] !== 'profile') return false;
      if (!clean(child, [...path, key])) return false;
    }
    return true;
  };
  return clean(parsed, []) ? parsed : null;
}

function fromRelay(tool: RelayTool, outcome: RelayOutcome): Outcome {
  switch (outcome.kind) {
    case 'result': {
      if (!outcome.ok) return fail(outcome.code);
      const guarded = guardResult(tool, outcome.result);
      return guarded ? ok(guarded) : fail('internal');
    }
    case 'timeout':
      return fail('device_timeout');
    case 'invalid_args':
      return fail('invalid_args');
    case 'denied':
      return fail('denied');
    case 'device_busy':
      return fail('rate_limited', { extra: { retry_after_s: 1 } });
    case 'no_device_online':
      return fail('no_device_online');
  }
}

function vaultStub(env: Env, vaultId: string) {
  return env.VAULT.get(env.VAULT.idFromName(vaultId));
}

/**
 * Seal a `set` or `delete` to the vault's current seal key and queue it (spec §3.6
 * "Who seals"): only for an `owner` or `editor` account, never without a current
 * seal-key document (the vault object withholds it while a rekey is pending).
 */
async function sealWrite(env: Env, claims: McpClaims, vaultId: string, role: Role, tool: 'set' | 'delete', args: JsonObject): Promise<Outcome> {
  if (role !== 'owner' && role !== 'editor') return fail('no_device_online');
  const vault = vaultStub(env, vaultId);
  const doc = await vault.getSealKey();
  if (!doc) return fail('no_device_online', { message: NO_SEAL_KEY });
  const name = args['name'] as string;
  let op: SealedOperation;
  if (tool === 'delete') op = { op: 'delete', name };
  else {
    const sensitivity = args['sensitivity'];
    op = { op: 'set', name, value: args['value'] as string, ...(sensitivity === 'normal' || sensitivity === 'high' ? { sensitivity } : {}) };
  }
  let wire;
  try {
    wire = sealOp(doc.seal_pub, {
      vaultId,
      keyEpoch: doc.key_epoch,
      origin: { kind: 'mcp', account: claims.sub, client_id: claims.client_id, grant_id: claims.grant_id },
      ts: Date.now(),
      op,
    });
  } catch {
    return fail('internal');
  } finally {
    // Drop the plaintext references as soon as the ciphertext exists (strings cannot be zeroized).
    delete args['value'];
    if (op.op === 'set') op.value = '';
  }
  const queued = await vault.enqueueSealed(wire);
  if (queued === 'queued') return ok({ status: 'queued', sealed_id: wire.sealed_id }, 'queued');
  if (queued === 'sealed_queue_full') return fail('sealed_queue_full');
  return fail('no_device_online');
}

async function execute(env: Env, claims: McpClaims, tool: RelayTool, rawArgs: unknown): Promise<Outcome> {
  const relay = relayStub(env, claims.sub);
  const rate = await relay.takeRate(claims.client_id, tool);
  if (!rate.ok) return fail('rate_limited', { extra: { retry_after_s: rate.retryAfterS ?? 60 } });

  const split = splitArgs(tool, rawArgs);
  if (!split.ok) return fail('invalid_args');
  const isWrite = tool === 'set' || tool === 'delete';

  let vaultId = split.vaultId;
  if (vaultId === undefined) {
    const known = await relay.knownVaults();
    if (known.length === 1) vaultId = known[0]!;
    else if (known.length === 0 && !isWrite) return fail('no_device_online');
    else return fail('invalid_args', { message: VAULT_REQUIRED });
  }

  // Membership of the account in the selected vault (spec §9.8). An unknown vault and
  // another account's vault answer alike, so the reply never says whether one exists.
  const role = await vaultStub(env, vaultId).accountRole(claims.sub);
  if (role === null) return fail('invalid_args', { message: split.vaultId === undefined ? VAULT_AUTO_UNKNOWN : VAULT_UNKNOWN });

  const deadlineMs = tool === 'run' ? REMOTE_ACCESS_LIMITS.relay_run_deadline_ms : REMOTE_ACCESS_LIMITS.relay_call_deadline_ms;
  const outcome = await relay.dispatch({
    vaultId,
    tool,
    args: split.args,
    caller: { clientId: claims.client_id, grantId: claims.grant_id, scopes: [...claims.scope] },
    deadlineMs,
  });
  if (outcome.kind === 'no_device_online' && isWrite) return sealWrite(env, claims, vaultId, role, tool, split.args);
  return fromRelay(tool, outcome);
}

/**
 * Run one tool call for an authenticated token whose scopes cover `tool`. Never
 * throws: an unavailable relay or vault object is an `internal` tool error.
 */
export async function callTool(env: Env, claims: McpClaims, tool: RelayTool, rawArgs: unknown): Promise<CallToolResult> {
  const started = Date.now();
  let outcome: Outcome;
  try {
    outcome = await execute(env, claims, tool, rawArgs);
  } catch {
    outcome = fail('internal');
  }
  const ms = Date.now() - started;
  const clientHash = clientLogTag(claims.client_id);
  let audited = false;
  // A call refused as rate_limited stores no audit row, so audit storage stays bounded
  // by the rate budgets rather than by raw request throughput; the log line still runs.
  if (outcome.code !== 'rate_limited') {
    try {
      audited = await relayStub(env, claims.sub).recordAudit({ clientHash, tool, outcome: outcome.code, ms });
    } catch {
      audited = false;
    }
  }
  logMcpCall({ tool, outcome: outcome.code, ms, client: clientHash, account: accountLogTag(claims.sub), audited });
  return outcome.result;
}
