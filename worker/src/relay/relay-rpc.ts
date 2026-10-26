/**
 * RPC contract of the `AccountRelay` Durable Object (spec §9.7), used by the
 * Worker's MCP handler. Obtain the stub with `relayStub(env, sub)`. Arguments and
 * results may hold D7 transit plaintext (ADR 0002): never log them.
 */
import type { RelayErrorCode, RelayTool } from '@ak-vault/protocol';
import type { Env } from '../env.js';
import type { ApiErrorCode } from '../http/errors.js';
import type { AccountRelay } from './account-relay-durable-object.js';
import type { IntentOp, IntentStatus } from './write-intent-store.js';

export type { IntentOp, IntentStatus };

export type { RelayErrorCode, RelayTool };

export interface RelayCaller {
  clientId: string;
  grantId: string;
  /** The MCP token's scopes (`vault-mcp:*`). */
  scopes: string[];
}

export interface RelayCall {
  /** Target vault; when absent the relay uses the one vault its online devices list. */
  vaultId?: string;
  tool: RelayTool;
  /** Tool arguments (spec §9.7 "Tools"), checked with `parseToolArgs` before relaying. */
  args: Record<string, unknown>;
  caller: RelayCaller;
  /** Requested device deadline; capped at `relay_call_deadline_ms` (`run`: `relay_run_deadline_ms`). */
  deadlineMs: number;
}

/**
 * - `result`: a verified device answer (`ok:true` results passed `parseToolResult`;
 *   one that did not is reported as `internal`).
 * - `no_device_online`: no open, announced device of the account serves the vault and tool.
 * - `timeout`: the chosen device did not answer in time, or disconnected first (outcome unknown).
 * - `invalid_args`: the call cannot be relayed (bad args or caller, oversize frame, or no
 *   `vaultId` while the online devices list several vaults or none can be chosen).
 * - `denied`: the caller's scopes do not cover the tool.
 * - `device_busy`: every eligible device already has `relay_calls_inflight_per_device` calls.
 */
export type RelayOutcome =
  | { kind: 'result'; ok: true; result: unknown; deviceId: string }
  | { kind: 'result'; ok: false; code: RelayErrorCode; deviceId: string }
  | { kind: 'no_device_online' }
  | { kind: 'timeout' }
  | { kind: 'invalid_args' }
  | { kind: 'denied' }
  | { kind: 'device_busy' };

export interface RateDecision {
  ok: boolean;
  retryAfterS?: number;
}

export interface RelayAuditEntry {
  /** Hashed client ID (`clientLogTag`), never the raw ID. */
  clientHash: string;
  tool: RelayTool;
  /** Stable outcome code, `[a-z_]{1,32}`. */
  outcome: string;
  ms: number;
}

/** The relay object of account `sub`. */
export function relayStub(env: Pick<Env, 'RELAY'>, sub: string): DurableObjectStub<AccountRelay> {
  return env.RELAY.get(env.RELAY.idFromName(`acct:${sub}`));
}

/** What `secrets_prepare_write` records: binding facts and the sealed target, never a value. */
export interface PrepareIntentArgs {
  vaultId: string;
  grantId: string;
  /** The MCP token's `iat`, kept so the grant's revocation is re-checked with the same rule. */
  grantIat: number;
  clientId: string;
  op: IntentOp;
  sensitivity?: 'normal' | 'high';
  /** Sealed-op wire object holding the target name, sealed to the vault's seal key. */
  target: unknown;
}

export type PrepareIntentResult = { ok: true; requestId: string; expiresAt: number } | { ok: false; code: 'too_many_open' | 'invalid' };

export interface IntentStatusResult {
  status: IntentStatus;
  /** Unix ms. */
  expiresAt: number;
}

export type IntentAction = 'view' | 'claim' | 'complete' | 'fail' | 'cancel';

/** One browser call to `/v1/write-intents/*`, already past the Worker's token and revocation checks. */
export interface IntentActionArgs {
  action: IntentAction;
  rid: string;
  sub: string;
  did: string;
  token: string;
  proof: string;
  htm: string;
  htu: string;
  body: Uint8Array;
  /** `claim`: the item the browser will write and the revision it writes over (0 for a new item). */
  itemId?: string;
  baseRevision?: number;
  /** `fail`: why the browser could not write. */
  reason?: 'conflict' | 'failed';
}

export type IntentActionResult =
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; code: ApiErrorCode; status?: number; extra?: Record<string, string | number | boolean> };
