/**
 * RPC contract of the `AccountRelay` Durable Object (spec §9.7), used by the
 * Worker's MCP handler. Obtain the stub with `relayStub(env, sub)`. Arguments and
 * results may hold D7 transit plaintext (ADR 0002): never log them.
 */
import type { RelayErrorCode, RelayTool } from '@ak-vault/protocol';
import type { Env } from '../env.js';
import type { AccountRelay } from './account-relay-durable-object.js';

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
  /**
   * Only this device may take the call (an input request's issuing device, ADR 0004);
   * every other check still applies. When absent, the newest eligible device takes it.
   */
  deviceId?: string;
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
