/**
 * Run configuration and readiness gates. Every live suite asks `gate()` first and
 * skips with a stated reason when its prerequisite is absent; a skip is an
 * environment blocker, never a pass. Nothing here reads or prints credentials:
 * the signed-in account is a Playwright storage-state file kept outside the repo.
 */
import { existsSync } from 'node:fs';

export const BASE_URL = normalizeOrigin(process.env['VAULT_E2E_BASE_URL'] ?? 'https://vault-staging.agentkit.best', 'VAULT_E2E_BASE_URL');
export const AK_WEB_ORIGIN = normalizeOrigin(process.env['VAULT_E2E_AK_WEB_ORIGIN'] ?? 'https://staging.agentkit.best', 'VAULT_E2E_AK_WEB_ORIGIN');
export const STORAGE_STATE = process.env['VAULT_E2E_STORAGE_STATE'] || '';
export const SECOND_STORAGE_STATE = process.env['VAULT_E2E_SECOND_STORAGE_STATE'] || '';
export const AK_BIN = process.env['AK_BIN'] || '';
/** Owner device HOME for the phase-10 `ak`: a temp directory the operator prepared, never the real home. */
export const AK_OWNER_HOME = process.env['AK_E2E_OWNER_HOME'] || '';

/** The run's sentinel value, generated in global setup and held in process memory only. */
export function runSentinel(): string {
  const value = process.env['VAULT_E2E_RUN_SENTINEL'];
  if (!value) throw new Error('VAULT_E2E_RUN_SENTINEL is unset: global setup did not run');
  return value;
}

/** The run's secret-name sentinel. The dashboard displays names by design, so it is checked in logs and responses only. */
export function runNameSentinel(): string {
  const value = process.env['VAULT_E2E_RUN_NAME_SENTINEL'];
  if (!value) throw new Error('VAULT_E2E_RUN_NAME_SENTINEL is unset: global setup did not run');
  return value;
}

function normalizeOrigin(raw: string, name: string): string {
  const url = new URL(raw);
  const local = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) throw new Error(`${name} must be https`);
  if (url.pathname !== '/' || url.search || url.hash) throw new Error(`${name} must be an origin without a path`);
  return url.origin;
}

export interface Probe {
  status: number;
  json: Record<string, unknown> | null;
}

/** A plain GET that never follows redirects and never sends credentials. */
export async function probe(url: string): Promise<Probe> {
  const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(20_000) });
  const text = await res.text();
  let json: Record<string, unknown> | null = null;
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

export interface Gate {
  /** Reason the remote-access suites cannot run against the target, or null. */
  remote: string | null;
  /** Reason the OAuth-dependent suites cannot run (ak-web authorization server), or null. */
  oauth: string | null;
  /** Reason the signed-in dashboard suites cannot run, or null. */
  account: string | null;
  /** Reason the suites that need the phase-10 `ak` binary cannot run, or null. */
  ak: string | null;
}

let cached: Promise<Gate> | null = null;

/** Readiness of the target. Cached per worker process; probes are GETs only. */
export function gate(): Promise<Gate> {
  cached ??= computeGate();
  return cached;
}

async function computeGate(): Promise<Gate> {
  const health = await probe(`${BASE_URL}/healthz`).catch(() => null);
  const remoteValue = health?.json?.['remote_access'];
  const remote =
    remoteValue === true
      ? null
      : `staging does not report remote_access=true (healthz HTTP ${health?.status ?? 'unreachable'}, field ${remoteValue === undefined ? 'absent' : 'false'}); the remote-access deploy has not reached ${BASE_URL}`;

  const as = await probe(`${AK_WEB_ORIGIN}/.well-known/oauth-authorization-server`).catch(() => null);
  const oauth = as?.status === 200 ? null : `ak-web staging authorization server answers HTTP ${as?.status ?? 'unreachable'} (env blocker: OAuth signing configuration)`;

  const account = STORAGE_STATE && existsSync(STORAGE_STATE) ? null : 'no signed-in staging test account (VAULT_E2E_STORAGE_STATE unset or missing)';
  const ak = !AK_BIN || !existsSync(AK_BIN)
    ? 'needs the phase-10 relay-capable ak binary (AK_BIN unset or missing)'
    : !AK_OWNER_HOME || !existsSync(AK_OWNER_HOME)
      ? 'needs a prepared owner HOME for the staging test account (AK_E2E_OWNER_HOME unset or missing)'
      : null;
  return { remote, oauth, account, ak };
}
