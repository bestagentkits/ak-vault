/**
 * Cloudflare API reads for the platform log disclosure scan: Workers
 * Observability telemetry (events, traces, invocations), GraphQL analytics, the
 * workers.dev subdomain, and the checks that the lab Worker and its Durable
 * Object namespaces are gone. Credentials come from CLOUDFLARE_API_TOKEN and
 * CLOUDFLARE_ACCOUNT_ID in the environment; they are never printed, and error
 * messages carry only the endpoint label and HTTP status.
 */

import { fetchRetrying } from './fetch-retrying.js';

const API = 'https://api.cloudflare.com/client/v4';
export interface CloudflareCredentials {
  token: string;
  accountId: string;
}

export function credentialsFromEnv(): CloudflareCredentials {
  const token = process.env['CLOUDFLARE_API_TOKEN'];
  const accountId = process.env['CLOUDFLARE_ACCOUNT_ID'];
  if (!token || !accountId) throw new Error('CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID must be set in the environment');
  if (!/^[0-9a-f]{32}$/.test(accountId)) throw new Error('CLOUDFLARE_ACCOUNT_ID is not a Cloudflare account id');
  return { token, accountId };
}

/**
 * Replace every credential and account identifier in `text` (wrangler output and
 * error messages shown on failure): the token, the account id and, once known,
 * the account's workers.dev subdomain.
 */
export function redactAccount(text: string, creds: CloudflareCredentials, subdomain?: string): string {
  const out = text.replaceAll(creds.token, '<token>').replaceAll(creds.accountId, '<account>');
  return subdomain ? out.replaceAll(subdomain, '<subdomain>') : out;
}

interface Envelope<T> {
  success: boolean;
  result: T;
  errors?: { code?: number }[];
  result_info?: { cursor?: string; total_pages?: number; page?: number };
}

async function api<T>(creds: CloudflareCredentials, label: string, path: string, init: { method?: string; body?: unknown } = {}): Promise<{ status: number; body: Envelope<T> | null; text: string }> {
  const res = await fetchRetrying(
    `${API}${path}`,
    () => ({
      method: init.method ?? 'GET',
      headers: { Authorization: `Bearer ${creds.token}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
      ...(init.body ? { body: JSON.stringify(init.body) } : {}),
    }),
    `Cloudflare API ${label}`,
  );
  const text = await res.text();
  let body: Envelope<T> | null = null;
  try {
    body = JSON.parse(text) as Envelope<T>;
  } catch {
    body = null;
  }
  return { status: res.status, body, text };
}

async function apiOk<T>(creds: CloudflareCredentials, label: string, path: string, init: { method?: string; body?: unknown } = {}): Promise<{ result: T; text: string; info: Envelope<T>['result_info'] }> {
  const { status, body, text } = await api<T>(creds, label, path, init);
  if (status !== 200 || !body?.success) throw new Error(`Cloudflare API ${label} failed: HTTP ${status}, codes ${(body?.errors ?? []).map((e) => e.code).join(',') || 'none'}`);
  return { result: body.result, text, info: body.result_info };
}

export async function workersDevSubdomain(creds: CloudflareCredentials): Promise<string> {
  const { result } = await apiOk<{ subdomain: string }>(creds, 'workers.dev subdomain', `/accounts/${creds.accountId}/workers/subdomain`);
  if (!/^[a-z0-9-]+$/.test(result.subdomain)) throw new Error('unexpected workers.dev subdomain');
  return result.subdomain;
}

export async function scriptExists(creds: CloudflareCredentials, name: string): Promise<boolean> {
  const { status } = await api(creds, 'script settings', `/accounts/${creds.accountId}/workers/scripts/${encodeURIComponent(name)}/settings`);
  if (status === 404) return false;
  if (status === 200) return true;
  throw new Error(`Cloudflare API script settings: HTTP ${status}`);
}

/** Durable Object namespaces whose script is `name`. */
export async function durableObjectNamespaces(creds: CloudflareCredentials, name: string): Promise<{ id: string; class: string }[]> {
  const out: { id: string; class: string }[] = [];
  for (let page = 1; page <= 50; page++) {
    const { result, info } = await apiOk<{ id: string; class: string; script: string }[]>(creds, 'durable object namespaces', `/accounts/${creds.accountId}/workers/durable_objects/namespaces?per_page=1000&page=${page}`);
    out.push(...result.filter((n) => n.script === name).map((n) => ({ id: n.id, class: n.class })));
    if (!info?.total_pages || page >= info.total_pages) return out;
  }
  throw new Error('too many durable object namespace pages');
}

export type TelemetryView = 'events' | 'traces' | 'invocations';

export interface TelemetryPull {
  view: TelemetryView;
  /** Raw response body: the text the scan searches. */
  text: string;
  /** Rows returned (events, traces or invocations). */
  rows: number;
}

/** Largest page the query API is asked for. */
const PAGE = 2000;

function rowsOf(view: TelemetryView, result: Record<string, unknown>): unknown[] {
  if (view === 'events') return ((result['events'] as { events?: unknown[] } | undefined)?.events ?? []) as unknown[];
  if (view === 'traces') return (result['traces'] as unknown[] | undefined) ?? [];
  const inv = result['invocations'] as Record<string, unknown[]> | undefined;
  return inv ? Object.values(inv).flat() : [];
}

/**
 * Every telemetry row of `service` in [from, to] for one view. A run fits in one
 * page; a full page fails the run rather than paging, because a partial pull
 * would be reported as complete if the API's paging differs from what a client
 * assumes. Shorten the traffic or the window instead.
 */
export async function queryTelemetry(creds: CloudflareCredentials, service: string, view: TelemetryView, from: number, to: number): Promise<TelemetryPull> {
  const body = {
    queryId: `logscan-${view}`,
    timeframe: { from, to },
    view,
    limit: PAGE,
    dry: true,
    parameters: { view, filters: [{ key: '$metadata.service', operation: 'eq', type: 'string', value: service }] },
  };
  const { result, text } = await apiOk<Record<string, unknown>>(creds, `telemetry ${view}`, `/accounts/${creds.accountId}/workers/observability/telemetry/query`, { method: 'POST', body });
  const rows = rowsOf(view, result).length;
  if (rows >= PAGE) throw new Error(`telemetry ${view} filled a whole page (${rows} rows): the pull may be partial`);
  return { view, text, rows };
}

/** Workers and Durable Object analytics (the platform metrics) for `service` in [from, to]. */
export async function queryAnalytics(creds: CloudflareCredentials, service: string, from: number, to: number): Promise<{ text: string; requests: number }> {
  const query = `query ($account: String!, $script: String!, $from: Time!, $to: Time!) {
    viewer { accounts(filter: {accountTag: $account}) {
      workersInvocationsAdaptive(limit: 10000, filter: {scriptName: $script, datetime_geq: $from, datetime_leq: $to}) {
        sum { requests errors subrequests }
        dimensions { datetime scriptName scriptVersion status }
      }
      durableObjectsInvocationsAdaptiveGroups(limit: 10000, filter: {scriptName: $script, datetime_geq: $from, datetime_leq: $to}) {
        sum { requests errors }
        dimensions { datetime scriptName namespaceId objectId status }
      }
    } }
  }`;
  const variables = { account: creds.accountId, script: service, from: new Date(from).toISOString(), to: new Date(to).toISOString() };
  const res = await fetchRetrying(
    `${API}/graphql`,
    () => ({ method: 'POST', headers: { Authorization: `Bearer ${creds.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ query, variables }) }),
    'Cloudflare GraphQL',
  );
  const text = await res.text();
  const body = JSON.parse(text) as { data?: { viewer?: { accounts?: { workersInvocationsAdaptive?: { sum: { requests: number } }[] }[] } }; errors?: unknown[] | null };
  if (res.status !== 200 || (body.errors && body.errors.length > 0) || !body.data) throw new Error(`Cloudflare GraphQL failed: HTTP ${res.status}, ${body.errors?.length ?? 0} error(s)`);
  const rows = body.data.viewer?.accounts?.[0]?.workersInvocationsAdaptive ?? [];
  return { text, requests: rows.reduce((n, r) => n + r.sum.requests, 0) };
}
