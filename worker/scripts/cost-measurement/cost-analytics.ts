/**
 * GraphQL Analytics reads for the cost measurement: Worker invocations, Durable
 * Object invocations, Durable Object periodic usage (active time, billed duration,
 * SQLite rows read and written) and SQLite stored bytes, for one Worker script and
 * one time window. Results are aggregates only; namespace IDs are resolved to the
 * class they belong to and never returned or printed. Credentials come from the
 * caller and appear only in the Authorization header.
 */
import { durableObjectNamespaces, type CloudflareCredentials } from '../platform-log-scan/cloudflare-api.js';
import { fetchRetrying } from '../platform-log-scan/fetch-retrying.js';

/** Durable Object classes of the Worker, by the label reports use. */
export const DO_CLASSES = { vault: 'VaultDurableObject', registry: 'RevocationRegistry' } as const;
export type DoLabel = keyof typeof DO_CLASSES;
export type NamespaceIds = Record<DoLabel, string>;

export interface WorkerUsage {
  requests: number;
  errors: number;
  cpuTimeUs: number;
  cpuP50Us: number;
  cpuP99Us: number;
  wallP50Us: number;
}

export interface DurableObjectUsage {
  requests: number;
  errors: number;
  wallP50Us: number;
  wallP99Us: number;
  /** Wall-clock time the objects were active, microseconds. */
  activeTimeUs: number;
  /** Billed duration, GB-s. */
  durationGbS: number;
  cpuTimeUs: number;
  rowsRead: number;
  rowsWritten: number;
}

export interface WindowUsage {
  worker: WorkerUsage;
  objects: Record<DoLabel, DurableObjectUsage>;
}

/** The namespace ID of each Durable Object class of `script`; fails when one is missing. */
export async function namespaceIds(creds: CloudflareCredentials, script: string): Promise<NamespaceIds> {
  const all = await durableObjectNamespaces(creds, script);
  const find = (cls: string): string => {
    const hit = all.find((n) => n.class === cls);
    if (!hit) throw new Error(`no ${cls} namespace for the measured Worker`);
    return hit.id;
  };
  return { vault: find(DO_CLASSES.vault), registry: find(DO_CLASSES.registry) };
}

async function graphql<T>(creds: CloudflareCredentials, query: string, variables: Record<string, unknown>): Promise<T> {
  const res = await fetchRetrying(
    'https://api.cloudflare.com/client/v4/graphql',
    () => ({ method: 'POST', headers: { Authorization: `Bearer ${creds.token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ query, variables }) }),
    'Cloudflare GraphQL',
  );
  const text = await res.text();
  type Body = { data?: { viewer?: { accounts?: T[] } }; errors?: unknown[] | null };
  let body: Body | null = null;
  try {
    body = JSON.parse(text) as Body;
  } catch {
    body = null;
  }
  const account = body?.data?.viewer?.accounts?.[0];
  if (res.status !== 200 || (body?.errors && body.errors.length > 0) || !account) throw new Error(`Cloudflare GraphQL failed: HTTP ${res.status}, ${body?.errors?.length ?? 0} error(s)`);
  return account;
}

interface UsageAccount {
  worker: { sum: { requests: number; errors: number; cpuTimeUs: number }; quantiles: { cpuTimeP50: number; cpuTimeP99: number; wallTimeP50: number } }[];
  doInvocations: { sum: { requests: number; errors: number }; quantiles: { wallTimeP50: number; wallTimeP99: number }; dimensions: { namespaceId: string } }[];
  doPeriodic: { sum: { activeTime: number; duration: number; cpuTime: number; rowsRead: number; rowsWritten: number }; dimensions: { namespaceId: string } }[];
}

const USAGE_QUERY = `query ($account: String!, $script: String!, $ns: [String!], $from: Time!, $to: Time!) {
  viewer { accounts(filter: {accountTag: $account}) {
    worker: workersInvocationsAdaptive(limit: 10, filter: {scriptName: $script, datetime_geq: $from, datetime_lt: $to}) {
      sum { requests errors cpuTimeUs }
      quantiles { cpuTimeP50 cpuTimeP99 wallTimeP50 }
    }
    doInvocations: durableObjectsInvocationsAdaptiveGroups(limit: 10, filter: {namespaceId_in: $ns, datetime_geq: $from, datetime_lt: $to}) {
      sum { requests errors }
      quantiles { wallTimeP50 wallTimeP99 }
      dimensions { namespaceId }
    }
    doPeriodic: durableObjectsPeriodicGroups(limit: 10, filter: {namespaceId_in: $ns, datetime_geq: $from, datetime_lt: $to}) {
      sum { activeTime duration cpuTime rowsRead rowsWritten }
      dimensions { namespaceId }
    }
  } }
}`;

const emptyObject = (): DurableObjectUsage => ({ requests: 0, errors: 0, wallP50Us: 0, wallP99Us: 0, activeTimeUs: 0, durationGbS: 0, cpuTimeUs: 0, rowsRead: 0, rowsWritten: 0 });

/** Usage of `script` and its two Durable Object namespaces in [from, to). */
export async function windowUsage(creds: CloudflareCredentials, script: string, ns: NamespaceIds, from: number, to: number): Promise<WindowUsage> {
  const account = await graphql<UsageAccount>(creds, USAGE_QUERY, {
    account: creds.accountId,
    script,
    ns: [ns.vault, ns.registry],
    from: new Date(from).toISOString(),
    to: new Date(to).toISOString(),
  });
  const label = (id: string): DoLabel | undefined => (id === ns.vault ? 'vault' : id === ns.registry ? 'registry' : undefined);
  const objects: Record<DoLabel, DurableObjectUsage> = { vault: emptyObject(), registry: emptyObject() };
  for (const row of account.doInvocations) {
    const l = label(row.dimensions.namespaceId);
    if (!l) continue;
    objects[l] = { ...objects[l], requests: row.sum.requests, errors: row.sum.errors, wallP50Us: row.quantiles.wallTimeP50, wallP99Us: row.quantiles.wallTimeP99 };
  }
  for (const row of account.doPeriodic) {
    const l = label(row.dimensions.namespaceId);
    if (!l) continue;
    objects[l] = { ...objects[l], activeTimeUs: row.sum.activeTime, durationGbS: row.sum.duration, cpuTimeUs: row.sum.cpuTime, rowsRead: row.sum.rowsRead, rowsWritten: row.sum.rowsWritten };
  }
  const w = account.worker[0];
  const worker: WorkerUsage = w
    ? { requests: w.sum.requests, errors: w.sum.errors, cpuTimeUs: w.sum.cpuTimeUs, cpuP50Us: w.quantiles.cpuTimeP50, cpuP99Us: w.quantiles.cpuTimeP99, wallP50Us: w.quantiles.wallTimeP50 }
    : { requests: 0, errors: 0, cpuTimeUs: 0, cpuP50Us: 0, cpuP99Us: 0, wallP50Us: 0 };
  return { worker, objects };
}

/** Largest SQLite stored bytes per namespace reported in [from, to). */
export async function storedBytes(creds: CloudflareCredentials, ns: NamespaceIds, from: number, to: number): Promise<Record<DoLabel, number>> {
  const account = await graphql<{ storage: { max: { storedBytes: number }; dimensions: { namespaceId: string } }[] }>(
    creds,
    `query ($account: String!, $ns: [String!], $from: Time!, $to: Time!) {
      viewer { accounts(filter: {accountTag: $account}) {
        storage: durableObjectsSqlStorageGroups(limit: 10, filter: {namespaceId_in: $ns, datetime_geq: $from, datetime_lt: $to}) {
          max { storedBytes }
          dimensions { namespaceId }
        }
      } }
    }`,
    { account: creds.accountId, ns: [ns.vault, ns.registry], from: new Date(from).toISOString(), to: new Date(to).toISOString() },
  );
  const out: Record<DoLabel, number> = { vault: 0, registry: 0 };
  for (const row of account.storage) {
    if (row.dimensions.namespaceId === ns.vault) out.vault = row.max.storedBytes;
    else if (row.dimensions.namespaceId === ns.registry) out.registry = row.max.storedBytes;
  }
  return out;
}
