/**
 * Entry of the throwaway LAB Worker used by the platform log disclosure scan
 * (../README.md). It is never deployed to staging or production.
 *
 * Every request is served by the real Worker entry (`src/index.ts`) and the real
 * Durable Object classes, unchanged. The only addition is a read-only dump route,
 * `POST /__lab/dump`, which returns every application row of the vault objects
 * named in the body and of the revocation registry, so the scan can search the
 * deployed Durable Object state the same way the vitest suite does. The route
 * answers only when `LAB_DUMP_SECRET` (a random per-run Worker secret) is
 * presented, and 404s otherwise, exactly like any unknown path outside `/v1`.
 */
import worker, { RevocationRegistry as RealRevocationRegistry, VaultDurableObject as RealVaultDurableObject } from '../../../src/index.js';
import { REVOCATION_REGISTRY_NAME } from '../../../src/auth/revocation-check.js';
import type { Env } from '../../../src/env.js';

interface LabEnv extends Env {
  LAB_DUMP_SECRET?: string;
}

const MAX_VAULTS_PER_DUMP = 64;

function cellText(value: unknown): string {
  if (value instanceof ArrayBuffer) {
    const bytes = new Uint8Array(value);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return `${new TextDecoder().decode(bytes)} ${btoa(binary)}`;
  }
  return String(value);
}

/** Every row of every application table, one line per row (as worker/test/helpers/disclosure-scan.ts). */
function dumpSql(sql: SqlStorage): { tables: string[]; rows: number; text: string } {
  const tables = sql
    .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
    .toArray()
    .map((r) => r.name)
    .filter((n) => !n.startsWith('_cf_') && !n.startsWith('sqlite_'));
  const lines: string[] = [];
  for (const table of tables) {
    for (const row of sql.exec(`SELECT * FROM "${table.replaceAll('"', '""')}"`).toArray()) lines.push(Object.values(row).map(cellText).join(' '));
  }
  return { tables, rows: lines.length, text: lines.join('\n') };
}

export class VaultDurableObject extends RealVaultDurableObject {
  labDump(): { tables: string[]; rows: number; text: string } {
    return dumpSql(this.ctx.storage.sql);
  }
}

export class RevocationRegistry extends RealRevocationRegistry {
  labDump(): { tables: string[]; rows: number; text: string } {
    return dumpSql(this.ctx.storage.sql);
  }
}

async function secretMatches(expected: string, presented: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(expected)), crypto.subtle.digest('SHA-256', enc.encode(presented))]);
  return crypto.subtle.timingSafeEqual(a, b);
}

async function labDump(request: Request, env: LabEnv): Promise<Response> {
  const notFound = new Response('not found', { status: 404 });
  const presented = request.headers.get('Lab-Dump-Secret');
  if (request.method !== 'POST' || !env.LAB_DUMP_SECRET || env.LAB_DUMP_SECRET.length < 32 || !presented) return notFound;
  if (!(await secretMatches(env.LAB_DUMP_SECRET, presented))) return notFound;
  let vaultIds: unknown;
  try {
    vaultIds = ((await request.json()) as { vault_ids?: unknown }).vault_ids;
  } catch {
    return new Response('bad request', { status: 400 });
  }
  if (!Array.isArray(vaultIds) || vaultIds.length === 0 || vaultIds.length > MAX_VAULTS_PER_DUMP || !vaultIds.every((v) => typeof v === 'string' && v.length > 0 && v.length <= 64)) {
    return new Response('bad request', { status: 400 });
  }
  const vaults: Record<string, { tables: string[]; rows: number; text: string }> = {};
  for (const id of vaultIds as string[]) {
    const stub = env.VAULT.get(env.VAULT.idFromName(id)) as unknown as DurableObjectStub<VaultDurableObject>;
    vaults[id] = await stub.labDump();
  }
  const registryStub = env.REVOCATIONS.get(env.REVOCATIONS.idFromName(REVOCATION_REGISTRY_NAME)) as unknown as DurableObjectStub<RevocationRegistry>;
  const registry = await registryStub.labDump();
  return Response.json({ vaults, registry });
}

export default {
  async fetch(request: Request, env: LabEnv): Promise<Response> {
    if (new URL(request.url).pathname === '/__lab/dump') return labDump(request, env);
    return worker.fetch(request, env);
  },
} satisfies ExportedHandler<LabEnv>;
