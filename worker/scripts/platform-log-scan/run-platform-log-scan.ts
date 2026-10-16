/**
 * Platform log disclosure scan on a deployed lab Worker. See README.md here.
 *
 *   CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… \
 *     tsx scripts/platform-log-scan/run-platform-log-scan.ts [--name ak-vault-lab-logscan-…] [--report FILE]
 *
 * Deploys a throwaway Worker (real code, production observability plus traces,
 * synthetic issuer), captures `wrangler tail` while seeded two-device traffic
 * and error paths run, dumps its Durable Objects, pulls Workers Observability
 * events, traces and invocations and the GraphQL analytics for it, and searches
 * all of it (and every response) for every planted value. Then it deletes the
 * Worker and checks that it and its Durable Object namespaces are gone.
 *
 * Output and the optional JSON report hold counts only: never a planted value,
 * credential, or the captured telemetry. Exit 0 only when the scan found nothing
 * in a gating category, every source was non-empty and the lab was deleted.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, type ChildProcess } from 'node:child_process';
import { b64encode, randomBytes } from '@ak-vault/protocol';
import { fetchRetrying } from './fetch-retrying.js';
import { credentialsFromEnv, durableObjectNamespaces, scriptExists, workersDevSubdomain, type CloudflareCredentials } from './cloudflare-api.js';
import { LabClient, LabIssuer } from './lab-client.js';
import { runLabTraffic, type StepResult } from './lab-traffic.js';
import { LAB_NAME_PATTERN, WORKER_DIR, countTailEvents, labObservability, startTail, stopProcess, writeLabConfig, wrangler } from './lab-worker-lifecycle.js';
import { NeedleSet, selfTestNeedleScan } from './needle-scan.js';
import { pullAnalytics, pullTelemetry, sleep, waitFor } from './telemetry-polling.js';

/** Categories that must have zero hits everywhere. The others are reported for context. */
const GATING = ['secret_names', 'secret_values', 'recovery_material', 'tokens', 'proofs', 'keys', 'idempotency_keys', 'webhook_material', 'request_body_canaries', 'request_header_canaries'];
/** Request URLs (with their opaque IDs, and any canary a client puts there) are platform request metadata. */
const INFORMATIONAL = ['url_canaries', 'opaque_ids'];

const say = (line: string) => process.stdout.write(`${line}\n`);

function args(): { name: string; report?: string; keepCapture?: string } {
  const argv = process.argv.slice(2);
  const stamp = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Saigon', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    .format(new Date())
    .replace(/[^0-9]/g, '');
  let name = `ak-vault-lab-logscan-${stamp}`;
  let report: string | undefined;
  let keepCapture: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--name') name = argv[++i] ?? '';
    else if (argv[i] === '--report') report = argv[++i];
    else if (argv[i] === '--keep-capture') keepCapture = argv[++i];
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (!LAB_NAME_PATTERN.test(name)) throw new Error(`lab name must match ${LAB_NAME_PATTERN}`);
  if (keepCapture !== undefined && (keepCapture === '' || existsSync(keepCapture))) throw new Error('--keep-capture needs a directory that does not exist yet');
  return { name, ...(report ? { report } : {}), ...(keepCapture ? { keepCapture } : {}) };
}

interface SourceResult {
  bytes: number;
  rows?: number;
  hits: Record<string, number>;
}

async function deleteLab(creds: CloudflareCredentials, name: string, cwd: string, log: string): Promise<{ scriptGone: boolean; namespacesLeft: number }> {
  if (await scriptExists(creds, name)) await wrangler(['delete', '--name', name, '--force'], cwd, log, creds);
  let namespacesLeft = -1;
  let scriptGone = false;
  await waitFor('lab deletion', 120_000, 5_000, async () => {
    scriptGone = !(await scriptExists(creds, name));
    namespacesLeft = (await durableObjectNamespaces(creds, name)).length;
    return scriptGone && namespacesLeft === 0;
  }).catch(() => undefined);
  return { scriptGone, namespacesLeft };
}

async function main(): Promise<number> {
  selfTestNeedleScan();
  const { name, report, keepCapture } = args();
  const creds = credentialsFromEnv();
  if (await scriptExists(creds, name)) throw new Error('a Worker with the lab name already exists; pick another --name');
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim();
  const dirty = execFileSync('git', ['status', '--porcelain', '--', 'src', 'wrangler.jsonc', 'public', 'scripts/platform-log-scan', '../packages/protocol'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim() !== '';
  const origin = `https://${name}.${await workersDevSubdomain(creds)}.workers.dev`;
  const priv = mkdtempSync(join(tmpdir(), 'akvault-logscan-'));
  const log = join(priv, 'wrangler.log');
  const needles = new NeedleSet();
  let tail: ChildProcess | undefined;
  let deployed = false;
  let steps: StepResult[] = [];
  let requests = 0;
  let tailFetches = 0;
  const sources: Record<string, SourceResult> = {};
  let cleanup: { scriptGone: boolean; namespacesLeft: number } = { scriptGone: false, namespacesLeft: -1 };
  const problems: string[] = [];
  const cleanupProblems: string[] = [];
  const settings = labObservability();
  say(`lab ${name} at ${commit}${dirty ? ' (uncommitted changes)' : ''}`);
  try {
    const issuer = await LabIssuer.create('https://logscan-issuer.ak-vault.invalid', origin, needles);
    const webhookSecret = b64encode(randomBytes(32));
    const dumpSecret = b64encode(randomBytes(32));
    needles.add('webhook_material', webhookSecret);
    needles.add('lab_harness', dumpSecret);
    const secretsFile = join(priv, 'lab.secrets.json');
    writeFileSync(secretsFile, JSON.stringify({ REVOCATION_WEBHOOK_SECRET: webhookSecret, LAB_DUMP_SECRET: dumpSecret }), { mode: 0o600 });
    const config = writeLabConfig(priv, name, { issuer: issuer.issuer, audience: origin, jwks: issuer.publicJwks });

    say('deploying the lab Worker');
    deployed = true;
    await wrangler(['deploy', '--config', config.path, '--secrets-file', secretsFile], priv, log, creds);
    rmSync(secretsFile);
    const client = new LabClient(origin, issuer, needles);
    await waitFor('the lab Worker', 180_000, 3_000, async () => (await fetch(`${origin}/healthz`, { signal: AbortSignal.timeout(10_000) })).status === 200);

    const tailFile = join(priv, 'tail.jsonl');
    tail = startTail(name, priv, tailFile);
    const from = Date.now() - 60_000;
    await waitFor('wrangler tail to capture', 120_000, 3_000, async () => {
      await fetch(`${origin}/healthz`, { signal: AbortSignal.timeout(10_000) });
      await sleep(2_000);
      return readFileSync(tailFile, 'utf8').includes('"outcome"');
    });

    say('running seeded traffic');
    const traffic = await runLabTraffic(client, needles, webhookSecret);
    steps = traffic.steps;
    requests = client.requests;
    const failed = steps.filter((s) => s.expected !== s.got);
    say(`  ${steps.length} steps, ${client.requests} requests, ${failed.length} unexpected status(es)`);
    for (const s of failed) problems.push(`step "${s.step}": expected ${s.expected}, got ${s.got}`);
    await sleep(15_000);
    await stopProcess(tail);
    tail = undefined;
    // The window closes before the dump request, which is lab-only harness traffic.
    const to = Date.now();

    say('dumping Durable Objects');
    const dumpRes = await fetchRetrying(`${origin}/__lab/dump`, () => ({ method: 'POST', headers: { 'Lab-Dump-Secret': dumpSecret, 'Content-Type': 'application/json' }, body: JSON.stringify({ vault_ids: traffic.vaultIds }) }), 'lab dump');
    if (dumpRes.status !== 200) throw new Error(`lab dump failed with ${dumpRes.status}`);
    const dump = (await dumpRes.json()) as { vaults: Record<string, { tables: string[]; rows: number; text: string }>; registry: { tables: string[]; rows: number; text: string } };
    const doText = [...Object.values(dump.vaults).map((v) => v.text), dump.registry.text].join('\n');
    const doRows = Object.values(dump.vaults).reduce((n, v) => n + v.rows, 0) + dump.registry.rows;
    const vaultTables = new Set(Object.values(dump.vaults).flatMap((v) => v.tables));
    for (const t of ['records', 'audit_entries', 'recovery_blob', 'idempotency', 'proof_jti']) if (!vaultTables.has(t)) problems.push(`vault dump lacks table ${t}`);

    say('pulling platform telemetry (ingestion can take minutes)');
    const telemetry = await pullTelemetry(creds, name, from, to, client.requests - 5);
    const analytics = await pullAnalytics(creds, name, from, to, Math.floor(client.requests / 2));

    const tailText = readFileSync(tailFile, 'utf8');
    if (keepCapture) {
      // Raw captures hold the run's synthetic tokens and canaries: for locating a hit, then delete.
      mkdirSync(keepCapture, { recursive: true, mode: 0o700 });
      const files: Record<string, string> = { 'tail.jsonl': tailText, 'events.json': telemetry.events.text, 'traces.json': telemetry.traces.text, 'invocations.json': telemetry.invocations.text, 'analytics.json': analytics.text, 'do-dump.txt': doText, 'responses.txt': client.responses.join('\n') };
      for (const [f, text] of Object.entries(files)) writeFileSync(join(keepCapture, f), text, { mode: 0o600 });
    }
    const scan = (text: string, rows?: number): SourceResult => ({ bytes: Buffer.byteLength(text), ...(rows === undefined ? {} : { rows }), hits: needles.count(text) });
    const tailCounts = countTailEvents(tailText);
    tailFetches = tailCounts.fetches;
    sources['wrangler tail'] = scan(tailText, tailCounts.events);
    sources['observability events'] = scan(telemetry.events.text, telemetry.events.rows);
    sources['observability traces'] = scan(telemetry.traces.text, telemetry.traces.rows);
    sources['observability invocations'] = scan(telemetry.invocations.text, telemetry.invocations.rows);
    sources['graphql analytics'] = scan(analytics.text);
    sources['durable object dump'] = scan(doText, doRows);
    sources['responses'] = scan(client.responses.join('\n'), client.responses.length);
    for (const [source, r] of Object.entries(sources)) if (r.bytes === 0 || r.rows === 0) problems.push(`source "${source}" is empty`);
  } finally {
    await stopProcess(tail);
    if (deployed) {
      say('deleting the lab Worker');
      cleanup = await deleteLab(creds, name, priv, log).catch((err: Error) => {
        cleanupProblems.push(`lab deletion failed: ${err.message}`);
        return cleanup;
      });
      if (!cleanup.scriptGone) cleanupProblems.push(`the lab Worker ${name} still exists: delete it by hand`);
      if (cleanup.namespacesLeft !== 0) cleanupProblems.push(`lab Durable Object namespaces not confirmed gone (${cleanup.namespacesLeft})`);
    }
    rmSync(priv, { recursive: true, force: true });
    // Printed here so they are seen even when the run itself failed.
    for (const p of cleanupProblems) say(`cleanup problem: ${p}`);
  }

  const seeded = needles.categories();
  const categories = [...GATING.filter((c) => seeded.includes(c)), ...seeded.filter((c) => !GATING.includes(c))];
  say('\nhits per source (gating categories first):');
  const header = ['source', 'bytes', 'rows', ...categories];
  say(header.join('\t'));
  for (const [source, r] of Object.entries(sources)) say([source, r.bytes, r.rows ?? '', ...categories.map((c) => r.hits[c] ?? 0)].join('\t'));
  const gatingHits = Object.values(sources).reduce((n, r) => n + GATING.reduce((m, c) => m + (r.hits[c] ?? 0), 0), 0);
  for (const c of GATING) if (!seeded.includes(c)) problems.push(`category ${c} was never seeded`);
  const ok = gatingHits === 0 && problems.length === 0 && cleanupProblems.length === 0;
  for (const p of problems) say(`problem: ${p}`);
  say(`tail captured ${tailFetches} fetch invocation(s) for ${requests} traffic request(s) plus warm-up probes`);
  say(`\nresult: ${ok ? 'PASS' : 'FAIL'} (${gatingHits} gating hit(s))`);
  if (report) {
    writeFileSync(
      report,
      `${JSON.stringify(
        {
          date: new Date().toISOString(),
          commit,
          dirty,
          lab: name,
          observability: { production: settings.production, scanned: settings.lab },
          gating: GATING,
          informational: [...INFORMATIONAL, 'lab_harness'],
          needle_forms: needles.formCounts(),
          steps: { total: steps.length, unexpected: steps.filter((s) => s.expected !== s.got).length },
          traffic_requests: requests,
          tail_fetch_events: tailFetches,
          sources,
          cleanup,
          problems: [...problems, ...cleanupProblems],
          result: ok ? 'pass' : 'fail',
        },
        null,
        2,
      )}\n`,
    );
  }
  return ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err: Error) => {
    process.stderr.write(`platform log scan failed: ${err.message}\n`);
    process.exit(2);
  },
);
