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
 * Worker and checks that it and its Durable Object namespaces are gone, also
 * when the run fails or is interrupted (SIGINT, SIGTERM).
 *
 * Output and the optional JSON report hold counts only: never a planted value,
 * credential, account identifier or the captured telemetry. Exit 0 only when the
 * scan found nothing in a gating category, every source was non-empty and the
 * lab was deleted.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { b64encode, randomBytes } from '@ak-vault/protocol';
import { fetchRetrying } from './fetch-retrying.js';
import { credentialsFromEnv, durableObjectNamespaces, redactAccount, scriptExists, workersDevSubdomain, type CloudflareCredentials } from './cloudflare-api.js';
import { LabClient, LabIssuer } from './lab-client.js';
import { runLabTraffic, type StepResult } from './lab-traffic.js';
import { WORKER_DIR, countTailEvents, labObservability, startTail, stopTail, writeLabConfig, wrangler, type TailCapture } from './lab-worker-lifecycle.js';
import { NeedleSet, selfTestNeedleScan } from './needle-scan.js';
import { scanOptions } from './scan-options.js';
import { concludeScan, say, type SourceResult } from './scan-report.js';
import { pullAnalytics, pullTelemetry, sleep, waitFor } from './telemetry-polling.js';

/** Hides credentials and account identifiers in anything printed; widened once they are known. */
let redact = (text: string) => text;
/** Deletes the lab and the private directory; set once there is something to clean up. */
let cleanupOnInterrupt: (() => Promise<unknown>) | undefined;

/** Delete the lab (again, if a deploy finished after the first attempt) until it and its namespaces are gone. */
async function deleteLab(creds: CloudflareCredentials, name: string, cwd: string, log: string): Promise<{ scriptGone: boolean; namespacesLeft: number }> {
  let namespacesLeft = -1;
  let scriptGone = false;
  await waitFor('lab deletion', 120_000, 5_000, async () => {
    if (await scriptExists(creds, name)) await wrangler(['delete', '--name', name, '--force'], cwd, log, redact);
    scriptGone = !(await scriptExists(creds, name));
    namespacesLeft = (await durableObjectNamespaces(creds, name)).length;
    return scriptGone && namespacesLeft === 0;
  }).catch(() => undefined);
  return { scriptGone, namespacesLeft };
}

async function main(): Promise<number> {
  selfTestNeedleScan();
  const { name, report, keepCapture } = scanOptions(process.argv.slice(2));
  const creds = credentialsFromEnv();
  redact = (text) => redactAccount(text, creds);
  if (await scriptExists(creds, name)) throw new Error('a Worker with the lab name already exists; pick another --name');
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim();
  const dirty = execFileSync('git', ['status', '--porcelain', '--', 'src', 'wrangler.jsonc', 'public', 'scripts/platform-log-scan', '../packages/protocol'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim() !== '';
  const subdomain = await workersDevSubdomain(creds);
  redact = (text) => redactAccount(text, creds, subdomain);
  const origin = `https://${name}.${subdomain}.workers.dev`;
  const priv = mkdtempSync(join(tmpdir(), 'akvault-logscan-'));
  const log = join(priv, 'wrangler.log');
  const needles = new NeedleSet();
  let tail: TailCapture | undefined;
  let deployed = false;
  let steps: StepResult[] = [];
  let requests = 0;
  let tailFetches = 0;
  let analyticsRequests = 0;
  const sources: Record<string, SourceResult> = {};
  let cleanup = { scriptGone: false, namespacesLeft: -1 };
  const problems: string[] = [];
  const cleanupProblems: string[] = [];
  const settings = labObservability();

  // Runs once, from `finally` or from a signal handler, whichever comes first.
  let cleaning: Promise<void> | undefined;
  const cleanUp = () =>
    (cleaning ??= (async () => {
      await stopTail(tail).catch((err: Error) => cleanupProblems.push(`tail did not stop cleanly: ${redact(err.message)}`));
      tail = undefined;
      if (deployed) {
        say('deleting the lab Worker');
        cleanup = await deleteLab(creds, name, priv, log).catch((err: Error) => {
          cleanupProblems.push(`lab deletion failed: ${redact(err.message)}`);
          return cleanup;
        });
        if (!cleanup.scriptGone) cleanupProblems.push(`the lab Worker ${name} still exists: delete it by hand`);
        if (cleanup.namespacesLeft !== 0) cleanupProblems.push(`lab Durable Object namespaces not confirmed gone (${cleanup.namespacesLeft})`);
      }
      rmSync(priv, { recursive: true, force: true });
      for (const p of cleanupProblems) say(`cleanup problem: ${p}`);
    })());
  cleanupOnInterrupt = cleanUp;

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
    await wrangler(['deploy', '--config', config.path, '--secrets-file', secretsFile], priv, log, redact);
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
    await stopTail(tail);
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
    const telemetry = await pullTelemetry(creds, name, from, to, client.requests);
    const analytics = await pullAnalytics(creds, name, from, to, client.requests);
    analyticsRequests = analytics.requests;

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
    await cleanUp();
  }

  const ok = concludeScan(
    {
      commit,
      dirty,
      lab: name,
      observability: { production: settings.production, scanned: settings.lab },
      needleForms: needles.formCounts(),
      steps: { total: steps.length, unexpected: steps.filter((s) => s.expected !== s.got).length },
      trafficRequests: requests,
      tailFetchEvents: tailFetches,
      analyticsRequests,
      sources,
      cleanup,
      problems,
      cleanupProblems,
    },
    report,
  );
  return ok ? 0 : 1;
}

// An interrupted or crashed run still deletes the lab; a second signal exits at once.
const abort = (why: string, code: number) => {
  process.stderr.write(`platform log scan stopped (${why}); cleaning up\n`);
  void (cleanupOnInterrupt?.() ?? Promise.resolve()).finally(() => process.exit(code));
};
process.once('SIGINT', () => abort('SIGINT', 130));
process.once('SIGTERM', () => abort('SIGTERM', 143));
process.once('uncaughtException', (err) => abort(`uncaught ${err.name}`, 2));

main().then(
  (code) => process.exit(code),
  (err: Error) => {
    process.stderr.write(`platform log scan failed: ${redact(err.message)}\n`);
    process.exit(2);
  },
);
