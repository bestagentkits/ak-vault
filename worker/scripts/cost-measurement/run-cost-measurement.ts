/**
 * Cost measurement on a lab Worker built from the STAGING configuration. See README.md here.
 *
 *   CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… \
 *     tsx scripts/cost-measurement/run-cost-measurement.ts [--name ak-vault-lab-cost-…] [--report FILE] [--baseline-only] [--baseline-hours N]
 *
 * 1. Reads the staging Worker's own analytics for the last N hours (read-only; the
 *    staging baseline). With --baseline-only it stops here.
 * 2. Deploys a throwaway lab Worker from this checkout with the staging environment
 *    of wrangler.jsonc (same entry, compatibility date, observability, Durable
 *    Object classes and migrations); only the name (workers.dev, no route), the
 *    issuer (a synthetic one, inline JWKS, key in this process only) and the
 *    webhook secret (random per run) differ.
 * 3. Runs the phased synthetic workload (cost-workload.ts), waits for analytics
 *    ingestion, and reads Worker and Durable Object usage per phase.
 * 4. Deletes the lab and checks that it and its Durable Object namespaces are gone,
 *    also when the run fails or is interrupted.
 *
 * Output and the optional JSON report hold aggregates only: never a credential,
 * account identifier, namespace ID, vault ID or synthetic value.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { b64encode, randomBytes } from '@ak-vault/protocol';
import { unstable_readConfig } from 'wrangler';
import { credentialsFromEnv, redactAccount, scriptExists, workersDevSubdomain, type CloudflareCredentials } from '../platform-log-scan/cloudflare-api.js';
import { LabClient, LabIssuer } from '../platform-log-scan/lab-client.js';
import { LAB_NAME_PATTERN, WORKER_DIR, deleteLab, stopAllWrangler, wrangler } from '../platform-log-scan/lab-worker-lifecycle.js';
import { NeedleSet } from '../platform-log-scan/needle-scan.js';
import { outsideRepository } from '../platform-log-scan/scan-options.js';
import { sleep, waitFor } from '../platform-log-scan/telemetry-polling.js';
import { namespaceIds, storedBytes, windowUsage, type WindowUsage } from './cost-analytics.js';
import { phaseWindows } from './cost-projection.js';
import { DEFAULT_SHAPE, runCostWorkload, type PhaseRecord } from './cost-workload.js';

const STAGING_SCRIPT = 'ak-vault-staging';
const say = (line: string) => process.stdout.write(`${line}\n`);

let redact = (text: string) => text;
let cleanupOnInterrupt: (() => Promise<unknown>) | undefined;
let interrupted = false;
/** True once the cleanup confirmed the lab and its namespaces are gone. */
let labGone = () => false;

interface Options {
  name: string;
  report?: string;
  baselineOnly: boolean;
  baselineHours: number;
}

function options(rawArgv: string[]): Options {
  const argv = rawArgv[0] === '--' ? rawArgv.slice(1) : rawArgv;
  const stamp = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Saigon', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
    .format(new Date())
    .replace(/[^0-9]/g, '');
  const out: Options = { name: `ak-vault-lab-cost-${stamp}`, baselineOnly: false, baselineHours: 24 };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--name') out.name = argv[++i] ?? '';
    else if (arg === '--report') out.report = outsideRepository(argv[++i] ?? '', '--report');
    else if (arg === '--baseline-only') out.baselineOnly = true;
    else if (arg === '--baseline-hours') out.baselineHours = Number(argv[++i]);
    else throw new Error(`unknown argument ${arg}`);
  }
  if (!LAB_NAME_PATTERN.test(out.name)) throw new Error(`lab name must match ${LAB_NAME_PATTERN}`);
  if (!Number.isInteger(out.baselineHours) || out.baselineHours < 1 || out.baselineHours > 24 * 30) throw new Error('--baseline-hours must be an integer from 1 to 720');
  return out;
}

/** Lab config: the staging environment of wrangler.jsonc with only name, routing, issuer and secrets changed. */
function writeLabConfig(dir: string, name: string, vars: { issuer: string; audience: string; jwks: string }): string {
  const staging = unstable_readConfig({ config: join(WORKER_DIR, 'wrangler.jsonc'), env: 'staging' }, {});
  if (staging.name !== STAGING_SCRIPT) throw new Error('wrangler.jsonc staging environment not found');
  if (!staging.main || !staging.migrations?.length || !staging.durable_objects.bindings.length) throw new Error('staging config lacks its entry, migrations or Durable Object bindings');
  // The JWKS URL would be ignored next to the inline JWKS; leave it out so the lab trusts only the synthetic issuer.
  const { VAULT_JWKS_URL: _unused, ...stagingVars } = staging.vars as Record<string, unknown>;
  const config = {
    name,
    main: staging.main,
    compatibility_date: staging.compatibility_date,
    compatibility_flags: staging.compatibility_flags,
    workers_dev: true,
    preview_urls: false,
    observability: staging.observability,
    assets: { ...staging.assets, directory: join(WORKER_DIR, 'public') },
    durable_objects: { bindings: staging.durable_objects.bindings.map((b: { name: string; class_name: string }) => ({ name: b.name, class_name: b.class_name })) },
    migrations: staging.migrations,
    vars: { ...stagingVars, VAULT_ISSUER: vars.issuer, VAULT_AUDIENCE: vars.audience, VAULT_JWKS_JSON: vars.jwks },
  };
  const path = join(dir, 'wrangler.cost-lab.json');
  writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
  return path;
}

const n = (x: number, digits = 2) => (Number.isFinite(x) ? x.toFixed(digits) : 'n/a');

function printUsage(label: string, u: WindowUsage): void {
  const w = u.worker;
  say(`  ${label}: worker ${w.requests} req, ${w.errors} err, cpu ${n(w.cpuTimeUs / 1000, 1)} ms total (p50 ${n(w.cpuP50Us / 1000)} ms, p99 ${n(w.cpuP99Us / 1000)} ms), wall p50 ${n(w.wallP50Us / 1000, 1)} ms`);
  for (const [l, o] of Object.entries(u.objects)) {
    say(`    ${l}: ${o.requests} req, ${o.errors} err, wall p50 ${n(o.wallP50Us / 1000, 1)} ms p99 ${n(o.wallP99Us / 1000, 1)} ms, active ${n(o.activeTimeUs / 1e6)} s, duration ${n(o.durationGbS, 3)} GB-s, rows read ${o.rowsRead}, written ${o.rowsWritten}`);
  }
}

async function stagingBaseline(creds: CloudflareCredentials, hours: number): Promise<{ hours: number; usage: WindowUsage; storedBytes: Record<string, number> }> {
  const ns = await namespaceIds(creds, STAGING_SCRIPT);
  const to = Math.floor(Date.now() / 60_000) * 60_000;
  const from = to - hours * 3_600_000;
  const usage = await windowUsage(creds, STAGING_SCRIPT, ns, from, to);
  const bytes = await storedBytes(creds, ns, from, to);
  say(`staging baseline, last ${hours} h (read-only):`);
  printUsage('staging', usage);
  say(`    stored bytes: vault ${bytes.vault}, registry ${bytes.registry}`);
  return { hours, usage, storedBytes: bytes };
}

interface PhaseResult extends PhaseRecord {
  window: { from: string; to: string };
  usage: WindowUsage;
}

async function main(): Promise<number> {
  const opts = options(process.argv.slice(2));
  const creds = credentialsFromEnv();
  redact = (text) => redactAccount(text, creds);
  const baseline = await stagingBaseline(creds, opts.baselineHours);
  if (opts.baselineOnly) {
    if (opts.report) writeFileSync(opts.report, JSON.stringify({ baseline }, null, 2), { mode: 0o600 });
    return 0;
  }

  if (await scriptExists(creds, opts.name)) throw new Error('a Worker with the lab name already exists; pick another --name');
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim();
  const dirty = execFileSync('git', ['status', '--porcelain', '--', 'src', 'wrangler.jsonc', 'public', '../packages/protocol'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim() !== '';
  const subdomain = await workersDevSubdomain(creds);
  redact = (text) => redactAccount(text, creds, subdomain);
  const origin = `https://${opts.name}.${subdomain}.workers.dev`;
  const problems: string[] = [];
  let priv: string | undefined;
  let deployed = false;
  let cleanup = { scriptGone: false, namespacesLeft: -1 };
  let phases: PhaseResult[] = [];
  let runStored: Record<string, number> = {};
  let vaults = 0;

  let cleaning: Promise<void> | undefined;
  const cleanUp = () =>
    (cleaning ??= (async () => {
      await stopAllWrangler();
      if (deployed && priv) {
        say('deleting the lab Worker');
        cleanup = await deleteLab(creds, opts.name, priv, join(priv, 'wrangler.log'), redact).catch((err: Error) => {
          problems.push(`lab deletion failed: ${redact(err.message)}`);
          return cleanup;
        });
        if (!cleanup.scriptGone) problems.push(`the lab Worker ${opts.name} still exists: delete it by hand`);
        if (cleanup.namespacesLeft !== 0) problems.push(`lab Durable Object namespaces not confirmed gone (${cleanup.namespacesLeft})`);
      }
      if (priv) rmSync(priv, { recursive: true, force: true });
    })());
  cleanupOnInterrupt = cleanUp;
  labGone = () => cleanup.scriptGone && cleanup.namespacesLeft === 0;
  priv = mkdtempSync(join(tmpdir(), 'akvault-cost-'));
  const log = join(priv, 'wrangler.log');
  say(`lab ${opts.name} at ${commit}${dirty ? ' (uncommitted changes)' : ''}, staging configuration`);
  try {
    const needles = new NeedleSet();
    const issuer = await LabIssuer.create('https://cost-issuer.ak-vault.invalid', origin, needles);
    const webhookSecret = b64encode(randomBytes(32));
    const secretsFile = join(priv, 'lab.secrets.json');
    writeFileSync(secretsFile, JSON.stringify({ REVOCATION_WEBHOOK_SECRET: webhookSecret }), { mode: 0o600 });
    const config = writeLabConfig(priv, opts.name, { issuer: issuer.issuer, audience: origin, jwks: issuer.publicJwks });
    if (interrupted) throw new Error('interrupted');
    say('deploying the lab Worker');
    deployed = true;
    await wrangler(['deploy', '--config', config, '--secrets-file', secretsFile], priv, log, redact);
    rmSync(secretsFile);
    await waitFor('the lab Worker', 180_000, 3_000, async () => {
      const res = await fetch(`${origin}/v1/meta`, { signal: AbortSignal.timeout(10_000) });
      return res.status === 200 && ((await res.json()) as { sync_enabled?: unknown }).sync_enabled === true;
    });
    const ns = await namespaceIds(creds, opts.name);

    const client = new LabClient(origin, issuer, needles);
    const workload = await runCostWorkload(client, needles, webhookSecret, DEFAULT_SHAPE, say);
    vaults = workload.vaults;
    for (const p of workload.phases) if (p.unexpected > 0) problems.push(`phase ${p.name}: ${p.unexpected} unexpected status(es)`);

    const windows = phaseWindows(workload.phases);
    const runFrom = windows[0]!.from;
    const runTo = windows.at(-1)!.to;
    await sleep(Math.max(0, runTo - Date.now()));
    say('waiting for analytics ingestion (minutes)');
    let lastRows = -1;
    await waitFor('analytics ingestion', 20 * 60_000, 60_000, async () => {
      const u = await windowUsage(creds, opts.name, ns, runFrom, runTo);
      const rows = u.objects.vault.rowsWritten + u.objects.registry.rowsWritten;
      say(`  worker ${u.worker.requests}/${workload.requests} requests, rows written ${rows}`);
      const settled = u.worker.requests >= 0.9 * workload.requests && rows > 0 && rows === lastRows;
      lastRows = rows;
      return settled;
    });
    phases = [];
    for (const [i, p] of workload.phases.entries()) {
      const w = windows[i]!;
      const usage = await windowUsage(creds, opts.name, ns, w.from, w.to);
      phases.push({ ...p, window: { from: new Date(w.from).toISOString(), to: new Date(w.to).toISOString() }, usage });
    }
    // Steady-state polling: the pull phase after the proof jti TTL (120 s) plus a minute, once expired jtis are deleted at the insert rate.
    const pull = workload.phases.find((p) => p.name === 'pull')!;
    const pullWindow = windows[workload.phases.indexOf(pull)]!;
    const steadyFrom = pullWindow.from + 3 * 60_000;
    const steadyUsage = await windowUsage(creds, opts.name, ns, steadyFrom, pullWindow.to);
    runStored = await storedBytes(creds, ns, runFrom, runTo);

    say('per-phase usage:');
    for (const p of phases) printUsage(`${p.name} (${p.operations} ops, ${p.requests} requests)`, p.usage);
    printUsage(`pull steady state from ${new Date(steadyFrom).toISOString()}`, steadyUsage);
    say(`  stored bytes after the run: vault ${runStored['vault']}, registry ${runStored['registry']} (${vaults} vaults)`);
    if (opts.report) {
      writeFileSync(
        opts.report,
        JSON.stringify({ commit, dirty, configuration: 'staging', baseline, shape: DEFAULT_SHAPE, vaults, phases, pullSteadyState: { from: new Date(steadyFrom).toISOString(), to: new Date(pullWindow.to).toISOString(), usage: steadyUsage }, storedBytes: runStored, problems }, null, 2),
        { mode: 0o600 },
      );
    }
  } finally {
    await cleanUp();
  }
  if (interrupted) problems.push('the run was interrupted');
  for (const p of problems) say(`problem: ${p}`);
  say(`lab deleted: ${cleanup.scriptGone && cleanup.namespacesLeft === 0 ? 'yes' : 'NO'}`);
  return problems.length === 0 ? 0 : 1;
}

const abort = (why: string, code: number) => {
  if (interrupted) process.exit(code);
  interrupted = true;
  process.stderr.write(`cost measurement stopped (${redact(why)}); cleaning up\n`);
  void (cleanupOnInterrupt?.() ?? Promise.resolve()).finally(() => process.exit(code));
};
process.on('SIGINT', () => abort('SIGINT', 130));
process.on('SIGTERM', () => abort('SIGTERM', 143));
process.on('uncaughtException', (err) => abort(`uncaught ${err.name}: ${err.message}`, 2));

main().then(
  (code) => process.exit(code),
  async (err: Error) => {
    process.stderr.write(`cost measurement failed: ${redact(err.message)}\n`);
    // `main` cleaned up in its `finally`; report whether the lab is gone.
    await (cleanupOnInterrupt?.() ?? Promise.resolve());
    process.stderr.write(`lab deleted: ${labGone() ? 'yes' : 'NO, or never deployed'}\n`);
    process.exit(2);
  },
);
