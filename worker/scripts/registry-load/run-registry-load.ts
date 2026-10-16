/**
 * Revocation registry ramp test on a lab Worker built from the STAGING configuration. See README.md here.
 *
 *   CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=… \
 *     tsx scripts/registry-load/run-registry-load.ts [--name ak-vault-lab-…] [--report FILE] [--rates 5,10,…] [--step-seconds N] [--seed N] [--estimate-only]
 *
 * 1. Estimates the worst-case cost and refuses to run above COST_CAP_USD.
 * 2. Deploys a throwaway lab Worker (staging config, synthetic issuer, random webhook secret).
 * 3. Seeds the registry through the signed webhook, checks one control request
 *    gets past the registry and one refused-shape request is refused 401.
 * 4. Steps an open-loop arrival rate (spread over generator child processes),
 *    each step from a whole minute, and records client p50/p99 latency, the 503
 *    rate and requests without an answer per step; stops early past the knee.
 * 5. Reads Worker and Durable Object analytics per step minute (registry wall
 *    time, CPU and active time) and applies the knee rule.
 * 6. Deletes the lab and checks that it and its Durable Object namespaces are
 *    gone, also when the run fails or is interrupted.
 *
 * Output and report hold aggregates only: never a credential, account identifier,
 * namespace ID or synthetic value.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { b64encode, randomBytes, randomId } from '@ak-vault/protocol';
import { credentialsFromEnv, redactAccount, scriptExists, workersDevSubdomain } from '../platform-log-scan/cloudflare-api.js';
import { LabClient, LabIssuer, labDevice } from '../platform-log-scan/lab-client.js';
import { LAB_NAME_PATTERN, WORKER_DIR, deleteLab, stopAllWrangler, wrangler } from '../platform-log-scan/lab-worker-lifecycle.js';
import { NeedleSet } from '../platform-log-scan/needle-scan.js';
import { outsideRepository, saigonStamp } from '../platform-log-scan/scan-options.js';
import { sleep, waitFor } from '../platform-log-scan/telemetry-polling.js';
import { namespaceIds, windowUsage, type WindowUsage } from '../cost-measurement/cost-analytics.js';
import { writeStagingLabConfig } from '../cost-measurement/staging-lab-config.js';
import {
  COST_CAP_USD,
  DEFAULT_RATES,
  DEFAULT_SEED_ENTRIES,
  DEFAULT_STEP_SECONDS,
  KNEE_P99_FACTOR,
  estimateCost,
  findKnee,
  parseRates,
  summarizeStep,
  type Sample,
  type StepSummary,
} from './registry-load-analysis.js';
import { runStep, seedRegistry, stopGenerators } from './registry-load-traffic.js';

const MINUTE = 60_000;
/** Generator children need a few seconds to load before a step's first request. */
const GENERATOR_LEAD_MS = 5_000;
/** Stop stepping up once a step is this far past the knee: more load only adds cost. */
const STOP_FAILED_SHARE = 0.05;
const STOP_P99_FACTOR = 10;
const say = (line: string) => process.stdout.write(`${line}\n`);

let redact = (text: string) => text;
let cleanupOnInterrupt: (() => Promise<unknown>) | undefined;
let interrupted = false;

interface Options {
  name: string;
  report?: string;
  rates: number[];
  stepSeconds: number;
  seed: number;
  estimateOnly: boolean;
}

function options(rawArgv: string[]): Options {
  const argv = rawArgv[0] === '--' ? rawArgv.slice(1) : rawArgv;
  const out: Options = { name: `ak-vault-lab-regload-${saigonStamp()}`, rates: [...DEFAULT_RATES], stepSeconds: DEFAULT_STEP_SECONDS, seed: DEFAULT_SEED_ENTRIES, estimateOnly: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--name') out.name = argv[++i] ?? '';
    else if (arg === '--report') {
      out.report = outsideRepository(argv[++i] ?? '', '--report');
      if (!existsSync(dirname(out.report))) throw new Error('--report directory does not exist');
    } else if (arg === '--rates') out.rates = parseRates(argv[++i] ?? '');
    else if (arg === '--step-seconds') out.stepSeconds = Number(argv[++i]);
    else if (arg === '--seed') out.seed = Number(argv[++i]);
    else if (arg === '--estimate-only') out.estimateOnly = true;
    else throw new Error(`unknown argument ${arg}`);
  }
  if (!LAB_NAME_PATTERN.test(out.name)) throw new Error(`lab name must match ${LAB_NAME_PATTERN}`);
  // A step must fit inside one whole minute with room for its slowest answers.
  if (!Number.isInteger(out.stepSeconds) || out.stepSeconds < 10 || out.stepSeconds > 55) throw new Error('--step-seconds must be an integer from 10 to 55');
  if (!Number.isInteger(out.seed) || out.seed < 100 || out.seed > 100_000) throw new Error('--seed must be an integer from 100 to 100000');
  return out;
}

const n = (x: number, digits = 1) => (Number.isFinite(x) ? x.toFixed(digits) : 'n/a');

interface StepResult extends StepSummary {
  /** Generator processes the step's schedule was spread over. */
  generators: number;
  window: { from: string; to: string };
  usage?: WindowUsage;
}

function printStep(s: StepResult): void {
  say(`  ${s.rate}/s: sent ${s.sent}/${s.planned} from ${s.generators} process(es), statuses ${JSON.stringify(s.statuses)} (0 = no answer, ${s.timeouts} of them timeouts), p50 ${n(s.p50Ms)} ms, p99 ${n(s.p99Ms)} ms, max ${n(s.maxMs)} ms, generator lag p99 ${n(s.lagP99Ms)} ms`);
  if (!s.usage) return;
  const r = s.usage.objects.registry;
  const v = s.usage.objects.vault;
  // Per check: rows read are exact (periodic dataset, one row per check); invocation counts are sampled.
  const per = (x: number) => (r.rowsRead > 0 ? x / r.rowsRead : Number.NaN);
  say(
    `    worker ${s.usage.worker.requests} req (wall p50 ${n(s.usage.worker.wallP50Us / 1000)} ms); registry ${r.requests} req, ${r.errors} err, wall p50 ${n(r.wallP50Us / 1000)} ms p99 ${n(r.wallP99Us / 1000)} ms, cpu ${n(per(r.cpuTimeUs) / 1000, 2)} ms/check, active ${n(r.activeTimeUs / 1e6)} s, rows read ${r.rowsRead}; vault ${v.requests} req`,
  );
}

async function main(): Promise<number> {
  const opts = options(process.argv.slice(2));
  const estimate = estimateCost({ rates: opts.rates, stepSeconds: opts.stepSeconds, seedEntries: opts.seed });
  say(`plan: rates ${opts.rates.join(', ')}/s, ${opts.stepSeconds} s each, ${estimate.rampRequests} ramp requests, ${estimate.seedWebhooks} seed webhooks; worst-case cost $${estimate.usd.toFixed(3)} (cap $${COST_CAP_USD})`);
  if (estimate.usd > COST_CAP_USD) throw new Error(`estimated cost exceeds the $${COST_CAP_USD} cap; lower --rates, --step-seconds or --seed`);
  if (opts.estimateOnly) return 0;

  const creds = credentialsFromEnv();
  redact = (text) => redactAccount(text, creds);
  if (await scriptExists(creds, opts.name)) throw new Error('a Worker with the lab name already exists; pick another --name');
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: WORKER_DIR, encoding: 'utf8' }).trim();
  const changed = (...paths: string[]) => execFileSync('git', ['status', '--porcelain', '--', ...paths], { cwd: WORKER_DIR, encoding: 'utf8' }).trim() !== '';
  const dirty = changed('src', 'wrangler.jsonc', 'public', '../packages/protocol');
  const harnessDirty = changed('scripts/registry-load', 'scripts/cost-measurement', 'scripts/platform-log-scan');
  const subdomain = await workersDevSubdomain(creds);
  redact = (text) => redactAccount(text, creds, subdomain);
  const origin = `https://${opts.name}.${subdomain}.workers.dev`;
  const problems: string[] = [];
  let priv: string | undefined;
  let deployed = false;
  let cleanup = { scriptGone: false, namespacesLeft: -1 };
  const report: Record<string, unknown> = { commit, dirty, harnessDirty, configuration: 'staging', plan: { rates: opts.rates, stepSeconds: opts.stepSeconds, seedEntries: opts.seed }, estimate };
  const writeReport = (): boolean => {
    if (!opts.report) return true;
    try {
      writeFileSync(opts.report, JSON.stringify(report, null, 2), { mode: 0o600 });
      return true;
    } catch (err) {
      say(`problem: the report could not be written (${(err as Error).name})`);
      return false;
    }
  };

  let cleaning: Promise<void> | undefined;
  const cleanUp = () =>
    (cleaning ??= (async () => {
      stopGenerators();
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
      if (interrupted) problems.push('the run was interrupted');
      const labDeleted = !deployed || (cleanup.scriptGone && cleanup.namespacesLeft === 0);
      report['labDeleted'] = labDeleted;
      report['problems'] = problems;
      for (const p of problems) say(`problem: ${p}`);
      say(`lab deleted: ${deployed ? (labDeleted ? 'yes' : 'NO') : 'never deployed'}`);
      if (!writeReport()) problems.push('the report could not be written');
    })());
  cleanupOnInterrupt = cleanUp;
  priv = mkdtempSync(join(tmpdir(), 'akvault-regload-'));
  const log = join(priv, 'wrangler.log');
  say(`lab ${opts.name} at ${commit}${dirty ? ' (uncommitted Worker changes)' : ''}${harnessDirty ? ' (uncommitted harness changes)' : ''}, staging configuration`);
  try {
    const needles = new NeedleSet();
    const issuer = await LabIssuer.create('https://regload-issuer.ak-vault.invalid', origin, needles);
    const webhookSecret = b64encode(randomBytes(32));
    const secretsFile = join(priv, 'lab.secrets.json');
    writeFileSync(secretsFile, JSON.stringify({ REVOCATION_WEBHOOK_SECRET: webhookSecret }), { mode: 0o600 });
    const config = writeStagingLabConfig(priv, opts.name, { issuer: issuer.issuer, audience: origin, jwks: issuer.publicJwks });
    if (interrupted) throw new Error('interrupted');
    say('deploying the lab Worker');
    deployed = true;
    await wrangler(['deploy', '--config', config, '--secrets-file', secretsFile], priv, log, redact);
    rmSync(secretsFile);
    // Ready once 10 consecutive probes succeed: a new workers.dev name reaches edges one by one.
    let ready = 0;
    await waitFor('the lab Worker', 180_000, 1_000, async () => {
      const res = await fetch(`${origin}/v1/meta`, { signal: AbortSignal.timeout(10_000) });
      const ok = res.status === 200 && ((await res.json()) as { sync_enabled?: unknown }).sync_enabled === true;
      ready = ok ? ready + 1 : 0;
      return ready >= 10;
    });
    const ns = await namespaceIds(creds, opts.name);
    const client = new LabClient(origin, issuer, needles);

    say(`seeding the registry with ${opts.seed} sids, dids and subs`);
    const seed = await seedRegistry(client, webhookSecret, opts.seed, say);
    report['seed'] = { webhooks: seed.webhooks, statuses: seed.statuses };
    if (seed.statuses['200'] !== seed.webhooks) throw new Error(`seeding failed: statuses ${JSON.stringify(seed.statuses)}`);

    // Control: an unrevoked, properly proven device gets past the registry (any answer
    // but 401/503), so the ramp's 401s come from the registry, not from token checks.
    const control = await client.call(labDevice('control', `acct-${randomId()}`, needles), 'GET', `/v1/vaults/${randomId()}/changes`);
    // The refused-shape probe goes through a generator process, as the ramp does; a
    // probe without any answer (client network) is retried, an answer must be 401.
    let refused: Sample | undefined;
    for (let attempt = 1; attempt <= 3 && (!refused || refused.status === 0); attempt++) {
      refused = (await runStep(origin, issuer, seed.revokedSubs, 1, 1, Date.now() + GENERATOR_LEAD_MS, new Map())).samples[0];
      if (refused?.status === 0) say(`  refused-shape probe got no answer (${refused.timedOut ? 'timeout' : 'connection failure'}); retrying`);
    }
    report['controls'] = { unrevokedStatus: control.status, refusedStatus: refused?.status ?? null };
    say(`controls: unrevoked device ${control.status}, refused-shape request ${refused?.status}`);
    if (control.status === 401 || control.status === 503 || refused?.status !== 401) throw new Error('controls did not show a registry refusal; not ramping');

    const colos = new Map<string, number>();
    const steps: StepResult[] = [];
    for (const rate of opts.rates) {
      if (interrupted) break;
      // Each step sends from 2 s past a whole minute; its analytics window runs to the
      // first whole minute after its last answer, and the next step starts there.
      const minuteStart = Math.ceil((Date.now() + GENERATOR_LEAD_MS) / MINUTE) * MINUTE;
      const { planned, generators, samples } = await runStep(origin, issuer, seed.revokedSubs, rate, opts.stepSeconds, minuteStart + 2_000, colos);
      const windowEnd = Math.ceil(Date.now() / MINUTE) * MINUTE;
      const step: StepResult = { ...summarizeStep(rate, planned, samples), generators, window: { from: new Date(minuteStart).toISOString(), to: new Date(windowEnd).toISOString() } };
      steps.push(step);
      printStep(step);
      const unexpected = samples.length - (step.statuses['401'] ?? 0) - step.failed - step.networkFailures;
      if (unexpected > 0) problems.push(`${rate}/s: ${unexpected} answer(s) other than 401 or 503`);
      const baseline = steps[0]!.p99Ms;
      if ((step.failed + step.networkFailures) / Math.max(1, step.sent) > STOP_FAILED_SHARE || step.p99Ms > STOP_P99_FACTOR * baseline) {
        say(`  stopping the ramp: well past the knee at ${rate}/s`);
        break;
      }
    }
    report['edgeLocations'] = Object.fromEntries(colos);
    report['steps'] = steps;
    writeReport();

    if (steps.length > 0) {
      const runFrom = Date.parse(steps[0]!.window.from);
      const runTo = Date.parse(steps.at(-1)!.window.to);
      const sent = steps.reduce((s, x) => s + x.sent, 0);
      await sleep(Math.max(0, runTo - Date.now()));
      say('waiting for analytics ingestion (minutes)');
      let last = -1;
      // Settled when the registry's periodic usage stopped changing and its request count
      // caught up with the Worker's. Requests that never reached the Worker (client
      // network failures) keep the Worker count below what the client sent.
      await waitFor('analytics ingestion', 20 * MINUTE, MINUTE, async () => {
        const u = await windowUsage(creds, opts.name, ns, runFrom, runTo);
        const r = u.objects.registry;
        say(`  worker ${u.worker.requests}/${sent} requests, registry ${r.requests}, registry cpu ${n(r.cpuTimeUs / 1000)} ms`);
        const settled = u.worker.requests > 0 && r.requests >= 0.95 * u.worker.requests && r.cpuTimeUs > 0 && r.cpuTimeUs === last;
        last = r.cpuTimeUs;
        return settled;
      }).catch((err: Error) => problems.push(`analytics: ${err.message}`));
      say('per-step results:');
      for (const step of steps) {
        try {
          step.usage = await windowUsage(creds, opts.name, ns, Date.parse(step.window.from), Date.parse(step.window.to));
          if (step.usage.objects.registry.requests > 0) step.registryWallP99Ms = step.usage.objects.registry.wallP99Us / 1000;
        } catch (err) {
          problems.push(`analytics for ${step.rate}/s: ${redact((err as Error).message)}`);
        }
        printStep(step);
      }
    }
    const knee = findKnee(steps);
    report['knee'] = knee;
    say(`edge locations: ${JSON.stringify(Object.fromEntries(colos))}`);
    say(`knee rule: > 0.1% answered 503, unanswered share > the first step's + 1 point, or client or registry wall p99 > ${KNEE_P99_FACTOR} x the first step's`);
    say(knee.kneeRate === null ? `no knee: ${knee.reason}` : `knee at ${knee.kneeRate}/s (${knee.reason}); highest rate below it ${knee.sustainedRate ?? 'none'}/s`);
    if (!knee.generatorKeptUp) problems.push(`load generator: ${knee.reason}`);
  } finally {
    await cleanUp();
  }
  return problems.length === 0 ? 0 : 1;
}

/** Exit once stdout and stderr have flushed (they are asynchronous when piped). */
const exitAfterFlush = (code: number) => {
  process.exitCode = code;
  process.stdout.write('', () => process.stderr.write('', () => process.exit(code)));
};

const abort = (why: string, code: number) => {
  if (interrupted) process.exit(code);
  interrupted = true;
  process.stderr.write(`registry load test stopped (${redact(why)}); cleaning up\n`);
  void (cleanupOnInterrupt?.() ?? Promise.resolve()).finally(() => exitAfterFlush(code));
};
process.on('SIGINT', () => abort('SIGINT', 130));
process.on('SIGTERM', () => abort('SIGTERM', 143));
process.on('uncaughtException', (err) => abort(`uncaught ${err.name}: ${err.message}`, 2));

main().then(exitAfterFlush, (err: Error) => {
  process.stderr.write(`registry load test failed: ${redact(err.message)}\n`);
  exitAfterFlush(2);
});
