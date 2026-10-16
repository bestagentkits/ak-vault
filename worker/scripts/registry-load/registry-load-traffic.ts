/**
 * Traffic of the revocation registry ramp test against a lab Worker:
 *
 * - `seedRegistry` fills the registry through the signed revocation webhook (the
 *   only write path), batches of 100 sids, 100 dids and 100 per-`sub` minimum `iat`s.
 *   The seeded subs' minimum `iat` lies a day ahead, so every token for them is
 *   "too old".
 * - `runStep` drives an open-loop constant arrival rate: request i leaves at
 *   start + i / rate whether or not earlier ones answered, so a slow registry
 *   shows up as latency and 503s instead of silently lowering the rate. The
 *   schedule is spread over child processes (registry-load-generator.ts). Each
 *   request carries a fresh token for a seeded sub with a random sid and did, so
 *   the registry runs all three lookups (sid miss, did miss, `min_iat` hit) and
 *   the Worker refuses it with 401 before any vault object is touched.
 *
 * Nothing here prints a token, secret or synthetic identifier.
 */
import { fork, type ChildProcess } from 'node:child_process';
import { availableParallelism } from 'node:os';
import { fileURLToPath } from 'node:url';
import { randomId, utf8Encode } from '@ak-vault/protocol';
import { webhookSignature, type LabClient, type LabIssuer } from '../platform-log-scan/lab-client.js';
import { SEED_BATCH, type Sample } from './registry-load-analysis.js';
import type { GeneratorResult, GeneratorTask } from './registry-load-generator.js';

const REQUEST_TIMEOUT_MS = 15_000;
const SEED_ATTEMPTS = 5;
const GENERATOR = fileURLToPath(new URL('./registry-load-generator.ts', import.meta.url));

export interface SeedResult {
  /** Subs whose tokens the registry refuses through `min_iat`. */
  revokedSubs: string[];
  webhooks: number;
  statuses: Record<string, number>;
}

export async function seedRegistry(client: LabClient, webhookSecret: string, entries: number, say: (line: string) => void): Promise<SeedResult> {
  const revokedSubs: string[] = [];
  const statuses: Record<string, number> = {};
  const futureIat = Math.floor(Date.now() / 1000) + 86_400;
  const batches = Math.ceil(entries / SEED_BATCH);
  for (let b = 0; b < batches; b++) {
    const size = Math.min(SEED_BATCH, entries - b * SEED_BATCH);
    const subs = Array.from({ length: size }, () => `acct-${randomId()}`);
    revokedSubs.push(...subs);
    const body = utf8Encode(
      JSON.stringify({
        v: 1,
        event_id: randomId(),
        revoke_sids: Array.from({ length: size }, () => `sid-${randomId()}`),
        revoke_dids: Array.from({ length: size }, () => randomId()),
        min_iat: subs.map((sub) => ({ sub, iat: futureIat })),
      }),
    );
    // Right after a deploy some edges may not route the new workers.dev name yet
    // (404). Resend the same batch with a fresh signature; a 409 on a resend means an
    // earlier attempt was applied, as ak-web treats it.
    let status = 0;
    for (let attempt = 1; attempt <= SEED_ATTEMPTS; attempt++) {
      const ts = String(Math.floor(Date.now() / 1000));
      const res = await client.raw('/internal/v1/revocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'AKV-Webhook-Timestamp': ts, 'AKV-Webhook-Signature': await webhookSignature(webhookSecret, ts, body) },
        body,
      });
      status = res.status === 409 && attempt > 1 ? 200 : res.status;
      if (status === 200 || attempt === SEED_ATTEMPTS) break;
      await new Promise((r) => setTimeout(r, 2_000 * attempt));
    }
    statuses[String(status)] = (statuses[String(status)] ?? 0) + 1;
    if ((b + 1) % 20 === 0 || b + 1 === batches) say(`  seeded ${b + 1}/${batches} webhook batches, statuses ${JSON.stringify(statuses)}`);
  }
  return { revokedSubs, webhooks: batches, statuses };
}

/** Requests a second one generator process is given; a step forks ceil(rate / this) of them. */
const RATE_PER_GENERATOR = 100;

/** Spawn one generator child, hand it its share of the schedule, collect its samples. */
function forkGenerator(task: GeneratorTask): { done: Promise<GeneratorResult>; child: ChildProcess } {
  // The children need no Cloudflare credentials: drop them from their environment.
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('CLOUDFLARE_')));
  const child = fork(GENERATOR, [], { execArgv: ['--import', 'tsx'], env, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  const done = new Promise<GeneratorResult>((resolvePromise, reject) => {
    let result: GeneratorResult | undefined;
    child.once('message', (m) => (result = m as GeneratorResult));
    child.once('error', (err) => reject(new Error(`load generator could not start: ${err.name}`)));
    child.once('exit', (code) => (result && code === 0 ? resolvePromise(result) : reject(new Error(`load generator exited with ${code}`))));
  });
  child.send(task);
  return { done, child };
}

/**
 * Send `rate` requests a second for `seconds`, open loop, starting at epoch ms
 * `startAt` (at least a few seconds ahead, so the children are loaded). The
 * schedule is interleaved over several child processes; resolves when every
 * request has answered or timed out.
 */
export async function runStep(
  origin: string,
  issuer: LabIssuer,
  subs: readonly string[],
  rate: number,
  seconds: number,
  startAt: number,
  colos: Map<string, number>,
): Promise<{ planned: number; generators: number; samples: Sample[] }> {
  const planned = rate * seconds;
  const generators = Math.min(Math.ceil(rate / RATE_PER_GENERATOR), Math.max(1, availableParallelism() - 1));
  const jwk = await issuer.privateJwk();
  const forks = Array.from({ length: generators }, (_, index) =>
    forkGenerator({ origin, issuer: issuer.issuer, audience: issuer.audience, kid: issuer.kid, jwk, subs: [...subs], rate, seconds, index, stride: generators, startAt, timeoutMs: REQUEST_TIMEOUT_MS }),
  );
  liveGenerators.push(...forks.map((f) => f.child));
  try {
    const results = await Promise.all(forks.map((f) => f.done));
    const samples: Sample[] = [];
    for (const r of results) {
      for (const [status, latencyMs, lagMs, timedOut] of r.samples) samples.push({ status, latencyMs, lagMs, timedOut: timedOut === 1 });
      for (const [colo, count] of Object.entries(r.colos)) colos.set(colo, (colos.get(colo) ?? 0) + count);
    }
    return { planned, generators, samples };
  } finally {
    stopGenerators();
  }
}

const liveGenerators: ChildProcess[] = [];

/** Kill every generator child still running (a failed step or an interrupt). */
export function stopGenerators(): void {
  for (const child of liveGenerators.splice(0)) if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
}
