/**
 * Pure helpers of the revocation registry ramp test: the step plan, the cost
 * estimate checked before any traffic, client-side latency summaries and the knee
 * rule. No I/O, so `worker/test/registry-load-analysis.test.ts` pins them.
 */
import { PRICES } from '../cost-measurement/cost-projection.js';

/** Arrival rates (requests a second) stepped through by default. */
export const DEFAULT_RATES = [5, 10, 20, 40, 80, 160, 320, 400, 600, 800, 1000] as const;
/** Each step sends for this long inside its own whole minute, so per-minute analytics split by step. */
export const DEFAULT_STEP_SECONDS = 55;
/** Cloudflare documents about 1,000 requests a second as the soft limit of one Durable Object. */
export const MAX_RATE = 1000;
/** Revocation entries seeded per list before the ramp: sids, dids and per-`sub` minimum `iat`s. */
export const DEFAULT_SEED_ENTRIES = 10_000;
/** The webhook accepts at most 100 entries per list. */
export const SEED_BATCH = 100;
/** The run refuses to start when its worst-case cost estimate exceeds this many USD. */
export const COST_CAP_USD = 2;

/** Knee rule: client p99, or the registry's own wall p99 from analytics, above this multiple of the first step's ... */
export const KNEE_P99_FACTOR = 2;
/** ... or more than this share of requests answered 503 (the Worker failing closed on the registry) ... */
export const KNEE_ERROR_SHARE = 0.001;
/**
 * ... or the share that got no answer at all exceeds the first step's share by more
 * than this. The operator network loses some requests at any rate (0.4% to 1.8% at
 * 5 a second in the 2026-10-16 runs), so only the excess over that baseline counts.
 */
export const KNEE_NO_ANSWER_EXCESS = 0.01;
/** ... or the client sent less than this share of the planned requests (the generator, not the Worker, is the limit). */
export const MIN_ACHIEVED_SHARE = 0.9;
/** A step whose requests left this late (p99) against their schedule arrived in bursts, not at its rate. */
export const MAX_LAG_P99_MS = 1000;

export function parseRates(text: string): number[] {
  const rates = text.split(',').map((s) => Number(s.trim()));
  if (rates.length === 0 || rates.some((r) => !Number.isInteger(r) || r < 1 || r > MAX_RATE)) throw new Error(`--rates must be integers from 1 to ${MAX_RATE}, comma-separated`);
  for (let i = 1; i < rates.length; i++) if (rates[i]! <= rates[i - 1]!) throw new Error('--rates must increase');
  return rates;
}

export interface LoadPlan {
  rates: readonly number[];
  stepSeconds: number;
  seedEntries: number;
}

export interface CostEstimate {
  rampRequests: number;
  seedWebhooks: number;
  usd: number;
}

/**
 * Worst-case USD for the run, ignoring every included monthly amount. Upper bounds
 * per ramp request: 5 ms Worker CPU, one registry request with 1 s of billed
 * duration (in reality the one object's wall time is shared by concurrent requests)
 * and 3 rows read; per seeded entry 2 rows written (row + primary-key index).
 */
export function estimateCost(plan: LoadPlan): CostEstimate {
  const rampRequests = plan.rates.reduce((sum, r) => sum + r * plan.stepSeconds, 0);
  const seedWebhooks = Math.ceil(plan.seedEntries / SEED_BATCH);
  const requests = rampRequests + seedWebhooks + 10;
  const usd =
    (requests / 1e6) * PRICES.workerRequests.perMillion +
    ((requests * 5) / 1e6) * PRICES.workerCpuMs.perMillion +
    (requests / 1e6) * PRICES.doRequests.perMillion +
    ((requests * 0.125) / 1e6) * PRICES.doDurationGbS.perMillion +
    ((requests * 3) / 1e6) * PRICES.rowsRead.perMillion +
    ((plan.seedEntries * 3 * 2) / 1e6) * PRICES.rowsWritten.perMillion;
  return { rampRequests, seedWebhooks, usd };
}

/** Nearest-rank percentile of an ascending array; NaN when empty. */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1]!;
}

/** One request as the generator saw it. `status` 0 means a timeout or network failure. */
export interface Sample {
  status: number;
  latencyMs: number;
  /** How late the request left against its open-loop schedule. */
  lagMs: number;
  /** No answer within the client timeout (as opposed to a connection failure). */
  timedOut?: boolean;
}

export interface StepSummary {
  rate: number;
  planned: number;
  sent: number;
  statuses: Record<string, number>;
  /** Requests answered 503: the Worker could not reach the registry in time and failed closed. */
  failed: number;
  /**
   * Requests with no HTTP answer: a client timeout or a connection failure. Left
   * out of the latency percentiles (there is no answer to time); they count toward
   * the knee only above the first step's share plus KNEE_NO_ANSWER_EXCESS, since
   * the client network loses a few at any rate.
   */
  networkFailures: number;
  /** Of `networkFailures`, those that hit the client timeout. */
  timeouts: number;
  p50Ms: number;
  p99Ms: number;
  maxMs: number;
  lagP99Ms: number;
  /** Registry Durable Object wall p99 from analytics, once read; free of the client's network noise. */
  registryWallP99Ms?: number;
}

export function summarizeStep(rate: number, planned: number, samples: readonly Sample[]): StepSummary {
  const statuses: Record<string, number> = {};
  for (const s of samples) statuses[String(s.status)] = (statuses[String(s.status)] ?? 0) + 1;
  const latencies = samples.filter((s) => s.status !== 0).map((s) => s.latencyMs).sort((a, b) => a - b);
  const lags = samples.map((s) => s.lagMs).sort((a, b) => a - b);
  return {
    rate,
    planned,
    sent: samples.length,
    statuses,
    failed: statuses['503'] ?? 0,
    networkFailures: statuses['0'] ?? 0,
    timeouts: samples.filter((s) => s.status === 0 && s.timedOut).length,
    p50Ms: percentile(latencies, 50),
    p99Ms: percentile(latencies, 99),
    maxMs: latencies.at(-1) ?? Number.NaN,
    lagP99Ms: percentile(lags, 99),
  };
}

export interface KneeVerdict {
  /** Rate of the first step that met the knee rule; null when none did. */
  kneeRate: number | null;
  /** Highest step rate below the knee (or the last step when no knee). */
  sustainedRate: number | null;
  reason: string;
  /**
   * False when the generator could not keep its schedule: before any knee (later
   * steps prove nothing), or at the knee step itself (its requests arrived in bursts
   * above the step rate, so the knee lies between the previous step and this one).
   */
  generatorKeptUp: boolean;
}

const noAnswerShare = (step: StepSummary) => (step.sent > 0 ? step.networkFailures / step.sent : 0);

/** Why `step` counts as the knee against the first step `baseline`, or null. */
export function kneeReason(step: StepSummary, baseline: StepSummary): string | null {
  const baselineP99Ms = baseline.p99Ms;
  if (step.sent > 0 && step.failed / step.sent > KNEE_ERROR_SHARE) return `${step.failed} of ${step.sent} requests answered 503`;
  if (step !== baseline && noAnswerShare(step) > noAnswerShare(baseline) + KNEE_NO_ANSWER_EXCESS) {
    return `${step.networkFailures} of ${step.sent} requests got no answer (${step.timeouts} timed out), against ${(100 * noAnswerShare(baseline)).toFixed(1)}% in the first step`;
  }
  const wall = step.registryWallP99Ms;
  const baseWall = baseline.registryWallP99Ms;
  if (wall !== undefined && baseWall !== undefined && baseWall > 0 && wall > KNEE_P99_FACTOR * baseWall) {
    return `registry wall p99 ${wall.toFixed(0)} ms > ${KNEE_P99_FACTOR} x the first step's ${baseWall.toFixed(0)} ms`;
  }
  if (step.p99Ms > KNEE_P99_FACTOR * baselineP99Ms) return `p99 ${step.p99Ms.toFixed(0)} ms > ${KNEE_P99_FACTOR} x baseline ${baselineP99Ms.toFixed(0)} ms`;
  return null;
}

/** Apply the knee rule to the steps in order; the first step is the baseline. */
export function findKnee(steps: readonly StepSummary[]): KneeVerdict {
  if (steps.length === 0) return { kneeRate: null, sustainedRate: null, reason: 'no steps ran', generatorKeptUp: false };
  const baseline = steps[0]!;
  let sustained: number | null = null;
  for (const step of steps) {
    const lagging = step.lagP99Ms > MAX_LAG_P99_MS;
    const reason = kneeReason(step, baseline);
    if (reason) {
      if (!lagging) return { kneeRate: step.rate, sustainedRate: sustained, reason, generatorKeptUp: true };
      return { kneeRate: step.rate, sustainedRate: sustained, reason: `${reason}; the generator also fell behind (lag p99 ${step.lagP99Ms.toFixed(0)} ms), so the knee is above ${sustained ?? 0}/s and at most ${step.rate}/s`, generatorKeptUp: false };
    }
    if (step.sent < MIN_ACHIEVED_SHARE * step.planned || lagging) {
      return { kneeRate: null, sustainedRate: sustained, reason: `the generator could not keep ${step.rate}/s (sent ${step.sent} of ${step.planned}, lag p99 ${step.lagP99Ms.toFixed(0)} ms)`, generatorKeptUp: false };
    }
    sustained = step.rate;
  }
  return { kneeRate: null, sustainedRate: sustained, reason: `no knee up to ${sustained}/s`, generatorKeptUp: true };
}
