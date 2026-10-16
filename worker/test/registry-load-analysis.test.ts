/**
 * The ramp test behind the measured registry ceiling in docs/operations/cost-model.md:
 * rate parsing, the pre-run cost cap, percentiles and the knee rule.
 */
import { describe, expect, it } from 'vitest';
import {
  COST_CAP_USD,
  DEFAULT_RATES,
  DEFAULT_SEED_ENTRIES,
  DEFAULT_STEP_SECONDS,
  estimateCost,
  findKnee,
  parseRates,
  percentile,
  summarizeStep,
  type Sample,
  type StepSummary,
} from '../scripts/registry-load/registry-load-analysis.js';

const samples = (n: number, latencyMs: number, status = 401): Sample[] => Array.from({ length: n }, () => ({ status, latencyMs, lagMs: 0 }));
const step = (rate: number, p99Ms: number, opts: { failed?: number; sent?: number; lagP99Ms?: number; noAnswer?: number } = {}): StepSummary => ({
  rate,
  planned: rate * 10,
  sent: opts.sent ?? rate * 10,
  statuses: {},
  failed: opts.failed ?? 0,
  networkFailures: opts.noAnswer ?? 0,
  timeouts: 0,
  p50Ms: p99Ms / 2,
  p99Ms,
  maxMs: p99Ms,
  lagP99Ms: opts.lagP99Ms ?? 0,
});

describe('parseRates', () => {
  it('accepts increasing integer rates', () => {
    expect(parseRates('5, 10,400')).toEqual([5, 10, 400]);
  });

  it.each(['', '0,5', '5,5', '10,5', '1.5', '5,1001', 'x'])('refuses %j', (text) => {
    expect(() => parseRates(text)).toThrow();
  });
});

describe('estimateCost', () => {
  it('keeps the default plan under the cost cap', () => {
    const e = estimateCost({ rates: DEFAULT_RATES, stepSeconds: DEFAULT_STEP_SECONDS, seedEntries: DEFAULT_SEED_ENTRIES });
    expect(e.rampRequests).toBe(3435 * DEFAULT_STEP_SECONDS);
    expect(e.seedWebhooks).toBe(100);
    expect(e.usd).toBeGreaterThan(0);
    expect(e.usd).toBeLessThan(COST_CAP_USD);
  });

  it('exceeds the cap for a plan far beyond the ramp', () => {
    expect(estimateCost({ rates: [1000], stepSeconds: 55 * 20, seedEntries: 100 }).usd).toBeGreaterThan(COST_CAP_USD);
  });
});

describe('percentile', () => {
  it('uses the nearest rank', () => {
    const sorted = Array.from({ length: 100 }, (_, i) => i + 1);
    expect(percentile(sorted, 50)).toBe(50);
    expect(percentile(sorted, 99)).toBe(99);
    expect(percentile([7], 99)).toBe(7);
    expect(percentile([], 50)).toBeNaN();
  });
});

describe('summarizeStep', () => {
  it('counts 503s as failed and keeps network failures apart', () => {
    const s = summarizeStep(10, 100, [...samples(97, 50), ...samples(2, 900, 503), { status: 0, latencyMs: 15_000, lagMs: 0, timedOut: true }]);
    expect(s.sent).toBe(100);
    expect(s.statuses).toEqual({ '401': 97, '503': 2, '0': 1 });
    expect(s.failed).toBe(2);
    expect(s.networkFailures).toBe(1);
    expect(s.timeouts).toBe(1);
    expect(s.p50Ms).toBe(50);
    // Requests without an answer are not latencies.
    expect(s.maxMs).toBe(900);
  });
});

describe('findKnee', () => {
  it('reports no knee when every step stays near the baseline', () => {
    expect(findKnee([step(5, 100), step(10, 120), step(20, 190)])).toMatchObject({ kneeRate: null, sustainedRate: 20, generatorKeptUp: true });
  });

  it('marks the first step whose p99 more than doubles', () => {
    expect(findKnee([step(5, 100), step(10, 150), step(20, 201), step(40, 900)])).toMatchObject({ kneeRate: 20, sustainedRate: 10 });
  });

  it('marks the first step with more than 0.1% 503', () => {
    expect(findKnee([step(5, 100), step(100, 110, { failed: 2, sent: 1000 })])).toMatchObject({ kneeRate: 100, sustainedRate: 5 });
    expect(findKnee([step(5, 100), step(100, 110, { failed: 1, sent: 1000 })])).toMatchObject({ kneeRate: null, sustainedRate: 100 });
  });

  it('counts unanswered requests only above the first step\'s share plus 1%', () => {
    // A lossy client network at the baseline is not a knee, there or later.
    expect(findKnee([step(5, 100, { noAnswer: 5, sent: 275 }), step(1000, 110, { noAnswer: 622, sent: 55_000 })])).toMatchObject({ kneeRate: null, sustainedRate: 1000 });
    expect(findKnee([step(5, 100, { noAnswer: 1, sent: 275 }), step(400, 110), step(600, 120, { noAnswer: 3300, sent: 33_000 })])).toMatchObject({ kneeRate: 600, sustainedRate: 400, generatorKeptUp: true });
  });

  it('uses the registry wall p99 from analytics when both steps have it', () => {
    const at = (rate: number, wall: number) => ({ ...step(rate, 3000), registryWallP99Ms: wall });
    expect(findKnee([at(5, 240), at(600, 199), at(800, 314), at(1000, 1240)])).toMatchObject({ kneeRate: 1000, sustainedRate: 800, generatorKeptUp: true });
    // Without analytics only the client-side rules apply.
    expect(findKnee([step(5, 3000), step(1000, 3100)])).toMatchObject({ kneeRate: null, sustainedRate: 1000 });
  });

  it('flags a generator that could not keep the schedule', () => {
    expect(findKnee([step(5, 100), step(400, 110, { sent: 3000 })])).toMatchObject({ kneeRate: null, sustainedRate: 5, generatorKeptUp: false });
  });

  it('bounds the knee when the generator fell behind at the knee step', () => {
    const v = findKnee([step(5, 100), step(400, 110), step(600, 2000, { failed: 96, sent: 33_000, lagP99Ms: 13_000 })]);
    expect(v).toMatchObject({ kneeRate: 600, sustainedRate: 400, generatorKeptUp: false });
    expect(v.reason).toContain('above 400/s and at most 600/s');
  });

  it('stops the verdict at a lagging step without a knee', () => {
    expect(findKnee([step(5, 100), step(400, 110, { lagP99Ms: 5000 }), step(600, 110)])).toMatchObject({ kneeRate: null, sustainedRate: 5, generatorKeptUp: false });
  });

  it('handles an empty run', () => {
    expect(findKnee([])).toMatchObject({ kneeRate: null, sustainedRate: null, generatorKeptUp: false });
  });
});
