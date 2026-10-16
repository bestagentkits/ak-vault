/**
 * Monthly cost projection for docs/operations/cost-model.md: Cloudflare Workers
 * Paid prices, per-operation inputs (measured by run-cost-measurement.ts) and a
 * fleet scenario (vaults, devices, pull and write rates) -> USD per line item.
 * Pure arithmetic with no I/O, so the documented figures can be recomputed and
 * are pinned by worker/test/cost-projection.test.ts. Prices are read from the
 * Cloudflare pricing pages; recheck them before relying on a result.
 */

/** Workers Paid plan prices (USD) and monthly included amounts. */
export const PRICES = {
  planMinimum: 5,
  workerRequests: { included: 10e6, perMillion: 0.3 },
  workerCpuMs: { included: 30e6, perMillion: 0.02 },
  doRequests: { included: 1e6, perMillion: 0.15 },
  doDurationGbS: { included: 400_000, perMillion: 12.5 },
  rowsRead: { included: 25e9, perMillion: 0.001 },
  rowsWritten: { included: 50e6, perMillion: 1 },
  storedGbMonth: { included: 5, perGb: 0.2 },
} as const;

export const DAYS_PER_MONTH = 30;

/** Usage of one API operation as billed: Worker side, then both Durable Object namespaces. */
export interface OperationCost {
  workerCpuMs: number;
  /** Durable Object requests (vault object plus revocation registry). */
  doRequests: number;
  /** Billed Durable Object duration, GB-s (vault plus registry). */
  durationGbS: number;
  rowsRead: number;
  rowsWritten: number;
}

export interface Scenario {
  vaults: number;
  devicesPerVault: number;
  pullsPerDevicePerDay: number;
  writesPerVaultPerDay: number;
  /** Stored SQLite bytes per vault. */
  storedBytesPerVault: number;
}

export interface MonthlyCost {
  calls: number;
  lines: { plan: number; workerRequests: number; workerCpu: number; doRequests: number; doDuration: number; rowsRead: number; rowsWritten: number; storage: number };
  total: number;
}

const overage = (used: number, price: { included: number; perMillion: number }): number => (Math.max(0, used - price.included) / 1e6) * price.perMillion;

/** Projected monthly bill for `scenario` with `pull` per poll and `write` per item write. */
export function projectMonthlyCost(scenario: Scenario, pull: OperationCost, write: OperationCost): MonthlyCost {
  const pulls = scenario.vaults * scenario.devicesPerVault * scenario.pullsPerDevicePerDay * DAYS_PER_MONTH;
  const writes = scenario.vaults * scenario.writesPerVaultPerDay * DAYS_PER_MONTH;
  const sum = (k: keyof OperationCost) => pulls * pull[k] + writes * write[k];
  const calls = pulls + writes;
  const storedGb = (scenario.vaults * scenario.storedBytesPerVault) / 1e9;
  const lines = {
    plan: PRICES.planMinimum,
    workerRequests: overage(calls, PRICES.workerRequests),
    workerCpu: overage(sum('workerCpuMs'), PRICES.workerCpuMs),
    doRequests: overage(sum('doRequests'), PRICES.doRequests),
    doDuration: overage(sum('durationGbS'), PRICES.doDurationGbS),
    rowsRead: overage(sum('rowsRead'), PRICES.rowsRead),
    rowsWritten: overage(sum('rowsWritten'), PRICES.rowsWritten),
    storage: Math.max(0, storedGb - PRICES.storedGbMonth.included) * PRICES.storedGbMonth.perGb,
  };
  return { calls, lines, total: Object.values(lines).reduce((a, b) => a + b, 0) };
}

/** Per-operation usage from window totals: `totals` divided by the number of operations. */
export function perOperation(totals: OperationCost, operations: number): OperationCost {
  if (!(operations > 0)) throw new Error('perOperation needs at least one operation');
  return {
    workerCpuMs: totals.workerCpuMs / operations,
    doRequests: totals.doRequests / operations,
    durationGbS: totals.durationGbS / operations,
    rowsRead: totals.rowsRead / operations,
    rowsWritten: totals.rowsWritten / operations,
  };
}

export interface PhaseTiming {
  startedAt: number;
  endedAt: number;
}

const MINUTE = 60_000;
const floorMinute = (t: number) => Math.floor(t / MINUTE) * MINUTE;

/**
 * Analytics window of each phase: from the start of its first minute to the start
 * of the next phase's first minute (the last phase gets `tailMs` after its last
 * minute). Phases must start in distinct, increasing minutes; Durable Object usage
 * reported a little after a phase's last request still falls in its own window.
 */
export function phaseWindows(phases: readonly PhaseTiming[], tailMs = 2 * MINUTE): { from: number; to: number }[] {
  return phases.map((p, i) => {
    const from = floorMinute(p.startedAt);
    const next = phases[i + 1];
    const to = next ? floorMinute(next.startedAt) : floorMinute(p.endedAt) + MINUTE + tailMs;
    if (!(to > from) || (next && floorMinute(next.startedAt) <= floorMinute(p.endedAt))) throw new Error('phases must not share a minute');
    return { from, to };
  });
}
