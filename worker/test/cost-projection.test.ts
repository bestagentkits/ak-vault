/**
 * The cost projection behind docs/operations/cost-model.md: plan minimum and
 * included amounts, per-line overage, per-operation division and the per-phase
 * analytics windows of the cost measurement.
 */
import { describe, expect, it } from 'vitest';
import { PRICES, perOperation, phaseWindows, projectMonthlyCost, type OperationCost, type Scenario } from '../scripts/cost-measurement/cost-projection.js';

const zero: OperationCost = { workerCpuMs: 0, doRequests: 0, durationGbS: 0, rowsRead: 0, rowsWritten: 0 };

describe('projectMonthlyCost', () => {
  it('charges only the plan minimum inside every included amount', () => {
    const scenario: Scenario = { vaults: 10, devicesPerVault: 2, pullsPerDevicePerDay: 50, writesPerVaultPerDay: 5, storedBytesPerVault: 100_000 };
    const op: OperationCost = { workerCpuMs: 3, doRequests: 2, durationGbS: 0.01, rowsRead: 7, rowsWritten: 5 };
    const cost = projectMonthlyCost(scenario, op, op);
    expect(cost.calls).toBe(10 * 2 * 50 * 30 + 10 * 5 * 30);
    expect(cost.total).toBe(PRICES.planMinimum);
  });

  it('bills each line only above its included amount', () => {
    // 1,000 vaults x 1 device x 1,000 pulls a day x 30 days = 30 million pulls, no writes.
    const scenario: Scenario = { vaults: 1000, devicesPerVault: 1, pullsPerDevicePerDay: 1000, writesPerVaultPerDay: 0, storedBytesPerVault: 10e6 };
    const pull: OperationCost = { workerCpuMs: 2, doRequests: 2, durationGbS: 0.02, rowsRead: 1000, rowsWritten: 5 };
    const { lines, total } = projectMonthlyCost(scenario, pull, zero);
    expect(lines.workerRequests).toBeCloseTo((30e6 - 10e6) / 1e6 * 0.3, 6);
    expect(lines.workerCpu).toBeCloseTo((60e6 - 30e6) / 1e6 * 0.02, 6);
    expect(lines.doRequests).toBeCloseTo((60e6 - 1e6) / 1e6 * 0.15, 6);
    expect(lines.doDuration).toBeCloseTo((600_000 - 400_000) / 1e6 * 12.5, 6);
    expect(lines.rowsRead).toBeCloseTo((30e9 - 25e9) / 1e6 * 0.001, 6);
    expect(lines.rowsWritten).toBeCloseTo((150e6 - 50e6) / 1e6 * 1, 6);
    expect(lines.storage).toBeCloseTo((10 - 5) * 0.2, 6);
    expect(total).toBeCloseTo(Object.values(lines).reduce((a, b) => a + b, 0), 6);
  });

  it('reproduces the 2026-10-15 estimate for 10,000 vaults polling every 60 s', () => {
    // Inputs of the lab measurement at 3f77991 (cost model, "Measured 2026-10-15"), registry duration capped as documented then.
    const scenario: Scenario = { vaults: 10_000, devicesPerVault: 3, pullsPerDevicePerDay: 1440, writesPerVaultPerDay: 20, storedBytesPerVault: 0 };
    const op: OperationCost = { workerCpuMs: 3.3, doRequests: 1.98, durationGbS: 0.0064 + 324_000 / 1_302_000_000, rowsRead: 6.9, rowsWritten: 4.76 };
    const cost = projectMonthlyCost(scenario, op, op);
    expect(cost.lines.rowsWritten).toBeCloseTo(6148, -1);
    expect(cost.total).toBeGreaterThan(7_050);
    expect(cost.total).toBeLessThan(7_150);
  });
});

describe('perOperation', () => {
  it('divides window totals by the operation count and refuses zero operations', () => {
    expect(perOperation({ workerCpuMs: 30, doRequests: 20, durationGbS: 1, rowsRead: 70, rowsWritten: 50 }, 10)).toEqual({ workerCpuMs: 3, doRequests: 2, durationGbS: 0.1, rowsRead: 7, rowsWritten: 5 });
    expect(() => perOperation(zero, 0)).toThrow();
  });
});

describe('phaseWindows', () => {
  const m = (minute: number, second = 0) => Date.UTC(2026, 9, 16, 8, minute, second);

  it('runs each window from its first minute to the next phase, the last one with a tail', () => {
    const windows = phaseWindows([
      { startedAt: m(0, 2), endedAt: m(1, 30) },
      { startedAt: m(3, 2), endedAt: m(8, 2) },
    ]);
    expect(windows).toEqual([
      { from: m(0), to: m(3) },
      { from: m(3), to: m(11) },
    ]);
  });

  it('refuses phases that share a minute', () => {
    expect(() => phaseWindows([{ startedAt: m(0, 2), endedAt: m(1, 30) }, { startedAt: m(1, 40), endedAt: m(2) }])).toThrow();
  });
});
