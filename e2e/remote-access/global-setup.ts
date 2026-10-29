/**
 * Run-wide setup: generates the value and name sentinels from a CSPRNG, keeps them
 * in this process's environment only (never in a file), and starts the live leak
 * scan. The returned teardown stops the tail, prints counts and nothing else.
 */
import { randomBytes } from 'node:crypto';
import { startLeakScan, type LeakScanResult } from './leak-scan.js';

export default async function globalSetup(): Promise<() => Promise<void>> {
  const valueSentinel = `SMOKE_VALUE_${randomBytes(24).toString('base64url')}`;
  const nameSentinel = `SMOKE_NAME_${randomBytes(12).toString('base64url')}`;
  process.env['VAULT_E2E_RUN_SENTINEL'] = valueSentinel;
  process.env['VAULT_E2E_RUN_NAME_SENTINEL'] = nameSentinel;

  const tail = await startLeakScan([valueSentinel, nameSentinel]);

  return async () => {
    const result: LeakScanResult = await tail.stop();
    delete process.env['VAULT_E2E_RUN_SENTINEL'];
    delete process.env['VAULT_E2E_RUN_NAME_SENTINEL'];
    report(result);
  };
}

/** Set to `1` to let a run pass although the log tail was unavailable (the leak scan did not run). */
const ALLOW_UNSCANNED_ENV = 'VAULT_E2E_ALLOW_UNSCANNED';

/**
 * Prints counts only. A sentinel hit fails the run. An unavailable tail also fails it,
 * because an unscanned run proves nothing about leaks; `VAULT_E2E_ALLOW_UNSCANNED=1`
 * downgrades it to a printed BLOCKED line for local runs that cannot reach the tail.
 */
function report(result: LeakScanResult): void {
  if (result.status === 'unavailable') {
    const reason = result.reason ?? 'unavailable';
    process.stdout.write(`[leak-scan] BLOCKED: ${reason}. Not a clean scan.\n`);
    if (process.env[ALLOW_UNSCANNED_ENV] !== '1') {
      throw new Error(`[leak-scan] the log tail was unavailable (${reason}): the run fails. Set ${ALLOW_UNSCANNED_ENV}=1 to accept an unscanned run.`);
    }
    return;
  }
  process.stdout.write(`[leak-scan] scanned ${result.chunks} tail chunks, ${result.hits} sentinel hits\n`);
  if (result.hits > 0) throw new Error(`[leak-scan] ${result.hits} sentinel occurrence(s) in the tail: the run fails`);
}
