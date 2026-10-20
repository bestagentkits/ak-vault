/**
 * Run-wide setup: generates the value and name sentinels from a CSPRNG, keeps them
 * in this process's environment only (never in a file), and starts the live leak
 * scan. The returned teardown stops the tail, prints counts and nothing else.
 */
import { randomBytes } from 'node:crypto';
import type { FullConfig } from '@playwright/test';
import { startLeakScan, type LeakScanResult } from './leak-scan.js';

export default async function globalSetup(config: FullConfig): Promise<() => Promise<void>> {
  const valueSentinel = `SMOKE_VALUE_${randomBytes(24).toString('base64url')}`;
  const nameSentinel = `SMOKE_NAME_${randomBytes(12).toString('base64url')}`;
  process.env['VAULT_E2E_RUN_SENTINEL'] = valueSentinel;
  process.env['VAULT_E2E_RUN_NAME_SENTINEL'] = nameSentinel;

  const cwd = config.rootDir;
  const tail = await startLeakScan([valueSentinel, nameSentinel], cwd);

  return async () => {
    const result: LeakScanResult = await tail.stop();
    report(result);
    delete process.env['VAULT_E2E_RUN_SENTINEL'];
    delete process.env['VAULT_E2E_RUN_NAME_SENTINEL'];
  };
}

function report(result: LeakScanResult): void {
  if (result.status === 'unavailable') {
    process.stdout.write(`[leak-scan] BLOCKED: ${result.reason ?? 'unavailable'}. Not a clean scan.\n`);
    return;
  }
  process.stdout.write(`[leak-scan] scanned ${result.chunks} tail chunks, ${result.hits} sentinel hits\n`);
}
