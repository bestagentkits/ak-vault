import { defineConfig, devices } from '@playwright/test';

/**
 * Targets the deployed staging Worker (VAULT_E2E_BASE_URL). No test here writes to
 * production: the base URL must be https, and the dashboard suites need a signed-in
 * staging test account supplied as a storage-state file outside the repo.
 * Serial execution keeps one synthetic vault per run and keeps the leak scan's
 * tail window meaningful.
 */
export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  globalSetup: './global-setup.ts',
  reporter: [['list']],
  use: {
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    // Traces and screenshots capture DOM and network bodies, which hold sentinels.
    actionTimeout: 15_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
