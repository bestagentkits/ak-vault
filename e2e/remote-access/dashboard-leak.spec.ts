/**
 * Value-leak assertions for the dashboard without a session: the run's sentinel must be
 * absent from the DOM, every response body, the console, Web Storage and IndexedDB, and
 * the page must make no third-party requests. The write-then-search round trip needs an
 * enrolled browser, whose keys cannot leave its context, so it runs in dashboard-flow.
 */
import { expect, test } from '@playwright/test';
import { AK_WEB_ORIGIN, BASE_URL, gate, runSentinel } from './support/env.js';
import { openDashboard } from './support/dashboard.js';
import { capture, dumpPageState } from './support/page-capture.js';

const g = await gate();
const ALLOWED_ORIGINS = new Set([new URL(BASE_URL).origin, AK_WEB_ORIGIN]);


test.describe('dashboard without a signed-in session', () => {
  test.skip(g.remote !== null, g.remote ?? '');
  test.skip(g.oauth !== null, g.oauth ?? '');

  test('the page makes only same-origin and ak-web requests and no third-party requests', async ({ page }) => {
    const seen = capture(page);
    await openDashboard(page);
    await page.waitForLoadState('networkidle');
    const origins = new Set(seen.requests.map((r) => new URL(r.url()).origin));
    for (const origin of origins) {
      expect(ALLOWED_ORIGINS.has(origin), 'third-party request').toBe(true);
    }
  });

  test('the sentinel is absent from the DOM, storage, IndexedDB, responses and console', async ({ page, context }) => {
    const sentinel = runSentinel();
    const seen = capture(page);
    await openDashboard(page);
    await page.waitForLoadState('networkidle');
    expect(await dumpPageState(page)).not.toContain(sentinel);
    expect(seen.bodies.some((b) => b.includes(sentinel))).toBe(false);
    expect(seen.console.some((c) => c.includes(sentinel))).toBe(false);
    expect(await context.cookies(BASE_URL)).toEqual([]);
  });
});
