/**
 * Network and cookie assertions for the dashboard without a session: the page must make no
 * third-party requests and set no cookie on the vault host. A signed-out page never holds the
 * run's sentinel, so a sentinel-absence check here would pass by construction; the value-leak
 * checks (DOM, storage, IndexedDB, responses, console) run in dashboard-flow, after the
 * sentinel has been written through an enrolled browser, whose keys cannot leave its context.
 */
import { expect, test } from '@playwright/test';
import { AK_WEB_ORIGIN, BASE_URL, gate } from './support/env.js';
import { openDashboard } from './support/dashboard.js';
import { capture } from './support/page-capture.js';

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

  test('the page sets no cookie on the vault host', async ({ page, context }) => {
    await openDashboard(page);
    await page.waitForLoadState('networkidle');
    expect(await context.cookies(BASE_URL)).toEqual([]);
  });
});
