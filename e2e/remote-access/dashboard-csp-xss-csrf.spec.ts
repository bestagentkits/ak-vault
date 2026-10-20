/**
 * Dashboard headers, script containment and cross-origin refusal. The CSP check is
 * exact and needs no account. The injection probes run in the page without a
 * signed-in session; the secret-name rendering probe needs the account and is gated.
 */
import { expect, test } from '@playwright/test';
import { AK_WEB_ORIGIN, BASE_URL, STORAGE_STATE, gate, runSentinel } from './support/env.js';
import { APP_URL, openDashboard, signIn, setSecret } from './support/dashboard.js';

const g = await gate();

/** The dashboard CSP, spelled out: any change to a directive is a deliberate, reviewed change. */
const EXPECTED_APP_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' ${AK_WEB_ORIGIN}`,
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join('; ');

const ATTACKER = 'https://attacker.example';

test.describe('dashboard response headers', () => {
  test.skip(g.remote !== null, g.remote ?? '');

  test('/app/ serves the exact CSP and the isolation headers', async ({ request }) => {
    const res = await request.get(APP_URL, { maxRedirects: 0, failOnStatusCode: false });
    expect(res.status()).toBe(200);
    const headers = res.headers();
    expect(headers['content-security-policy']).toBe(EXPECTED_APP_CSP);
    expect(headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(headers['cross-origin-resource-policy']).toBe('same-origin');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['cache-control']).toContain('no-store');
    expect(headers['set-cookie']).toBeUndefined();
  });

  test('every script and stylesheet in the dashboard document has SRI and a same-origin URL', async ({ request }) => {
    const html = await (await request.get(APP_URL, { maxRedirects: 0, failOnStatusCode: false })).text();
    const tags = [...html.matchAll(/<(script|link)\b[^>]*>/gi)].map((m) => m[0]).filter((t) => /\bsrc=|rel="?stylesheet/i.test(t));
    expect(tags.length).toBeGreaterThan(0);
    for (const tag of tags) {
      expect(tag, 'integrity attribute').toMatch(/\bintegrity="sha(256|384|512)-/);
      const url = /\b(?:src|href)="([^"]+)"/i.exec(tag)?.[1] ?? '';
      expect(url.startsWith('http') ? new URL(url).origin : BASE_URL, 'same origin').toBe(BASE_URL);
    }
  });

  test('the root document keeps the default CSP, not the dashboard one', async ({ request }) => {
    const res = await request.get(`${BASE_URL}/`, { maxRedirects: 0, failOnStatusCode: false });
    expect(res.headers()['content-security-policy']).not.toBe(EXPECTED_APP_CSP);
  });
});

test.describe('script containment in the page', () => {
  test.skip(g.remote !== null, g.remote ?? '');
  // The dashboard renders its configuration alert, not its views, while ak-web's metadata is unavailable.
  test.skip(g.oauth !== null, g.oauth ?? '');

  test('Trusted Types refuse a string sink and the injected handler never runs', async ({ page }) => {
    await openDashboard(page);
    const probe = await page.evaluate(() => {
      const reports: string[] = [];
      document.addEventListener('securitypolicyviolation', (e) => reports.push(e.violatedDirective));
      const w = window as unknown as Record<string, unknown>;
      let threw = false;
      try {
        // Injected markup with an error handler: a string is not a TrustedHTML, so the sink must refuse it.
        const host = document.createElement('div');
        host.innerHTML = '<img src="x" onerror="window.__xssProbe = 1">';
      } catch {
        threw = true;
      }
      return { threw, executed: w['__xssProbe'] === 1, reports: reports.length };
    });
    expect(probe.threw).toBe(true);
    expect(probe.executed).toBe(false);
  });

  test('a javascript: URL and an eval-style string do not execute', async ({ page }) => {
    await openDashboard(page);
    const result = await page.evaluate(async () => {
      const w = window as unknown as Record<string, unknown>;
      const anchor = document.createElement('a');
      anchor.href = 'javascript:window.__xssLink = 1';
      document.body.append(anchor);
      let evalBlocked = false;
      try {
        new Function('window.__xssEval = 1')();
      } catch {
        evalBlocked = true;
      }
      return { evalBlocked, linkExecuted: w['__xssLink'] === 1, evalExecuted: w['__xssEval'] === 1 };
    });
    expect(result.evalBlocked).toBe(true);
    expect(result.evalExecuted).toBe(false);
    expect(result.linkExecuted).toBe(false);
  });
});

test.describe('cross-origin requests cannot act on the vault', () => {
  test.skip(g.remote !== null, g.remote ?? '');

  test('a foreign page cannot fetch or submit to vault routes with the visitor credentials', async ({ page, context }) => {
    await page.route(`${ATTACKER}/**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: `<!doctype html><script>
          (async () => {
            const out = {};
            for (const [label, url, init] of [
              ['mcp', '${BASE_URL}/mcp', { method: 'POST', body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' }],
              ['sync', '${BASE_URL}/v1/vaults/AAAAAAAAAAAAAAAAAAAAAA/changes', { method: 'GET' }],
            ]) {
              try {
                const r = await fetch(url, { credentials: 'include', mode: 'cors', ...init, headers: { 'content-type': 'application/json' } });
                out[label] = { status: r.status, acao: r.headers.get('access-control-allow-origin') };
              } catch (e) {
                out[label] = { blocked: true };
              }
            }
            window.__out = out;
          })();
          </script>`,
      }),
    );
    await page.goto(`${ATTACKER}/`);
    await page.waitForFunction(() => (window as unknown as { __out?: unknown }).__out !== undefined, undefined, { timeout: 30_000 });
    const out = await page.evaluate(() => (window as unknown as { __out: Record<string, { status?: number; acao?: string | null; blocked?: boolean }> }).__out);
    for (const label of ['mcp', 'sync']) {
      const entry = out[label]!;
      // Either the browser blocks the read (no CORS grant) or the Worker refuses the bearer-less request.
      if (!entry.blocked) {
        expect(entry.status, label).toBe(401);
        expect(entry.acao, label).not.toBe(ATTACKER);
      }
    }
    expect(await context.cookies(BASE_URL)).toEqual([]);
  });

  test('the vault origin sets no cookies on a dashboard visit', async ({ page, context }) => {
    test.skip(g.oauth !== null, g.oauth ?? '');
    await openDashboard(page);
    expect(await context.cookies(BASE_URL)).toEqual([]);
  });
});

test.describe('secret names and profile text render inert (signed-in account)', () => {
  test.skip(g.remote !== null, g.remote ?? '');
  test.skip(g.account !== null, g.account ?? '');
  test.use({ storageState: STORAGE_STATE || undefined });

  test('an injected image handler in a secret name does not execute and is shown as text', async ({ page }) => {
    await signIn(page);
    const name = `SMOKE_XSS_<img src=x onerror="window.__xssName=1">`;
    await setSecret(page, name, runSentinel());
    await expect(page.getByTestId('item-name').filter({ hasText: 'SMOKE_XSS_' })).toBeVisible({ timeout: 30_000 });
    expect(await page.evaluate(() => (window as unknown as { __xssName?: number }).__xssName)).toBeUndefined();
    expect(await page.locator('img[onerror]').count()).toBe(0);
  });
});
