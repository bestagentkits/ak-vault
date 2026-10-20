/**
 * Value-leak assertions for the dashboard: the run's sentinel must be absent from the
 * DOM, every response body, the console, Web Storage and IndexedDB, and the page must
 * make no third-party requests. The unauthenticated checks run on every target; the
 * write-then-search round trip runs only with a signed-in staging account.
 */
import { expect, test, type Page, type Request } from '@playwright/test';
import { AK_WEB_ORIGIN, BASE_URL, STORAGE_STATE, gate, runNameSentinel, runSentinel } from './support/env.js';
import { openDashboard, setSecret, signIn } from './support/dashboard.js';

const g = await gate();
const ALLOWED_ORIGINS = new Set([new URL(BASE_URL).origin, AK_WEB_ORIGIN]);

interface Capture {
  requests: Request[];
  bodies: string[];
  console: string[];
}

function capture(page: Page): Capture {
  const seen: Capture = { requests: [], bodies: [], console: [] };
  page.on('request', (req) => seen.requests.push(req));
  page.on('console', (msg) => seen.console.push(msg.text()));
  page.on('response', (res) => {
    void res
      .body()
      .then((buf) => seen.bodies.push(buf.toString('utf8')))
      .catch(() => seen.bodies.push(''));
  });
  return seen;
}

/** Everything the page can keep: DOM, Web Storage, and every IndexedDB record as text. */
async function dumpPageState(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const parts: string[] = [document.documentElement.outerHTML];
    for (const store of [localStorage, sessionStorage]) {
      for (let i = 0; i < store.length; i += 1) {
        const key = store.key(i)!;
        parts.push(key, store.getItem(key) ?? '');
      }
    }
    const databases = (await indexedDB.databases?.()) ?? [];
    for (const info of databases) {
      if (!info.name) continue;
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open(info.name!);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      for (const name of Array.from(db.objectStoreNames)) {
        const rows = await new Promise<unknown[]>((resolve, reject) => {
          const get = db.transaction(name, 'readonly').objectStore(name).getAll();
          get.onsuccess = () => resolve(get.result as unknown[]);
          get.onerror = () => reject(get.error);
        });
        parts.push(JSON.stringify(rows, (_k, v) => (v instanceof ArrayBuffer ? Array.from(new Uint8Array(v)).join(',') : v)));
      }
      db.close();
    }
    return parts.join('\n');
  });
}

test.describe('dashboard without a signed-in session', () => {
  test.skip(g.remote !== null, g.remote ?? '');

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

test.describe('dashboard round trip (signed-in staging account)', () => {
  test.skip(g.remote !== null, g.remote ?? '');
  test.skip(g.account !== null, g.account ?? '');
  test.use({ storageState: STORAGE_STATE || undefined });

  test('a written value never appears in the DOM, storage, responses or console; the name never in responses or console', async ({ page, context }) => {
    const sentinel = runSentinel();
    const name = runNameSentinel();
    const seen = capture(page);
    await signIn(page);
    await setSecret(page, name, sentinel);
    // The dashboard shows names by design; the value must stay hidden everywhere.
    await expect(page.getByTestId('item-name').filter({ hasText: name })).toBeVisible({ timeout: 60_000 });
    await page.getByTestId('filter').fill(name);
    await page.waitForLoadState('networkidle');
    expect(await dumpPageState(page)).not.toContain(sentinel);
    expect(seen.bodies.some((b) => b.includes(sentinel) || b.includes(name))).toBe(false);
    expect(seen.console.some((c) => c.includes(sentinel) || c.includes(name))).toBe(false);
    expect(await context.cookies(BASE_URL)).toEqual([]);
  });
});
