/**
 * What a dashboard page can expose: every request, response body and console line it
 * produces, and everything it keeps (DOM, Web Storage, IndexedDB). Leak assertions search
 * these for the run's sentinels; nothing here logs the captured text.
 */
import type { Page, Request } from '@playwright/test';

export interface Capture {
  requests: Request[];
  bodies: string[];
  console: string[];
}

export function capture(page: Page): Capture {
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
export async function dumpPageState(page: Page): Promise<string> {
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
