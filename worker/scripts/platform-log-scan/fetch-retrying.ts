/** Network retry for the platform log disclosure scan's HTTP calls. */

const TIMEOUT_MS = 30_000;
const ATTEMPTS = 5;

/**
 * `fetch` that retries network failures (no HTTP response at all), which the
 * operator network produces now and then. HTTP errors are returned, not retried.
 */
export async function fetchRetrying(url: string, init: () => RequestInit, label: string): Promise<Response> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await fetch(url, { ...init(), signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (err) {
      if (attempt >= ATTEMPTS) throw new Error(`${label}: ${(err as Error).name} after ${ATTEMPTS} attempts`);
      await new Promise((r) => setTimeout(r, 2_000 * attempt));
    }
  }
}
