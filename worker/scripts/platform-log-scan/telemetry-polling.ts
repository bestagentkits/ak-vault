/**
 * Waiting helpers of the platform log disclosure scan: generic polling, and
 * telemetry and analytics pulls that wait until Cloudflare's ingestion has caught
 * up with the run (counts reach what the run emitted and stop growing).
 */
import { queryAnalytics, queryTelemetry, type CloudflareCredentials, type TelemetryPull, type TelemetryView } from './cloudflare-api.js';

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const say = (line: string) => process.stdout.write(`${line}\n`);

export async function waitFor(what: string, timeoutMs: number, everyMs: number, check: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check().catch(() => false)) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

/** Poll until events and invocations cover every request the run made (`minRequests`) and the counts stop growing. */
export async function pullTelemetry(creds: CloudflareCredentials, name: string, from: number, to: number, minRequests: number): Promise<Record<TelemetryView, TelemetryPull>> {
  let last = -1;
  const deadline = Date.now() + 15 * 60_000;
  for (;;) {
    const [events, traces, invocations] = await Promise.all((['events', 'traces', 'invocations'] as const).map((v) => queryTelemetry(creds, name, v, from, to)));
    const pulls = { events: events!, traces: traces!, invocations: invocations! };
    const total = events!.rows + traces!.rows + invocations!.rows;
    say(`  telemetry: events ${events!.rows}, traces ${traces!.rows}, invocations ${invocations!.rows}`);
    if (events!.rows >= minRequests && invocations!.rows >= minRequests && traces!.rows > 0 && total === last) return pulls;
    if (Date.now() > deadline) throw new Error('telemetry did not settle within 15 minutes');
    last = total;
    await sleep(45_000);
  }
}

export async function pullAnalytics(creds: CloudflareCredentials, name: string, from: number, to: number, minRequests: number) {
  const deadline = Date.now() + 15 * 60_000;
  for (;;) {
    const a = await queryAnalytics(creds, name, from, to);
    say(`  analytics: ${a.requests} requests`);
    if (a.requests >= minRequests) return a;
    if (Date.now() > deadline) throw new Error('analytics did not reach the run within 15 minutes');
    await sleep(45_000);
  }
}
