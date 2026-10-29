/**
 * Load-generator child process of the registry ramp test, forked by
 * registry-load-traffic.ts so one step's open-loop schedule is spread over
 * several event loops (one Node process cannot keep a schedule much above
 * 400 requests a second while signing a token per request and opening TLS
 * connections). Child `index` of `stride` sends requests n = index, index +
 * stride, … at `startAt + n / rate`, and reports compact samples over IPC.
 *
 * The issuer's private JWK arrives over IPC only. Nothing here prints a token,
 * key or synthetic identifier.
 */
import { randomId } from '@ak-vault/protocol';
import { LabIssuer } from '../platform-log-scan/lab-client.js';

export interface GeneratorTask {
  origin: string;
  issuer: string;
  audience: string;
  kid: string;
  jwk: JsonWebKey;
  subs: string[];
  rate: number;
  seconds: number;
  index: number;
  stride: number;
  /** Epoch ms of request 0. */
  startAt: number;
  timeoutMs: number;
}

/** Per request: status (0 = no answer), latency ms, lag ms, 1 when the client timed out. */
export type PackedSample = [number, number, number, number];

export interface GeneratorResult {
  samples: PackedSample[];
  colos: Record<string, number>;
}

const TICK_MS = 2;

async function oneRequest(task: GeneratorTask, issuer: LabIssuer, sub: string, scheduledAt: number, colos: Record<string, number>): Promise<PackedSample> {
  const now = Math.floor(Date.now() / 1000);
  // A seeded (revoked through min_iat) sub with a random, unrevoked sid and did: all three lookups run.
  const token = await issuer.sign(
    { alg: 'ES256', typ: 'at+jwt', kid: issuer.kid },
    { iss: issuer.issuer, aud: issuer.audience, sub, did: randomId(), sid: `sid-${randomId()}`, jti: randomId(), scope: 'vault:read', session_kind: 'email_otp', iat: now, nbf: now, exp: now + 300 },
  );
  const sentAt = performance.now();
  try {
    const res = await fetch(`${task.origin}/v1/vaults/${randomId()}/changes`, {
      headers: { Authorization: `Bearer ${token}` },
      redirect: 'error',
      signal: AbortSignal.timeout(task.timeoutMs),
    });
    await res.arrayBuffer();
    // cf-ray ends with the edge location code (for example "-SIN"); kept as a count only.
    const colo = res.headers.get('cf-ray')?.split('-').at(-1) ?? 'unknown';
    colos[colo] = (colos[colo] ?? 0) + 1;
    return [res.status, performance.now() - sentAt, sentAt - scheduledAt, 0];
  } catch (err) {
    return [0, performance.now() - sentAt, sentAt - scheduledAt, (err as Error).name === 'TimeoutError' ? 1 : 0];
  }
}

export async function generate(task: GeneratorTask): Promise<GeneratorResult> {
  const issuer = await LabIssuer.fromPrivateJwk(task.issuer, task.audience, task.kid, task.jwk);
  const planned = task.rate * task.seconds;
  const intervalMs = 1000 / task.rate;
  const start = performance.now() + (task.startAt - Date.now());
  const colos: Record<string, number> = {};
  const inFlight: Promise<PackedSample>[] = [];
  let n = task.index;
  while (n < planned) {
    const now = performance.now();
    while (n < planned && start + n * intervalMs <= now) {
      inFlight.push(oneRequest(task, issuer, task.subs[n % task.subs.length]!, start + n * intervalMs, colos));
      n += task.stride;
    }
    await new Promise((r) => setTimeout(r, TICK_MS));
  }
  return { samples: await Promise.all(inFlight), colos };
}

// Child-process entry: one task in, one result out, then exit.
if (process.send) {
  process.once('message', (task: GeneratorTask) => {
    generate(task).then(
      (result) => process.send!(result, () => process.exit(0)),
      (err: Error) => {
        process.stderr.write(`load generator failed: ${err.name}\n`);
        process.exit(1);
      },
    );
  });
}
