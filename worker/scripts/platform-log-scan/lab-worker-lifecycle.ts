/**
 * Deploy, tail and delete the throwaway lab Worker with wrangler. The lab config
 * is generated from the production top level of `worker/wrangler.jsonc`
 * (observability, assets, Durable Object bindings and migrations, compatibility
 * date) with only these changes: a lab name on workers.dev and no custom domain,
 * the lab entry (`lab-worker/lab-worker-entry.ts`), traces turned on, sync on, and
 * the synthetic issuer's inline JWKS. Generated files live in the run's private
 * temporary directory, never in the repository.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createWriteStream, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { unstable_readConfig } from 'wrangler';

const HERE = dirname(fileURLToPath(import.meta.url));
export const WORKER_DIR = resolve(HERE, '../..');
const WRANGLER = join(WORKER_DIR, 'node_modules/.bin/wrangler');
const LAB_ENTRY = join(HERE, 'lab-worker/lab-worker-entry.ts');

/** Lab names are namespaced so a typo can never target the real Workers. */
export const LAB_NAME_PATTERN = /^ak-vault-lab-[a-z0-9-]{4,40}$/;

/** Every wrangler process this run started and that has not exited yet. */
const liveChildren = new Set<ChildProcess>();

function spawnWrangler(args: string[], cwd: string): ChildProcess & { stdout: NonNullable<ChildProcess['stdout']>; stderr: NonNullable<ChildProcess['stderr']> } {
  const child = spawn(WRANGLER, args, { cwd, env: { ...process.env, CI: '1', WRANGLER_SEND_METRICS: 'false' }, stdio: ['ignore', 'pipe', 'pipe'] });
  liveChildren.add(child);
  child.once('close', () => liveChildren.delete(child));
  child.once('error', () => liveChildren.delete(child));
  return child;
}

/** Stop every wrangler process still running (a deploy or tail cut short by an interrupt) and wait for each to exit. */
export async function stopAllWrangler(): Promise<void> {
  await Promise.all([...liveChildren].map((child) => stopProcess(child)));
}

export interface LabVars {
  issuer: string;
  audience: string;
  jwks: string;
}

/** Production observability, plus traces (off in production) so the scan also covers them. */
export function labObservability(): { production: unknown; lab: Record<string, unknown> } {
  const prod = unstable_readConfig({ config: join(WORKER_DIR, 'wrangler.jsonc'), env: '' }, {});
  const production = prod.observability;
  if (!production || typeof production !== 'object') throw new Error('production observability settings not found');
  return { production, lab: { ...production, traces: { enabled: true, head_sampling_rate: 1 } } };
}

export function writeLabConfig(dir: string, name: string, vars: LabVars): { path: string; observability: Record<string, unknown> } {
  const prod = unstable_readConfig({ config: join(WORKER_DIR, 'wrangler.jsonc'), env: '' }, {});
  const { lab } = labObservability();
  const config = {
    name,
    main: LAB_ENTRY,
    compatibility_date: prod.compatibility_date,
    compatibility_flags: prod.compatibility_flags,
    workers_dev: true,
    preview_urls: false,
    observability: lab,
    assets: { ...prod.assets, directory: join(WORKER_DIR, 'public') },
    durable_objects: { bindings: prod.durable_objects.bindings.map((b: { name: string; class_name: string }) => ({ name: b.name, class_name: b.class_name })) },
    migrations: prod.migrations,
    vars: { VAULT_SYNC_ENABLED: 'true', VAULT_ISSUER: vars.issuer, VAULT_AUDIENCE: vars.audience, VAULT_JWKS_JSON: vars.jwks },
  };
  const path = join(dir, 'wrangler.lab.json');
  writeFileSync(path, JSON.stringify(config, null, 2), { mode: 0o600 });
  return { path, observability: lab };
}

/**
 * Run wrangler to completion; its output goes to `logFile` and only the last
 * lines, passed through `redact`, are shown on failure.
 */
export function wrangler(args: string[], cwd: string, logFile: string, redact: (text: string) => string, timeoutMs = 300_000): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const out = createWriteStream(logFile, { flags: 'a', mode: 0o600 });
    out.on('error', (err) => reject(new Error(`wrangler log could not be written: ${err.name}`)));
    const chunks: string[] = [];
    const child = spawnWrangler(args, cwd);
    const collect = (b: Buffer) => {
      out.write(b);
      chunks.push(b.toString('utf8'));
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const timer = setTimeout(() => child.kill('SIGTERM'), timeoutMs);
    child.on('error', (err) => {
      clearTimeout(timer);
      out.end();
      reject(new Error(`wrangler ${args[0]} could not start: ${err.name}`));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      out.end();
      if (code === 0) return resolvePromise();
      const tail = redact(chunks.join('').split('\n').slice(-15).join('\n'));
      reject(new Error(`wrangler ${args[0]} exited with ${code}:\n${tail}`));
    });
  });
}

export interface TailCapture {
  child: ChildProcess;
  /** Settles once wrangler exited and the capture file is fully flushed; rejects on a process or write error. */
  flushed: Promise<void>;
}

/** `wrangler tail --format json` into `file` until stopped with `stopTail`. */
export function startTail(name: string, cwd: string, file: string): TailCapture {
  const out = createWriteStream(file, { mode: 0o600 });
  const child = spawnWrangler(['tail', name, '--format', 'json'], cwd);
  // stderr carries wrangler's own status lines; keep them with the capture so they are scanned too.
  const write = (b: Buffer) => out.write(b);
  child.stdout.on('data', write);
  child.stderr.on('data', write);
  const flushed = new Promise<void>((resolvePromise, reject) => {
    out.on('error', (err) => reject(new Error(`tail capture could not be written: ${err.name}`)));
    child.on('error', (err) => {
      out.end();
      reject(new Error(`wrangler tail could not start: ${err.name}`));
    });
    child.on('close', () => out.end(() => resolvePromise()));
  });
  // Observed by stopTail; this only keeps an early failure from crashing the process unhandled.
  flushed.catch(() => undefined);
  return { child, flushed };
}

function stopProcess(child: ChildProcess, timeoutMs = 10_000): Promise<void> {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolvePromise) => {
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.once('close', () => {
      clearTimeout(timer);
      resolvePromise();
    });
    child.kill('SIGINT');
  });
}

/** Stop the tail and wait until its capture is on disk. */
export async function stopTail(tail: TailCapture | undefined): Promise<void> {
  if (!tail) return;
  await stopProcess(tail.child);
  await tail.flushed;
}

/** `wrangler tail --format json` prints pretty-printed objects back to back: count them, and the fetch invocations among them. */
export function countTailEvents(text: string): { events: number; fetches: number } {
  let events = 0;
  let fetches = 0;
  let buffer: string[] = [];
  for (const line of text.split('\n')) {
    if (line === '{') buffer = [];
    buffer.push(line);
    if (line !== '}') continue;
    try {
      const event = JSON.parse(buffer.join('\n')) as { event?: { request?: unknown } };
      events++;
      if (event.event?.request) fetches++;
    } catch {
      // A partial object at the end of the capture; its text is still scanned.
    }
    buffer = [];
  }
  return { events, fetches };
}
