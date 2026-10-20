/**
 * Live leak scan for the suite: `wrangler tail --env staging` runs for the whole
 * run, and every chunk it prints is searched in memory for the run's value and
 * name sentinels. Nothing is written to disk and no tail content is printed; the
 * result is counts only. A tail that cannot start is reported as `unavailable`,
 * never as a clean scan.
 */
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const WRANGLER_BIN = fileURLToPath(new URL('../../worker/node_modules/wrangler/bin/wrangler.js', import.meta.url));
const READY_AFTER_MS = 8_000;
const DRAIN_MS = 5_000;

export interface LeakScanResult {
  status: 'scanned' | 'unavailable';
  reason?: string;
  /** Tail chunks searched; a chunk is one stdout write from wrangler. */
  chunks: number;
  /** Sentinel occurrences found. Must be zero for a passing run. */
  hits: number;
}

export interface TailHandle {
  stop(): Promise<LeakScanResult>;
}

/**
 * Starts the tail and resolves once it has stayed alive for `READY_AFTER_MS`.
 * The returned handle's `stop()` drains, kills the process and returns the result.
 */
export async function startLeakScan(sentinels: readonly string[], cwd: string): Promise<TailHandle> {
  const needles = sentinels.filter((s) => s.length > 0);
  const carryLength = Math.max(0, ...needles.map((s) => s.length)) - 1;
  const result: LeakScanResult = { status: 'scanned', chunks: 0, hits: 0 };
  let carry = '';

  if (!existsSync(WRANGLER_BIN)) {
    result.status = 'unavailable';
    result.reason = 'worker/node_modules/wrangler is not installed';
    return { stop: async () => result };
  }

  const child: ChildProcessByStdio<null, Readable, Readable> = spawn(process.execPath, [WRANGLER_BIN, 'tail', '--env', 'staging', '--format', 'json'], {
    cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  const scanChunk = (text: string): void => {
    result.chunks += 1;
    const haystack = carry + text;
    for (const needle of needles) {
      let at = haystack.indexOf(needle);
      while (at !== -1) {
        result.hits += 1;
        at = haystack.indexOf(needle, at + needle.length);
      }
    }
    carry = carryLength > 0 ? haystack.slice(-carryLength) : '';
  };
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', scanChunk);
  // stderr can echo account or auth details; it is searched for sentinels but never reported.
  child.stderr.on('data', scanChunk);

  let stopping = false;
  let exitDescription: string | null = null;
  child.once('exit', (code, signal) => {
    if (stopping) return;
    exitDescription = code !== null ? `code ${code}` : `signal ${signal}`;
  });
  await new Promise((resolve) => setTimeout(resolve, READY_AFTER_MS));
  if (exitDescription !== null) {
    result.status = 'unavailable';
    result.reason = `wrangler tail exited before the run started (${exitDescription}); check Cloudflare authentication`;
    return { stop: async () => result };
  }

  return {
    stop: async () => {
      await new Promise((resolve) => setTimeout(resolve, DRAIN_MS));
      stopping = true;
      await terminate(child);
      if (exitDescription !== null) {
        result.status = 'unavailable';
        result.reason = `wrangler tail stopped during the run (${exitDescription}); the scan is incomplete`;
      }
      return result;
    },
  };
}

async function terminate(child: ChildProcessByStdio<null, Readable, Readable>): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 5_000);
  await exited;
  clearTimeout(timer);
}
