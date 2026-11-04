/** Reads a vault object's in-memory rate counters (request-replay-state.ts) from a test. */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { replayStateFor } from '../../src/vault/request-replay-state.js';
import type { RateBucket } from '../../src/vault/request-guard.js';

export function rateCounters(vaultId: string, bucket: RateBucket): Promise<{ subject: string; windowStart: number; count: number }[]> {
  return runInDurableObject(env.VAULT.get(env.VAULT.idFromName(vaultId)), (instance: unknown) =>
    replayStateFor((instance as { sql: SqlStorage }).sql, Date.now()).rateEntries(`${bucket}\n`),
  );
}

export function setRateCounter(vaultId: string, bucket: RateBucket, subject: string, windowStart: number, count: number): Promise<void> {
  return runInDurableObject(env.VAULT.get(env.VAULT.idFromName(vaultId)), (instance: unknown) => {
    replayStateFor((instance as { sql: SqlStorage }).sql, Date.now()).setRate(`${bucket}\n${subject}`, { windowStart, count });
  });
}
