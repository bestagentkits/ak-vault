/**
 * Single-use proof `jti` bookkeeping (spec §9) and the per-device rate window.
 *
 * Replay state is one row per device holding that device's unexpired `jti`s, so a
 * verified request rewrites one existing row and prunes expired entries in the
 * same write: no insert, no per-request delete, no secondary index. Reads are
 * served from memory once a device is loaded. The rate window is memory only: it
 * caps abuse and a restart empties it, which never relaxes authentication.
 */
import { LIMITS } from '../limits.js';

type JtiExpiries = Map<string, number>;

/** Bound on devices held in memory; storage still holds every device's row. */
const MAX_CACHED_DEVICES = 512;

export class ProofReplayStore {
  private readonly cache = new Map<string, JtiExpiries>();
  /** Latest expiry in the legacy per-jti table, read once; null until first use. */
  private legacyUntilMs: number | null = null;

  constructor(private readonly sql: SqlStorage) {}

  private load(did: string): JtiExpiries {
    const hit = this.cache.get(did);
    if (hit) return hit;
    const row = this.sql.exec<{ jtis: string }>('SELECT jtis FROM proof_seen WHERE did = ?', did).toArray()[0];
    const entries = new Map<string, number>(row ? (JSON.parse(row.jtis) as [string, number][]) : []);
    if (this.cache.size >= MAX_CACHED_DEVICES) this.cache.clear();
    this.cache.set(did, entries);
    return entries;
  }

  /**
   * Vaults created before per-device rows kept one row per `jti` in `proof_jti`. A
   * proof accepted just before an upgrade must still be refused until it expires.
   */
  private legacyHas(did: string, jti: string, nowMs: number): boolean {
    if (this.legacyUntilMs === null) {
      const exists = this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'proof_jti'").toArray().length > 0;
      this.legacyUntilMs = exists ? (this.sql.exec<{ m: number | null }>('SELECT MAX(expires_at) AS m FROM proof_jti').one().m ?? 0) : 0;
    }
    if (nowMs > this.legacyUntilMs) return false;
    return this.sql.exec('SELECT 1 FROM proof_jti WHERE did = ? AND jti = ? AND expires_at >= ?', did, jti, nowMs).toArray().length > 0;
  }

  isReplay(did: string, jti: string, nowMs: number): boolean {
    const expiresAt = this.load(did).get(jti);
    if (expiresAt !== undefined && expiresAt >= nowMs) return true;
    return this.legacyHas(did, jti, nowMs);
  }

  /** Remember `jti` until its single-use window ends; one row write. */
  burn(did: string, jti: string, nowMs: number): void {
    const entries = this.load(did);
    for (const [seen, expiresAt] of entries) if (expiresAt < nowMs) entries.delete(seen);
    entries.set(jti, nowMs + LIMITS.proof_jti_ttl_seconds * 1000);
    this.sql.exec('INSERT INTO proof_seen (did, jtis) VALUES (?, ?) ON CONFLICT (did) DO UPDATE SET jtis = excluded.jtis', did, JSON.stringify([...entries]));
  }
}

interface RateWindow {
  windowStart: number;
  count: number;
}

export class RateLimiter {
  private readonly windows = new Map<string, RateWindow>();

  /** Count one request for `did`; returns the seconds to wait when over budget, else null. */
  hit(did: string, nowMs: number): number | null {
    const windowMs = LIMITS.rate_window_seconds * 1000;
    const windowStart = Math.floor(nowMs / windowMs) * windowMs;
    let w = this.windows.get(did);
    if (!w || w.windowStart !== windowStart) {
      if (this.windows.size >= MAX_CACHED_DEVICES) for (const [d, old] of this.windows) if (old.windowStart !== windowStart) this.windows.delete(d);
      w = { windowStart, count: 0 };
      this.windows.set(did, w);
    }
    w.count += 1;
    if (w.count <= LIMITS.rate_requests_per_window) return null;
    return Math.max(1, Math.ceil((windowStart + windowMs - nowMs) / 1000));
  }
}
