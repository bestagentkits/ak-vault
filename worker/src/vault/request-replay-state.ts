/**
 * Per-vault rate windows and burned proof `jti`s, kept in Durable Object memory so a
 * steady-state request writes no SQLite rows (rows written are the largest cost line,
 * docs/operations/cost-model.md).
 *
 * Single use of a proof `jti` (spec §9 item 2) must survive a restart, so storage holds
 * one session marker in `meta`:
 * - Before the first proof of a session is accepted, the marker is set to `active`
 *   (one row). Nothing is accepted before that write succeeds.
 * - After `IDLE_FLUSH_MS` without requests, a Durable Object alarm saves the live
 *   `jti`s and rate windows and sets the marker to `clean` (one row). An alarm, not a
 *   timer: a pending timer keeps the object awake and billed for duration.
 * - A start that finds `clean` reloads the saved `jti`s and windows. A start that finds
 *   `active` (the object stopped while it was serving, so `jti`s accepted since the
 *   last save are lost) refuses every proof whose `ts` is earlier than the start plus
 *   the clock skew. Any proof the earlier run accepted has such a `ts`, so none can be
 *   replayed; a client's next fresh proof after that point is accepted. Fail closed.
 *   That floor is saved at once (marker `clean` with `f`) and in every later marker, so
 *   a start after a run that accepted nothing keeps it rather than moving it forward;
 *   otherwise a vault woken only by short request bursts would refuse every proof.
 *
 * Rate windows lost by an unclean stop start again from zero: the budget is abuse
 * control, not an authorization rule, and the stop is not under a caller's control.
 */
import { LIMITS } from '../limits.js';

/** Idle time after which the session is saved and marked clean. Well below the platform's idle eviction. */
export const IDLE_FLUSH_MS = 10_000;
/** Saved entries above this stay unsaved; the marker then stays `active` and the next start fails closed. */
const MAX_SAVED_ENTRIES = 20_000;
const MARKER_KEY = 'request_replay_state';

export interface RateCounter {
  windowStart: number;
  count: number;
}

interface SavedState {
  s: 'active' | 'clean';
  /** [did, jti, expiresAt] */
  j?: [string, string, number][];
  /** [bucketKey, windowStart, count] */
  r?: [string, number, number][];
  /** Proofs with an earlier `ts` are refused (unix ms; set after an unclean stop). */
  f?: number;
}

export class RequestReplayState {
  private readonly jtis = new Map<string, number>();
  private readonly rates = new Map<string, RateCounter>();
  /** Proofs with an earlier `ts` are refused (non-zero only after an unclean stop). */
  private refuseProofsBeforeMs = 0;
  /** Whether storage currently says `active`. */
  private active = false;
  /** Last request that changed state; 0 in an object that has served none. */
  private lastActivityMs = 0;
  /** Whether a flush alarm is pending. */
  private flushScheduled = false;

  private constructor(
    private readonly sql: SqlStorage,
    private readonly scheduleFlush: (atMs: number) => void,
  ) {}

  /** Load the saved session; `nowMs` is the start time used for the unclean-stop floor. */
  static load(sql: SqlStorage, nowMs: number, scheduleFlush: (atMs: number) => void = () => undefined): RequestReplayState {
    const state = new RequestReplayState(sql, scheduleFlush);
    const row = sql.exec<{ v: string }>('SELECT v FROM meta WHERE k = ?', MARKER_KEY).toArray()[0];
    if (!row) return state;
    const saved = JSON.parse(row.v) as SavedState;
    state.refuseProofsBeforeMs = typeof saved.f === 'number' ? saved.f : 0;
    if (saved.s === 'active') {
      // `jti`s accepted since the last save are lost; every proof that run accepted has a
      // `ts` before this start plus the skew. The floor is saved at once with a clean
      // marker, so a later start keeps it instead of moving it forward again: a start
      // that accepted nothing before the next stop must not refuse fresh proofs anew.
      state.refuseProofsBeforeMs = Math.max(state.refuseProofsBeforeMs, nowMs + LIMITS.clock_skew_seconds * 1000);
      state.write({ s: 'clean', f: state.refuseProofsBeforeMs });
      return state;
    }
    for (const [did, jti, exp] of saved.j ?? []) if (exp >= nowMs) state.jtis.set(jtiKey(did, jti), exp);
    for (const [key, windowStart, count] of saved.r ?? []) state.rates.set(key, { windowStart, count });
    return state;
  }

  rate(key: string): RateCounter | undefined {
    return this.rates.get(key);
  }

  setRate(key: string, counter: RateCounter): void {
    this.rates.set(key, counter);
    this.touch();
  }

  /** Counters of one bucket (`bucketPrefix` = bucket name + newline), for tests and diagnostics. */
  rateEntries(bucketPrefix: string): { subject: string; windowStart: number; count: number }[] {
    return [...this.rates].filter(([key]) => key.startsWith(bucketPrefix)).map(([key, c]) => ({ subject: key.slice(bucketPrefix.length), ...c }));
  }

  /** Drop every counter of `bucketPrefix` from windows before `windowStart`. */
  dropRatesBefore(bucketPrefix: string, windowStart: number): void {
    for (const [key, c] of this.rates) if (key.startsWith(bucketPrefix) && c.windowStart < windowStart) this.rates.delete(key);
  }

  /**
   * The floor a proof's `ts` falls under after an unclean stop (it may have been accepted
   * before the stop), or 0. The client's next fresh proof made at or after it is served.
   */
  refusedUntil(proofTsMs: number): number {
    return proofTsMs < this.refuseProofsBeforeMs ? this.refuseProofsBeforeMs : 0;
  }

  /** True when this proof's `jti` was already accepted and is still live. */
  isReplay(did: string, jti: string, nowMs: number): boolean {
    const exp = this.jtis.get(jtiKey(did, jti));
    return exp !== undefined && exp >= nowMs;
  }

  /** Burn a `jti`. Persists the `active` marker first when the session is not yet marked. */
  burn(did: string, jti: string, nowMs: number): void {
    if (!this.active) {
      this.write({ s: 'active', ...this.floor() });
      this.active = true;
    }
    for (const [key, exp] of this.jtis) if (exp < nowMs) this.jtis.delete(key);
    this.jtis.set(jtiKey(did, jti), nowMs + LIMITS.proof_jti_ttl_seconds * 1000);
    this.touch();
  }

  /** The flush alarm fired: save when idle long enough, otherwise wait for the idle point. */
  onFlushAlarm(nowMs: number): void {
    this.flushScheduled = false;
    if (!this.active) return;
    const due = this.lastActivityMs + IDLE_FLUSH_MS;
    if (nowMs < due) return this.schedule(due);
    this.flush(nowMs);
  }

  /**
   * Save live entries and mark the session clean. Kept `active` (fail closed) if too large.
   * The unclean-stop floor is saved with it, so it keeps refusing the lost run's proofs.
   */
  flush(nowMs: number): void {
    if (!this.active) return;
    const j: [string, string, number][] = [];
    for (const [key, exp] of this.jtis) {
      if (exp < nowMs) continue;
      const [did, jti] = key.split('\n') as [string, string];
      j.push([did, jti, exp]);
    }
    const r: [string, number, number][] = [...this.rates].map(([key, c]) => [key, c.windowStart, c.count]);
    if (j.length + r.length > MAX_SAVED_ENTRIES) return;
    this.write({ s: 'clean', j, r, ...this.floor() });
    this.active = false;
  }

  /** The floor to save; omitted when there is none. */
  private floor(): Pick<SavedState, 'f'> {
    return this.refuseProofsBeforeMs > 0 ? { f: this.refuseProofsBeforeMs } : {};
  }

  private touch(): void {
    this.lastActivityMs = Date.now();
    if (this.active && !this.flushScheduled) this.schedule(this.lastActivityMs + IDLE_FLUSH_MS);
  }

  /** The flush alarm could not be set: the next request schedules it again. */
  flushNotScheduled(): void {
    this.flushScheduled = false;
  }

  private schedule(atMs: number): void {
    this.scheduleFlush(atMs);
    this.flushScheduled = true;
  }

  private write(saved: SavedState): void {
    this.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v', MARKER_KEY, JSON.stringify(saved));
  }
}

function jtiKey(did: string, jti: string): string {
  return `${did}\n${jti}`;
}

const states = new WeakMap<SqlStorage, RequestReplayState>();
const schedulers = new WeakMap<SqlStorage, (atMs: number) => void>();

/** Register how a vault object schedules the flush alarm for its storage. */
export function setReplayFlushScheduler(sql: SqlStorage, scheduleFlush: (atMs: number) => void): void {
  schedulers.set(sql, scheduleFlush);
}

/** The state for a vault object's storage, loaded on first use (after its schema exists). */
export function replayStateFor(sql: SqlStorage, nowMs: number): RequestReplayState {
  let state = states.get(sql);
  if (!state) {
    state = RequestReplayState.load(sql, nowMs, schedulers.get(sql));
    states.set(sql, state);
  }
  return state;
}
