/**
 * Global live-revocation registry (spec §9.3): one SQLite-backed Durable Object
 * (named "global") holding revoked session IDs, revoked device IDs and a per-`sub`
 * minimum `iat`. Revocations are monotonic: nothing is ever un-revoked and a
 * minimum `iat` only moves forward, so a replayed webhook cannot weaken state.
 * Webhook event IDs are remembered past the signature time window to refuse replays.
 */
import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env.js';

/** A device-bound sync token: its session, its device and its age all apply. */
export interface RevocationQuery {
  sub: string;
  sid: string;
  did: string;
  iat: number;
}

/** An MCP access token: bound to a grant (`sid` = grant ID), never to a device. */
export interface GrantRevocationQuery {
  sub: string;
  sid: string;
  iat: number;
}

export interface RevocationBatch {
  event_id: string;
  revoke_sids: string[];
  revoke_dids: string[];
  min_iat: { sub: string; iat: number }[];
}

/** Webhook event IDs are kept longer than the ±300 s acceptance window. */
const EVENT_ID_TTL_MS = 15 * 60_000;

export class RevocationRegistry extends DurableObject<Env> {
  private readonly sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS revoked_sids (sid TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS revoked_dids (did TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS min_iat (sub TEXT PRIMARY KEY, min_iat INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS webhook_events (event_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS webhook_events_expiry ON webhook_events (expires_at);
    `);
  }

  /** True when the session, the device, or a token this old for `sub` is revoked. */
  isRevoked(q: RevocationQuery): boolean {
    if (this.sql.exec('SELECT 1 FROM revoked_sids WHERE sid = ?', q.sid).toArray().length > 0) return true;
    if (this.sql.exec('SELECT 1 FROM revoked_dids WHERE did = ?', q.did).toArray().length > 0) return true;
    return belowMinIat(this.sql, q.sub, q.iat);
  }

  /** True when the grant (`sid`) or a token this old for `sub` is revoked. No device applies. */
  isGrantRevoked(q: GrantRevocationQuery): boolean {
    if (this.sql.exec('SELECT 1 FROM revoked_sids WHERE sid = ?', q.sid).toArray().length > 0) return true;
    return belowMinIat(this.sql, q.sub, q.iat);
  }

  /** Apply a verified webhook batch atomically. Returns 'duplicate' for a replayed event ID. */
  applyBatch(batch: RevocationBatch, nowMs: number): 'applied' | 'duplicate' {
    return this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM webhook_events WHERE expires_at < ?', nowMs);
      if (this.sql.exec('SELECT 1 FROM webhook_events WHERE event_id = ?', batch.event_id).toArray().length > 0) return 'duplicate';
      this.sql.exec('INSERT INTO webhook_events (event_id, expires_at) VALUES (?, ?)', batch.event_id, nowMs + EVENT_ID_TTL_MS);
      for (const sid of batch.revoke_sids) this.sql.exec('INSERT OR IGNORE INTO revoked_sids (sid, revoked_at) VALUES (?, ?)', sid, nowMs);
      for (const did of batch.revoke_dids) this.sql.exec('INSERT OR IGNORE INTO revoked_dids (did, revoked_at) VALUES (?, ?)', did, nowMs);
      for (const { sub, iat } of batch.min_iat) {
        this.sql.exec(
          'INSERT INTO min_iat (sub, min_iat) VALUES (?, ?) ON CONFLICT (sub) DO UPDATE SET min_iat = MAX(min_iat, excluded.min_iat)',
          sub,
          iat,
        );
      }
      return 'applied';
    });
  }
}

/** Kept outside the class so it is not exposed as an RPC method. */
function belowMinIat(sql: SqlStorage, sub: string, iat: number): boolean {
  const row = sql.exec<{ min_iat: number }>('SELECT min_iat FROM min_iat WHERE sub = ?', sub).toArray()[0];
  return row !== undefined && iat < row.min_iat;
}
