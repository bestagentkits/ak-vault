/**
 * One relay Durable Object per account (`acct:<sub>`, spec §9.7, ADR 0002 D4).
 *
 * Devices hold `GET /v1/relay` open through the WebSocket hibernation API. The
 * Worker authenticates the upgrade (token, session kind, scopes, revocation,
 * device key) and hands it here; this object burns the proof `jti`, enforces
 * `relay_devices_per_account`, replaces an older connection of the same device
 * (4409), verifies `hello` against every listed vault's membership, takes
 * `reauth` before the token expires, and relays MCP calls to the newest eligible
 * device, re-checking revocation and membership before each call. It also keeps
 * the per-client MCP rate budgets and a 30-day operational audit (failure and success
 * rows capped separately) of hashed client IDs, tools, outcomes and latency.
 *
 * Frames, arguments and results are never logged or stored: arguments may carry a
 * `set` value and results carry names and metadata in transit (ADR 0002 D7).
 */
import { DurableObject } from 'cloudflare:workers';
import {
  RELAY_TOOLS,
  TOOL_SCOPE,
  b64encode,
  cjson,
  isAkvError,
  parseRelayFrame,
  parseRelayFrameObject,
  parseToolArgs,
  parseToolResult,
  randomBytes,
  verifyHello,
  verifyResult,
  type HelloFrame,
  type JsonObject,
  type ReauthFrame,
  type RelayTool,
  type ResultFrame,
  type Role,
} from '@ak-vault/protocol';
import { verifyToken } from '../auth/jwt-verify.js';
import { isDeviceRevoked } from '../auth/revocation-check.js';
import type { Env } from '../env.js';
import { ApiError, errorResult } from '../http/errors.js';
import { logRelayEvent } from '../http/operational-logger.js';
import { resultResponse } from '../http/responses.js';
import { REMOTE_ACCESS_LIMITS } from '../limits.js';
import type { RateDecision, RelayAuditEntry, RelayCall, RelayOutcome } from './relay-rpc.js';
import {
  CLOSE,
  CLOSE_REASON,
  RELAY_OPEN_HEADER,
  decodeRelayOpen,
  frameBytes,
  relaySessionRefusal,
  verifyRelayProof,
  type CloseCode,
  type Connection,
} from './relay-session.js';

const L = REMOTE_ACCESS_LIMITS;
/** Transit allowance on top of the device's `deadline_ms` before a call times out. */
const DEADLINE_GRACE_MS = 2_000;
const AUDIT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
/** Failure rows (every outcome but a success) kept per account; successes never count against it, so recent failure evidence survives any number of successful calls. */
export const AUDIT_MAX_ROWS = 20_000;
/** Successful rows kept per account; they otherwise keep the full retention window. */
export const AUDIT_MAX_SUCCESS_ROWS = 100_000;
/** Inserts between audit prunes (and one gated prune when the object starts), so a full table is not counted on every call. */
export const AUDIT_PRUNE_EVERY = 256;
/** Outcomes of a tool that ran (`ok`) or whose write was sealed and queued (`queued`). */
const AUDIT_SUCCESS_OUTCOMES: readonly string[] = ['ok', 'queued'];

/**
 * Create the audit table and bring an older one up to date: rows written before the
 * `success` class column existed get it added and backfilled, then the indexes exist.
 */
export function ensureAuditSchema(storage: DurableObjectStorage): void {
  const sql = storage.sql;
  sql.exec('CREATE TABLE IF NOT EXISTS client_audit (ts INTEGER NOT NULL, client_hash TEXT NOT NULL, tool TEXT NOT NULL, outcome TEXT NOT NULL, ms INTEGER NOT NULL, success INTEGER NOT NULL DEFAULT 0)');
  if (!sql.exec<{ name: string }>('PRAGMA table_info(client_audit)').toArray().some((c) => c.name === 'success')) {
    storage.transactionSync(() => {
      sql.exec('ALTER TABLE client_audit ADD COLUMN success INTEGER NOT NULL DEFAULT 0');
      sql.exec(`UPDATE client_audit SET success = 1 WHERE outcome IN (${AUDIT_SUCCESS_OUTCOMES.map((o) => `'${o}'`).join(', ')})`);
    });
  }
  sql.exec('CREATE INDEX IF NOT EXISTS client_audit_ts ON client_audit (ts)');
  sql.exec('CREATE INDEX IF NOT EXISTS client_audit_class_ts ON client_audit (success, ts)');
}
const AUDIT_CAPS = [[0, AUDIT_MAX_ROWS], [1, AUDIT_MAX_SUCCESS_ROWS]] as const;
const RATE_WINDOW_MS = 60_000;
const WRITE_TOOLS: ReadonlySet<RelayTool> = new Set<RelayTool>(['set', 'delete']);

interface PendingCall {
  cid: string;
  tool: RelayTool;
  deviceId: string;
  deadlineAt: number;
  timer: ReturnType<typeof setTimeout>;
  resolve: (outcome: RelayOutcome) => void;
}

export class AccountRelay extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  /** Outstanding calls by `call_id`; in memory only, as a call keeps the object awake until it settles. */
  private readonly pending = new Map<string, PendingCall>();
  /** Audit inserts since the object started; drives the periodic prune. */
  private auditInserts = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS proof_jti (did TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (did, jti));
      CREATE INDEX IF NOT EXISTS proof_jti_expiry ON proof_jti (expires_at);
      CREATE TABLE IF NOT EXISTS client_rate (bucket TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL);
    `);
    ensureAuditSchema(ctx.storage);
    this.pruneAuditIfOverCap();
  }

  // ---------------------------------------------------------------- upgrade

  /** Accept a device connection the Worker already authenticated (see `handleRelayUpgrade`). */
  override async fetch(request: Request): Promise<Response> {
    const open = decodeRelayOpen(request.headers.get(RELAY_OPEN_HEADER));
    if (!open || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return refuse('bad_request');
    const now = Date.now();
    if (!verifyRelayProof(this.sql, { proof: open.proof, token: open.token, htu: open.htu, did: open.did, signPub: open.signPub, nowMs: now })) return refuse('unauthorized');
    const sockets = this.openSockets();
    const others = sockets.filter(([, c]) => c.did !== open.did);
    if (others.length >= L.relay_devices_per_account) return refuse('rate_limited');
    for (const [ws, c] of sockets) if (c.did === open.did) this.close(ws, c, CLOSE.replaced);

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.ctx.acceptWebSocket(server);
    const conn: Connection = {
      cid: b64encode(randomBytes(16)),
      sub: open.sub,
      did: open.did,
      signPub: open.signPub,
      sid: open.sid,
      iat: open.iat,
      exp: open.exp,
      htu: open.htu,
      connectedAt: now,
      hello: 'none',
      helloAt: 0,
      vaults: [],
      tools: [],
      reauths: 0,
      reauthWindowEnd: 0,
      unsolicited: 0,
    };
    server.serializeAttachment(conn);
    await this.scheduleAlarm();
    return new Response(null, { status: 101, webSocket: client });
  }

  // ---------------------------------------------------------------- frames

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const conn = this.connection(ws);
    if (!conn) return;
    let frame;
    try {
      frame = parseRelayFrame(typeof message === 'string' ? message : new Uint8Array(message), { maxBytes: L.relay_frame_max_bytes });
    } catch {
      this.close(ws, conn, CLOSE.badFrame);
      return;
    }
    try {
      if (frame.type === 'hello') await this.onHello(ws, conn, frame);
      else if (frame.type === 'reauth') await this.onReauth(ws, conn, frame);
      else if (frame.type === 'result') this.onResult(ws, conn, frame);
      else this.close(ws, conn, CLOSE.badFrame); // `ready` and `call` only travel server -> device
    } catch {
      // A membership or revocation lookup failed: fail closed without guessing a cause.
      this.close(ws, this.connection(ws) ?? conn, CLOSE.internal);
    }
  }

  override async webSocketClose(ws: WebSocket): Promise<void> {
    const conn = this.connection(ws);
    if (conn) this.settleConnection(conn.cid);
    try {
      ws.close(1000, 'closed');
    } catch {
      // already closed
    }
    await this.scheduleAlarm();
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws);
  }

  private async onHello(ws: WebSocket, conn: Connection, frame: HelloFrame): Promise<void> {
    const now = Date.now();
    if (conn.hello !== 'none' || now > conn.connectedAt + L.relay_hello_timeout_ms) return this.close(ws, conn, CLOSE.badFrame);
    try {
      verifyHello(frame, { signPub: conn.signPub, now });
    } catch (err) {
      return this.close(ws, conn, isAkvError(err) && err.code === 'forbidden' ? CLOSE.forbidden : CLOSE.badFrame);
    }
    if (frame.device_id !== conn.did) return this.close(ws, conn, CLOSE.forbidden);
    this.save(ws, { ...conn, hello: 'pending' });
    const roles = await Promise.all(frame.vaults.map((vid) => this.deviceRole(vid, conn)));
    const current = this.connection(ws);
    if (!current || current.cid !== conn.cid || !this.isOpen(ws)) return;
    if (roles.some((r) => r === null)) return this.close(ws, current, CLOSE.forbidden);
    this.save(ws, { ...current, hello: 'ready', helloAt: Date.now(), vaults: [...frame.vaults], tools: [...frame.tools] });
    this.sendReady(ws, current.exp);
  }

  private async onReauth(ws: WebSocket, conn: Connection, frame: ReauthFrame): Promise<void> {
    const now = Date.now();
    // `reauth` MUST arrive before the token in force expires (spec §9.7); the alarm
    // may fire late, so a late frame cannot revive the connection.
    if (!live(conn, now)) return this.close(ws, conn, CLOSE.unauthorized);
    if (conn.hello !== 'ready') return this.close(ws, conn, CLOSE.badFrame);
    const windowOpen = now < conn.reauthWindowEnd;
    const reauths = (windowOpen ? conn.reauths : 0) + 1;
    if (reauths > L.relay_reauth_per_token_lifetime) return this.close(ws, conn, CLOSE.tooFast);
    const reauthWindowEnd = windowOpen ? conn.reauthWindowEnd : now + Math.max(1, conn.exp - conn.iat) * 1000;
    this.save(ws, { ...conn, reauths, reauthWindowEnd });

    let claims;
    try {
      claims = await verifyToken(frame.token, this.env, now);
    } catch {
      return this.closeCurrent(ws, conn.cid, CLOSE.unauthorized);
    }
    if (claims.sub !== conn.sub || claims.did !== conn.did) return this.closeCurrent(ws, conn.cid, CLOSE.unauthorized);
    if (relaySessionRefusal(claims)) return this.closeCurrent(ws, conn.cid, CLOSE.forbidden);
    if (await isDeviceRevoked(this.env, claims)) return this.closeCurrent(ws, conn.cid, CLOSE.unauthorized);
    if (!verifyRelayProof(this.sql, { proof: frame.proof, token: frame.token, htu: conn.htu, did: conn.did, signPub: conn.signPub, nowMs: now })) {
      return this.closeCurrent(ws, conn.cid, CLOSE.unauthorized);
    }
    const roles = await Promise.all(conn.vaults.map(async (vid) => [vid, await this.deviceRole(vid, conn)] as const));
    const current = this.connection(ws);
    if (!current || current.cid !== conn.cid || !this.isOpen(ws)) return;
    const vaults = roles.filter(([, role]) => role !== null).map(([vid]) => vid);
    if (vaults.length === 0) return this.close(ws, current, CLOSE.forbidden);
    this.save(ws, { ...current, sid: claims.sid, iat: claims.iat, exp: claims.exp, vaults });
    this.sendReady(ws, claims.exp);
    await this.scheduleAlarm();
  }

  private onResult(ws: WebSocket, conn: Connection, frame: ResultFrame): void {
    if (conn.hello !== 'ready') return this.close(ws, conn, CLOSE.badFrame);
    const call = this.pending.get(frame.call_id);
    let verified = false;
    if (call && call.cid === conn.cid && Date.now() <= call.deadlineAt) {
      try {
        verifyResult(frame, conn.signPub);
        verified = true;
      } catch {
        // dropped like an unknown call_id
      }
    }
    if (!call || !verified) {
      const unsolicited = conn.unsolicited + 1;
      if (unsolicited > L.relay_calls_inflight_per_device) return this.close(ws, conn, CLOSE.tooFast);
      this.save(ws, { ...conn, unsolicited });
      return;
    }
    if (conn.unsolicited !== 0) this.save(ws, { ...conn, unsolicited: 0 });
    if (!frame.ok) return this.settle(frame.call_id, { kind: 'result', ok: false, code: frame.error.code, deviceId: call.deviceId });
    try {
      parseToolResult(call.tool, frame.result);
    } catch {
      return this.settle(frame.call_id, { kind: 'result', ok: false, code: 'internal', deviceId: call.deviceId });
    }
    this.settle(frame.call_id, { kind: 'result', ok: true, result: frame.result, deviceId: call.deviceId });
  }

  // ---------------------------------------------------------------- RPC

  /** Vault IDs announced by the account's online devices, sorted. */
  async knownVaults(): Promise<string[]> {
    const vaults = new Set<string>();
    const now = Date.now();
    for (const [, c] of this.openSockets()) if (c.hello === 'ready' && live(c, now)) for (const v of c.vaults) vaults.add(v);
    return [...vaults].sort();
  }

  /**
   * Relay one MCP tool call to an online device of this account (spec §9.7). Throws
   * when the revocation registry or a vault object cannot answer (fail closed).
   */
  async dispatch(call: RelayCall): Promise<RelayOutcome> {
    const tool = call.tool;
    if (!(RELAY_TOOLS as readonly string[]).includes(tool) || !Number.isSafeInteger(call.deadlineMs) || call.deadlineMs < 1) return { kind: 'invalid_args' };
    try {
      parseToolArgs(tool, call.args);
    } catch {
      return { kind: 'invalid_args' };
    }
    if (!Array.isArray(call.caller?.scopes) || !call.caller.scopes.includes(TOOL_SCOPE[tool])) return { kind: 'denied' };

    // Between `exp` and the alarm firing, a connection whose token expired is not eligible.
    const now = Date.now();
    const ready = this.openSockets().filter(([, c]) => c.hello === 'ready' && live(c, now));
    let vaultId = call.vaultId;
    if (vaultId === undefined) {
      const known = new Set(ready.flatMap(([, c]) => c.vaults));
      if (known.size === 0) return { kind: 'no_device_online' };
      if (known.size > 1) return { kind: 'invalid_args' };
      vaultId = [...known][0]!;
    }
    const candidates = ready
      .filter(([, c]) => c.vaults.includes(vaultId) && c.tools.includes(tool))
      .sort(([, a], [, b]) => b.helloAt - a.helloAt);
    let busy = false;
    for (const [ws, initial] of candidates) {
      if (this.inflight(initial.cid) >= L.relay_calls_inflight_per_device) {
        busy = true;
        continue;
      }
      if (await isDeviceRevoked(this.env, initial)) {
        this.closeCurrent(ws, initial.cid, CLOSE.unauthorized);
        continue;
      }
      const role = await this.deviceRole(vaultId, initial);
      const conn = this.connection(ws);
      // The lookups above awaited: the token in force may have expired meanwhile.
      if (!conn || conn.cid !== initial.cid || !this.isOpen(ws) || !live(conn, Date.now())) continue;
      if (role === null) {
        const vaults = conn.vaults.filter((v) => v !== vaultId);
        if (vaults.length === 0) this.close(ws, conn, CLOSE.forbidden);
        else this.save(ws, { ...conn, vaults });
        continue;
      }
      if (WRITE_TOOLS.has(tool) && role !== 'owner' && role !== 'editor') continue;
      if (this.inflight(conn.cid) >= L.relay_calls_inflight_per_device) {
        busy = true;
        continue;
      }
      return this.send(ws, conn, vaultId, call);
    }
    return busy ? { kind: 'device_busy' } : { kind: 'no_device_online' };
  }

  /**
   * Take one MCP request from the client's budgets: per (account, client), per
   * (account, client) for `run`, and per account, each a one-minute window. `tool` is
   * null for a request that runs no tool (`tools/list`, `ping`, a refused call). A
   * refused request spends nothing. An invalid client ID or tool is refused without
   * `retryAfterS`.
   */
  async takeRate(clientId: string, tool: RelayTool | 'prepare_write' | null, nowMs: number = Date.now()): Promise<RateDecision> {
    if (typeof clientId !== 'string' || !/^[\x20-\x7e]{1,256}$/.test(clientId) || (tool !== null && tool !== 'prepare_write' && !(RELAY_TOOLS as readonly string[]).includes(tool))) {
      return { ok: false };
    }
    const window = Math.floor(nowMs / RATE_WINDOW_MS);
    const buckets: [string, number][] = [
      [`client:${clientId}`, L.mcp_calls_per_minute_per_client],
      ['account', L.mcp_calls_per_minute_per_account],
    ];
    if (tool === 'run') buckets.push([`run:${clientId}`, L.mcp_run_calls_per_minute_per_client]);
    if (tool === 'prepare_write') buckets.push([`prepare:${clientId}`, L.mcp_prepare_write_per_minute_per_client]);
    return this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM client_rate WHERE window < ?', window);
      const counts = buckets.map(([bucket]) => this.sql.exec<{ count: number }>('SELECT count FROM client_rate WHERE bucket = ? AND window = ?', bucket, window).toArray()[0]?.count ?? 0);
      if (buckets.some(([, limit], i) => counts[i]! >= limit)) {
        return { ok: false, retryAfterS: Math.max(1, Math.ceil(((window + 1) * RATE_WINDOW_MS - nowMs) / 1000)) };
      }
      buckets.forEach(([bucket], i) => {
        this.sql.exec(
          'INSERT INTO client_rate (bucket, window, count) VALUES (?, ?, ?) ON CONFLICT (bucket) DO UPDATE SET window = excluded.window, count = excluded.count',
          bucket,
          window,
          counts[i]! + 1,
        );
      });
      return { ok: true };
    });
  }

  /**
   * Append one operational audit row (hashed client, tool, outcome, latency); rows
   * older than 30 days are dropped. Failure and success rows are capped separately
   * (see `pruneAudit`), checked every `AUDIT_PRUNE_EVERY` inserts. False, storing
   * nothing, for an invalid entry.
   */
  async recordAudit(e: RelayAuditEntry, nowMs: number = Date.now()): Promise<boolean> {
    if (
      typeof e?.clientHash !== 'string' ||
      !/^[0-9a-f]{16,64}$/.test(e.clientHash) ||
      !(RELAY_TOOLS as readonly string[]).includes(e.tool) ||
      typeof e.outcome !== 'string' ||
      !/^[a-z_]{1,32}$/.test(e.outcome) ||
      !Number.isSafeInteger(e.ms) ||
      e.ms < 0
    ) {
      return false;
    }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM client_audit WHERE ts < ?', nowMs - AUDIT_RETENTION_MS);
      this.sql.exec('INSERT INTO client_audit (ts, client_hash, tool, outcome, ms, success) VALUES (?, ?, ?, ?, ?, ?)', nowMs, e.clientHash, e.tool, e.outcome, e.ms, AUDIT_SUCCESS_OUTCOMES.includes(e.outcome) ? 1 : 0);
      if (++this.auditInserts % AUDIT_PRUNE_EVERY === 0) this.pruneAudit();
    });
    return true;
  }

  /**
   * Trim each audit class to its own cap, newest rows kept: the cutoff is the first row
   * past the cap in (ts, rowid) order, found and deleted through `client_audit_class_ts`.
   * A token holder who spams `AUDIT_MAX_SUCCESS_ROWS` successful calls can still roll the
   * success history; that is accepted, because every one of those calls is itself recorded.
   */
  private pruneAudit(caps: readonly (readonly [0 | 1, number])[] = AUDIT_CAPS): void {
    for (const [success, cap] of caps) {
      const edge = this.sql.exec<{ ts: number; id: number }>('SELECT ts, rowid AS id FROM client_audit WHERE success = ? ORDER BY ts DESC, rowid DESC LIMIT 1 OFFSET ?', success, cap).toArray()[0];
      if (edge) this.sql.exec('DELETE FROM client_audit WHERE success = ? AND ts <= ? AND (ts < ? OR rowid <= ?)', success, edge.ts, edge.ts, edge.id);
    }
  }

  /**
   * The prune for an object waking from hibernation, where the insert counter restarts
   * from zero. Rowids are distinct integers, so the table holds at most `MAX(rowid) -
   * MIN(rowid) + 1` rows, read from the two ends of the table b-tree without a scan. A
   * class whose cap that bound cannot exceed is skipped; only a class that might be over
   * pays for the `OFFSET` walk. A table that is mostly successes thus skips the 100k walk.
   */
  private pruneAuditIfOverCap(): void {
    const span = this.sql.exec<{ span: number | null }>('SELECT MAX(rowid) - MIN(rowid) + 1 AS span FROM client_audit').one().span;
    if (span === null) return;
    this.pruneAudit(AUDIT_CAPS.filter(([, cap]) => span > cap));
  }

  // ---------------------------------------------------------------- alarm

  /** Close connections whose `hello` is overdue (4400) or whose token expired without `reauth` (4401). */
  override async alarm(): Promise<void> {
    const now = Date.now();
    for (const [ws, c] of this.openSockets()) {
      if (!live(c, now)) this.close(ws, c, CLOSE.unauthorized);
      else if (c.hello !== 'ready' && now >= c.connectedAt + L.relay_hello_timeout_ms) this.close(ws, c, CLOSE.badFrame);
    }
    await this.scheduleAlarm();
  }

  private async scheduleAlarm(): Promise<void> {
    let next = Number.POSITIVE_INFINITY;
    for (const [, c] of this.openSockets()) {
      next = Math.min(next, c.exp * 1000);
      if (c.hello !== 'ready') next = Math.min(next, c.connectedAt + L.relay_hello_timeout_ms);
    }
    if (next === Number.POSITIVE_INFINITY) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(next);
  }

  // ---------------------------------------------------------------- helpers

  private send(ws: WebSocket, conn: Connection, vaultId: string, call: RelayCall): Promise<RelayOutcome> {
    const maxDeadline = call.tool === 'run' ? L.relay_run_deadline_ms : L.relay_call_deadline_ms;
    const deadline = Math.min(call.deadlineMs, maxDeadline);
    const callId = b64encode(randomBytes(16));
    let text: string;
    try {
      const frame = parseRelayFrameObject({
        v: 1,
        type: 'call',
        call_id: callId,
        vault_id: vaultId,
        tool: call.tool,
        args: call.args,
        caller: { client_id: call.caller.clientId, grant_id: call.caller.grantId, scopes: call.caller.scopes },
        deadline_ms: deadline,
      });
      text = cjson(frame as unknown as JsonObject);
    } catch {
      return Promise.resolve({ kind: 'invalid_args' });
    }
    if (frameBytes(text) > L.relay_frame_max_bytes) return Promise.resolve({ kind: 'invalid_args' });
    return new Promise<RelayOutcome>((resolve) => {
      const deadlineAt = Date.now() + deadline + DEADLINE_GRACE_MS;
      const timer = setTimeout(() => this.settle(callId, { kind: 'timeout' }), deadline + DEADLINE_GRACE_MS);
      this.pending.set(callId, { cid: conn.cid, tool: call.tool, deviceId: conn.did, deadlineAt, timer, resolve });
      try {
        ws.send(text);
      } catch {
        this.settle(callId, { kind: 'timeout' });
      }
    });
  }

  private settle(callId: string, outcome: RelayOutcome): void {
    const call = this.pending.get(callId);
    if (!call) return;
    this.pending.delete(callId);
    clearTimeout(call.timer);
    call.resolve(outcome);
  }

  /** A connection ended: its outstanding calls have an unknown outcome. */
  private settleConnection(cid: string): void {
    for (const [callId, call] of this.pending) if (call.cid === cid) this.settle(callId, { kind: 'timeout' });
  }

  private inflight(cid: string): number {
    let n = 0;
    for (const call of this.pending.values()) if (call.cid === cid) n++;
    return n;
  }

  /** The device's role in `vaultId` when it is still a current human device of the account with this key. */
  private deviceRole(vaultId: string, conn: Connection): Promise<Role | null> {
    const stub = this.env.VAULT.get(this.env.VAULT.idFromName(vaultId));
    return stub.memberDeviceRole(conn.did, conn.sub, conn.signPub);
  }

  private sendReady(ws: WebSocket, exp: number): void {
    try {
      ws.send(cjson({ v: 1, type: 'ready', exp }));
    } catch {
      // the socket closed meanwhile; webSocketClose cleans up
    }
  }

  private connection(ws: WebSocket): Connection | null {
    try {
      return (ws.deserializeAttachment() as Connection | null) ?? null;
    } catch {
      return null;
    }
  }

  private save(ws: WebSocket, conn: Connection): void {
    ws.serializeAttachment(conn);
  }

  private isOpen(ws: WebSocket): boolean {
    return ws.readyState === WebSocket.OPEN;
  }

  private openSockets(): [WebSocket, Connection][] {
    const out: [WebSocket, Connection][] = [];
    for (const ws of this.ctx.getWebSockets()) {
      const conn = this.connection(ws);
      if (conn && this.isOpen(ws)) out.push([ws, conn]);
    }
    return out;
  }

  /** Close only if `ws` still carries connection `cid` (state may change across awaits). */
  private closeCurrent(ws: WebSocket, cid: string, code: CloseCode): void {
    const conn = this.connection(ws);
    if (conn && conn.cid === cid) this.close(ws, conn, code);
  }

  private close(ws: WebSocket, conn: Connection, code: CloseCode): void {
    this.settleConnection(conn.cid);
    try {
      ws.close(code, CLOSE_REASON[code]);
    } catch {
      // already closing
    }
    logRelayEvent({ event: 'close', code, sub: conn.sub });
  }
}

/** The connection's token in force has not expired. */
function live(conn: Connection, nowMs: number): boolean {
  return nowMs < conn.exp * 1000;
}

function refuse(code: 'bad_request' | 'unauthorized' | 'rate_limited'): Response {
  return resultResponse(errorResult(new ApiError(code)));
}
