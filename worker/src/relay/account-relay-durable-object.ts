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
 * the per-client MCP rate budgets and a 30-day operational audit of hashed
 * client IDs, tools, outcomes and latency.
 *
 * Frames, arguments and results are never logged or stored: arguments may carry a
 * `set` value and results carry names and metadata in transit (ADR 0002 D7).
 */
import { DurableObject } from 'cloudflare:workers';
import {
  RELAY_TOOLS,
  TOOL_SCOPE,
  b64decodeLength,
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
import { isDeviceRevoked, isGrantRevoked } from '../auth/revocation-check.js';
import type { Env } from '../env.js';
import { ApiError, errorResult } from '../http/errors.js';
import { logRelayEvent } from '../http/operational-logger.js';
import { resultResponse } from '../http/responses.js';
import { REMOTE_ACCESS_LIMITS } from '../limits.js';
import type {
  IntentActionArgs,
  IntentActionResult,
  IntentStatusResult,
  PrepareIntentArgs,
  PrepareIntentResult,
  RateDecision,
  RelayAuditEntry,
  RelayCall,
  RelayOutcome,
} from './relay-rpc.js';
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
import {
  INTENT_SCHEMA,
  claim as claimIntent,
  getIntent,
  insertIntent,
  nextPurgeAt,
  openIntentCount,
  processingOverdue,
  purgeIntents,
  transition,
  type IntentRow,
  type IntentStatus,
} from './write-intent-store.js';

const L = REMOTE_ACCESS_LIMITS;
/** Transit allowance on top of the device's `deadline_ms` before a call times out. */
const DEADLINE_GRACE_MS = 2_000;
const AUDIT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
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

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS proof_jti (did TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (did, jti));
      CREATE INDEX IF NOT EXISTS proof_jti_expiry ON proof_jti (expires_at);
      CREATE TABLE IF NOT EXISTS client_rate (bucket TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS client_audit (ts INTEGER NOT NULL, client_hash TEXT NOT NULL, tool TEXT NOT NULL, outcome TEXT NOT NULL, ms INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS client_audit_ts ON client_audit (ts);
      ${INTENT_SCHEMA}
    `);
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
  async takeRate(clientId: string, tool: RelayTool | null, nowMs: number = Date.now()): Promise<RateDecision> {
    if (typeof clientId !== 'string' || !/^[\x20-\x7e]{1,256}$/.test(clientId) || (tool !== null && !(RELAY_TOOLS as readonly string[]).includes(tool))) {
      return { ok: false };
    }
    const window = Math.floor(nowMs / RATE_WINDOW_MS);
    const buckets: [string, number][] = [
      [`client:${clientId}`, L.mcp_calls_per_minute_per_client],
      ['account', L.mcp_calls_per_minute_per_account],
    ];
    if (tool === 'run') buckets.push([`run:${clientId}`, L.mcp_run_calls_per_minute_per_client]);
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
   * older than 30 days are dropped. False, storing nothing, for an invalid entry.
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
      this.sql.exec('INSERT INTO client_audit (ts, client_hash, tool, outcome, ms) VALUES (?, ?, ?, ?, ?)', nowMs, e.clientHash, e.tool, e.outcome, e.ms);
    });
    return true;
  }


  // ---------------------------------------------------------------- write requests

  /**
   * Record a human-only write request for a vault the Worker's MCP handler already
   * checked (membership, role, scope, seal key). The row binds the MCP grant and
   * client that asked; `target` is the sealed name. Open requests are capped per account.
   */
  async prepareWriteIntent(a: PrepareIntentArgs, nowMs: number = Date.now()): Promise<PrepareIntentResult> {
    if (
      !isId(a?.vaultId) ||
      typeof a.grantId !== 'string' ||
      a.grantId.length === 0 ||
      !Number.isSafeInteger(a.grantIat) ||
      typeof a.clientId !== 'string' ||
      a.clientId.length === 0 ||
      (a.op !== 'create' && a.op !== 'replace') ||
      (a.sensitivity !== undefined && a.sensitivity !== 'normal' && a.sensitivity !== 'high') ||
      typeof a.target !== 'object' ||
      a.target === null
    ) {
      return { ok: false, code: 'invalid' };
    }
    const target = JSON.stringify(a.target);
    const result = this.ctx.storage.transactionSync((): PrepareIntentResult => {
      purgeIntents(this.sql, nowMs);
      if (openIntentCount(this.sql, nowMs) >= L.write_intents_open_per_account || openIntentCount(this.sql, nowMs, a.clientId) >= L.write_intents_open_per_client) {
        return { ok: false, code: 'too_many_open' };
      }
      const requestId = b64encode(randomBytes(16));
      const expiresAt = nowMs + L.write_intent_ttl_s * 1000;
      insertIntent(this.sql, {
        rid: requestId,
        vault_id: a.vaultId,
        grant_id: a.grantId,
        grant_iat: a.grantIat,
        client_id: a.clientId,
        op: a.op,
        sensitivity: a.sensitivity ?? null,
        target,
        created_at: nowMs,
        expires_at: expiresAt,
      });
      return { ok: true, requestId, expiresAt };
    });
    if (result.ok) await this.scheduleAlarm();
    return result;
  }

  /**
   * Status of a request for the MCP client that created it. Null when the request is
   * unknown, purged, or was made by another grant or client (all answer alike).
   */
  async writeIntentStatus(a: { requestId: string; grantId: string; clientId: string }, nowMs: number = Date.now()): Promise<IntentStatusResult | null> {
    if (!isId(a?.requestId)) return null;
    const row = getIntent(this.sql, a.requestId);
    if (!row || row.grant_id !== a.grantId || row.client_id !== a.clientId) return null;
    const settled = await this.settleIntent(row, nowMs);
    return { status: settled.status, expiresAt: settled.expires_at };
  }

  /**
   * One browser call on a request (`view`, `claim`, `complete`, `fail`, `cancel`).
   * Order: request -> the device is a current owner or editor of the request's vault (its
   * enrolled key comes from there) -> proof (burns its `jti`) -> per-device rate -> the MCP
   * grant is still live -> settle by time and vault state -> the action, as a
   * compare-and-set on the status.
   * Every refusal is a stable code; nothing here sees a value or a name.
   */
  async writeIntentAction(a: IntentActionArgs, nowMs: number = Date.now()): Promise<IntentActionResult> {
    const refuse = (code: Extract<IntentActionResult, { ok: false }>['code'], extra?: Record<string, string | number | boolean>, status?: number): IntentActionResult => ({
      ok: false,
      code,
      ...(status === undefined ? {} : { status }),
      ...(extra ? { extra } : {}),
    });
    if (!isId(a?.rid)) return refuse('bad_request');
    const initial = getIntent(this.sql, a.rid);
    if (!initial) return refuse('not_found');

    // The device must be a current owner or editor device of the request's vault; its
    // proof is checked against the key the membership chain enrolled for it.
    const device = await this.env.VAULT.get(this.env.VAULT.idFromName(initial.vault_id)).memberDevice(a.did, a.sub);
    if (!device || (device.role !== 'owner' && device.role !== 'editor')) return refuse('forbidden');
    if (!verifyRelayProof(this.sql, { proof: a.proof, token: a.token, htu: a.htu, did: a.did, signPub: device.signPub, nowMs, htm: a.htm, body: a.body })) return refuse('unauthorized');
    if (!this.takeIntentRate(a.did, nowMs)) return refuse('rate_limited');
    let revoked: boolean;
    try {
      revoked = await isGrantRevoked(this.env, { sub: a.sub, sid: initial.grant_id, iat: initial.grant_iat });
    } catch {
      return refuse('internal', undefined, 503);
    }
    if (revoked) {
      // The grant that asked is gone: nobody may finish what it asked for.
      this.ctx.storage.transactionSync(() => {
        transition(this.sql, initial.rid, 'pending_user', 'cancelled', nowMs);
        transition(this.sql, initial.rid, 'processing', 'cancelled', nowMs);
      });
      return refuse('unauthorized');
    }

    const row = await this.settleIntent(initial, nowMs);
    const view = (r: IntentRow) => ({ request_id: r.rid, status: r.status, expires_at: r.expires_at });
    const wrong = (r: IntentRow) => refuse('conflict', { status: r.status });
    const settledAs = (to: IntentStatus, from: IntentStatus): IntentActionResult => {
      const won = this.ctx.storage.transactionSync(() => transition(this.sql, row.rid, from, to, nowMs));
      const now = getIntent(this.sql, row.rid) ?? row;
      return won ? { ok: true, body: view(now) } : wrong(now);
    };

    switch (a.action) {
      case 'view': {
        if (row.status !== 'pending_user') return wrong(row);
        return {
          ok: true,
          body: { ...view(row), vault_id: row.vault_id, operation: row.op, ...(row.sensitivity ? { sensitivity: row.sensitivity } : {}), target: JSON.parse(row.target) as unknown },
        };
      }
      case 'cancel':
        return row.status === 'pending_user' ? settledAs('cancelled', 'pending_user') : wrong(row);
      case 'claim': {
        if (row.status !== 'pending_user') return wrong(row);
        if (!isId(a.itemId) || !Number.isSafeInteger(a.baseRevision) || (a.baseRevision as number) < 0) return refuse('bad_request');
        const base = a.baseRevision as number;
        let head;
        try {
          head = await this.env.VAULT.get(this.env.VAULT.idFromName(row.vault_id)).itemHead(a.itemId);
        } catch {
          return refuse('internal');
        }
        // The request binds the operation and the revision: a create needs a new item at 0,
        // a replace needs the live item exactly at the revision the browser read.
        const fits = row.op === 'create' ? head === null && base === 0 : head !== null && !head.tombstone && head.revision === base;
        if (!fits) {
          // The binding no longer holds: end the request as a conflict and refuse this claim.
          this.ctx.storage.transactionSync(() => transition(this.sql, row.rid, 'pending_user', 'conflict', nowMs));
          return wrong(getIntent(this.sql, row.rid) ?? row);
        }
        const won = this.ctx.storage.transactionSync(() => claimIntent(this.sql, row.rid, a.did, a.itemId as string, base, nowMs));
        if (!won) this.ctx.storage.transactionSync(() => transition(this.sql, row.rid, 'pending_user', 'conflict', nowMs));
        const now = getIntent(this.sql, row.rid) ?? row;
        return won ? { ok: true, body: view(now) } : wrong(now);
      }
      case 'complete':
        if (row.status === 'completed') return row.did === a.did ? { ok: true, body: view(row) } : refuse('forbidden');
        if (row.status !== 'processing') return wrong(row);
        return row.did === a.did ? { ok: true, body: view(row) } : refuse('forbidden');
      case 'fail': {
        if (row.status === 'completed') return row.did === a.did ? { ok: true, body: view(row) } : refuse('forbidden');
        const to: IntentStatus = a.reason === 'conflict' ? 'conflict' : 'failed';
        if (row.status === 'pending_user') return settledAs(to, 'pending_user');
        if (row.status !== 'processing') return wrong(row);
        if (row.did !== a.did) return refuse('forbidden');
        return settledAs(to, 'processing');
      }
    }
  }

  /** Per-device budget for `/v1/write-intents/*`; a refused call spends nothing. */
  private takeIntentRate(did: string, nowMs: number): boolean {
    const window = Math.floor(nowMs / RATE_WINDOW_MS);
    const bucket = `intent:${did}`;
    return this.ctx.storage.transactionSync(() => {
      const count = this.sql.exec<{ count: number }>('SELECT count FROM client_rate WHERE bucket = ? AND window = ?', bucket, window).toArray()[0]?.count ?? 0;
      if (count >= L.write_intent_calls_per_minute_per_device) return false;
      this.sql.exec('INSERT INTO client_rate (bucket, window, count) VALUES (?, ?, ?) ON CONFLICT (bucket) DO UPDATE SET window = excluded.window, count = excluded.count', bucket, window, count + 1);
      return true;
    });
  }

  /**
   * Bring a request up to date: a pending one past its TTL expires; a claimed one is
   * compared with the vault. The browser's item write is a normal signed record, so
   * the vault's durable head tells whether it landed: the claiming device authored a
   * live head at `base_revision + 1` -> `completed`; any other advance -> `conflict`;
   * no advance after the processing window -> `failed`. An unreadable vault leaves
   * the row as it is.
   */
  private async settleIntent(row: IntentRow, nowMs: number): Promise<IntentRow> {
    const reload = () => getIntent(this.sql, row.rid) ?? row;
    if (row.status === 'pending_user') {
      if (nowMs >= row.expires_at) this.ctx.storage.transactionSync(() => transition(this.sql, row.rid, 'pending_user', 'expired', nowMs));
      return reload();
    }
    if (row.status !== 'processing' || row.item_id === null || row.base_revision === null || row.did === null) return row;
    let head;
    try {
      head = await this.env.VAULT.get(this.env.VAULT.idFromName(row.vault_id)).itemHead(row.item_id);
    } catch {
      return reload();
    }
    const base = row.base_revision;
    const wrote = head !== null && !head.tombstone && head.author === row.did && head.revision === base + 1;
    const raced = head !== null && head.revision > base && !wrote;
    const to: IntentStatus | null = wrote ? 'completed' : raced ? 'conflict' : processingOverdue(row, nowMs) ? 'failed' : null;
    if (to) this.ctx.storage.transactionSync(() => transition(this.sql, row.rid, 'processing', to, nowMs));
    return reload();
  }

  // ---------------------------------------------------------------- alarm

  /**
   * Close connections whose `hello` is overdue (4400) or whose token expired without
   * `reauth` (4401), and purge write requests past retention.
   */
  override async alarm(): Promise<void> {
    const now = Date.now();
    purgeIntents(this.sql, now);
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
    const purgeAt = nextPurgeAt(this.sql);
    if (purgeAt !== null) next = Math.min(next, Math.max(purgeAt, Date.now() + 1000));
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

function isId(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    b64decodeLength(value, 16);
    return true;
  } catch {
    return false;
  }
}

/** The connection's token in force has not expired. */
function live(conn: Connection, nowMs: number): boolean {
  return nowMs < conn.exp * 1000;
}

function refuse(code: 'bad_request' | 'unauthorized' | 'rate_limited'): Response {
  return resultResponse(errorResult(new ApiError(code)));
}
