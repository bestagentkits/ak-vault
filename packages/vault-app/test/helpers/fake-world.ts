/**
 * An in-memory ak-web authorization server, ak-web vault token endpoint and
 * vault Worker for dashboard tests, built from the protocol library so every
 * signature, wrap, record and checkpoint is real. An owner "CLI" device creates
 * the vault and approves join codes. Every request and response body is kept
 * for the no-disclosure checks. All data is synthetic.
 */
import {
  applyRecord,
  b64encode,
  buildGenesisEvent,
  cjson,
  computeStateDigest,
  createDeviceKeys,
  deviceIdFromSignPub,
  encodeOfferCode,
  isAkvError,
  nextLogHead,
  nextMembershipEvent,
  parseJoinCode,
  randomBytes,
  randomId,
  recordDigest,
  sasCode,
  sasDigest,
  sealItem,
  sha256,
  signCheckpoint,
  signRecord,
  utf8Encode,
  verifyDetached,
  verifyMembershipChain,
  verifyProof,
  verifyRecord,
  authorizeRecordWrite,
  appendAuditEntry,
  auditEntryHash,
  epochTag,
  parseEnvelope,
  wrapToDevice,
  wrapsDigest,
  nameIndexKey,
  nameTag,
  deriveSealKeyPair,
  sealWriteIntent,
  type DeviceKeys,
  type WriteIntentOperation,
  type WriteIntentTarget,
  type Envelope,
  type ItemState,
  type JsonObject,
  type MembershipEvent,
  type MembershipState,
  type SignedRecord,
  type X25519Wrap,
} from '@ak-vault/protocol';
import type { PendingSignIn, PendingStore } from '../../src/oauth/pkce-client.js';

export const ORIGIN = 'https://vault.example.test';
export const ISSUER = 'https://id.example.test';
export const ACCOUNT = 'acct-alice';
const CLIENT_ID = `${ORIGIN}/app/client.json`;
const REDIRECT = `${ORIGIN}/app/`;
const RESOURCE = `${ORIGIN}/app`;

function b64json(v: unknown): string {
  return b64encode(utf8Encode(JSON.stringify(v)));
}

/** An unsigned JWT-shaped token: the dashboard reads claims and never verifies them. */
export function fakeJwt(claims: Record<string, unknown>): string {
  return `${b64json({ alg: 'ES256', typ: 'JWT' })}.${b64json(claims)}.${b64encode(randomBytes(64))}`;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function apiError(status: number, code: string): Response {
  return json(status, { error: { code, message: 'synthetic' } });
}

/** A write request as the Worker keeps it (spec §3.10); the intent is cleared on close. */
export interface FakeWriteRequest {
  account: string;
  clientId: string;
  operation: WriteIntentOperation;
  state: 'pending_user' | 'completed' | 'conflict' | 'cancelled' | 'expired' | 'failed';
  reason: string | null;
  receipt: string | null;
  intent: JsonObject | null;
  expiresAt: number;
}

const CLOSE_REASONS: Record<string, string[]> = { cancelled: ['user_cancelled'], failed: ['already_exists', 'not_found', 'device_error'] };

export interface LoggedExchange {
  method: string;
  url: string;
  requestBody: string;
  responseBody: string;
  status: number;
}

export function memoryPendingStore(): PendingStore & { value: PendingSignIn | null } {
  const s = {
    value: null as PendingSignIn | null,
    save(p: PendingSignIn) {
      s.value = { ...p };
    },
    take() {
      const v = s.value;
      s.value = null;
      return v;
    },
  };
  return s;
}

export class FakeWorld {
  readonly owner: DeviceKeys = createDeviceKeys({ account: ACCOUNT, role: 'owner', kind: 'human' });
  readonly recovery: DeviceKeys = createDeviceKeys({ account: ACCOUNT, role: 'owner', kind: 'human' });
  readonly vaultId = randomId();
  readonly vks = new Map<number, Uint8Array>([[1, randomBytes(32)]]);
  events: MembershipEvent[] = [];
  readonly wraps = new Map<number, X25519Wrap[]>();
  log: { log_seq: number; conflict_id: string | null; record: SignedRecord }[] = [];
  logHeads: string[] = [''];
  itemStates = new Map<string, ItemState>();
  readonly tags = new Map<string, { key_epoch: number; tag: string }>();
  readonly exchanges: LoggedExchange[] = [];
  readonly writeRequests = new Map<string, FakeWriteRequest>();
  readonly revoked: string[] = [];
  /** The encrypted audit stream, as the Worker stores it. */
  readonly audit: Envelope[] = [];
  private readonly codes = new Map<string, { challenge: string; state: string }>();
  private readonly appTokens = new Map<string, { sub: string; sid: string }>();
  private readonly refreshTokens = new Map<string, { sub: string; sid: string }>();
  private readonly syncTokens = new Map<string, { sub: string; did: string }>();
  private readonly grantDevice = new Map<string, string>();
  private readonly jtis = new Set<string>();
  private grants = 0;
  /** Knobs for hostile-server tests. */
  readonly hostile = {
    /** Account the next app token is issued for. */
    appSub: ACCOUNT,
    /** Account the sync token claims (cross-tenant token). */
    syncSub: null as string | null,
    revokedDids: new Set<string>(),
    /** Serve only the first n log entries (a rolled-back server). */
    truncateLog: null as number | null,
    /** Withhold one log position (a gap in the served log). */
    dropLogSeq: null as number | null,
    /** Rewrite served log entries (a tampered record, a relabelled branch). */
    mutateEntry: null as ((e: { log_seq: number; conflict_id: string | null; record: SignedRecord }) => { log_seq: number; conflict_id: string | null; record: SignedRecord }) | null,
    /** Replace the membership chain served. */
    membership: null as MembershipEvent[] | null,
    omitIss: false,
    /** Offset of the vault origin's `Date` header from this machine's clock (a skewed device clock). */
    dateOffsetMs: 0,
    /** Answer every vault request 401, as a proof timestamp outside the window would be. */
    rejectProofs: false,
    /** Refuse every item write with 403, as a Worker does for a role the chain no longer grants. */
    forbidWrites: false,
    /** Every request fails at the network layer. */
    offline: false,
    /** Refuse audit appends with this HTTP status (a failing audit store). */
    auditAppendStatus: null as number | null,
    /** Answer the next n audit appends with a 409 as if another device appended first. */
    auditConflicts: 0,
    /** Serve a head the stored chain does not have, and accept appends chained on it (a lying server). */
    auditForgedHead: false,
  };

  constructor(opts: { shared?: boolean } = {}) {
    const wrap = wrapToDevice({ vk: this.vks.get(1)!, vaultId: this.vaultId, keyEpoch: 1, recipient: this.owner.record });
    const genesis = buildGenesisEvent(
      {
        vault_id: this.vaultId, ts: Date.now(), author: this.owner.record.device_id,
        body: {
          vault_kind: opts.shared ? 'shared' : 'personal', owner_account: ACCOUNT, recovery_sign_pub: this.recovery.record.sign_pub,
          devices: [this.owner.record as unknown as JsonObject], wraps_digest: wrapsDigest([wrap]),
        },
      },
      this.owner.signSecret,
    );
    this.events.push(genesis);
    this.wraps.set(0, [wrap]);
  }

  state(): MembershipState {
    return verifyMembershipChain(this.events);
  }

  checkpoint() {
    const st = this.state();
    return signCheckpoint(
      {
        vault_id: this.vaultId, membership_seq: st.seq, membership_head: st.head, log_seq: this.log.length,
        state_digest: computeStateDigest(this.itemStates.values()), key_epoch: st.key_epoch, ts: Date.now(), author: this.owner.record.device_id,
      },
      this.owner.signSecret,
    );
  }

  /** What `ak secrets devices approve <join>` prints: the offer code and the SAS. */
  offerFor(joinCode: string, opts: { origin?: string; joiner?: string; trustAnchor?: string } = {}): { code: string; sas: string; nonceI: string } {
    const join = parseJoinCode(joinCode);
    const nonceI = b64encode(randomBytes(16));
    const code = encodeOfferCode({
      vault_origin: opts.origin ?? ORIGIN, vault_id: this.vaultId, initiator: this.owner.record.device_id,
      joiner: opts.joiner ?? join.device.device_id, nonce_i: nonceI, nonce_j: join.nonce_j,
      trust_anchor: opts.trustAnchor ?? this.owner.record.sign_pub, checkpoint: this.checkpoint(),
    });
    const sas = sasCode({ vault_id: this.vaultId, initiator: this.owner.record.device_id, joiner: join.device, nonce_i: nonceI, nonce_j: join.nonce_j });
    return { code, sas, nonceI };
  }

  /** The owner's `device_add` after the SAS matched. `wrongSas` signs another transcript. */
  approve(joinCode: string, nonceI: string, opts: { wrongSas?: boolean; omitEpochs?: number[] } = {}): void {
    const join = parseJoinCode(joinCode);
    const st = this.state();
    const ws = [...this.vks.entries()].filter(([e]) => !opts.omitEpochs?.includes(e)).map(([e, vk]) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: e, recipient: join.device }));
    const sas = sasDigest({ vault_id: this.vaultId, initiator: this.owner.record.device_id, joiner: join.device, nonce_i: opts.wrongSas ? b64encode(randomBytes(16)) : nonceI, nonce_j: join.nonce_j });
    const ev = nextMembershipEvent(st, { type: 'device_add', ts: Date.now(), author: this.owner.record.device_id, body: { device: join.device as unknown as JsonObject, sas, wraps_digest: wrapsDigest(ws) } }, this.owner.signSecret);
    this.events.push(ev);
    this.wraps.set(ev.seq, ws);
  }

  /** The owner adds another owner device (as `ak secrets devices approve` would) so there is someone to remove. */
  addDevice(keys: DeviceKeys): void {
    const st = this.state();
    const ws = [...this.vks.entries()].map(([e, vk]) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: e, recipient: keys.record }));
    const sas = sasDigest({ vault_id: this.vaultId, initiator: this.owner.record.device_id, joiner: keys.record, nonce_i: b64encode(randomBytes(16)), nonce_j: b64encode(randomBytes(16)) });
    const ev = nextMembershipEvent(st, { type: 'device_add', ts: Date.now(), author: this.owner.record.device_id, body: { device: keys.record as unknown as JsonObject, sas, wraps_digest: wrapsDigest(ws) } }, this.owner.signSecret);
    this.events.push(ev);
    this.wraps.set(ev.seq, ws);
  }

  /** Shared vaults: the owner signs another account in with one device and a role. */
  addMember(keys: DeviceKeys, role: 'owner' | 'editor' | 'reader'): void {
    const st = this.state();
    const rec = { ...keys.record, role };
    const ws = [...this.vks.entries()].map(([e, vk]) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: e, recipient: rec }));
    const ev = nextMembershipEvent(st, { type: 'member_add', ts: Date.now(), author: this.owner.record.device_id, body: { account: rec.account, role, devices: [rec as unknown as JsonObject], wraps_digest: wrapsDigest(ws) } }, this.owner.signSecret);
    this.events.push(ev);
    this.wraps.set(ev.seq, ws);
  }

  /** The owner signs a role change for an account; `fence` defaults to the current log position, like a removal. */
  setRole(account: string, role: 'owner' | 'editor' | 'reader', fence = this.log.length): void {
    const body = { account, role, log_fence: fence, log_head: this.logHeads[fence]! };
    const ev = nextMembershipEvent(this.state(), { type: 'role_set', ts: Date.now(), author: this.owner.record.device_id, body }, this.owner.signSecret);
    this.events.push(ev);
  }

  /** The owner rekeys to a new vault key, wrapping it to every current device, and flags items for rotation. */
  rekey(needsRotate: string[] = []): number {
    const st = this.state();
    const epoch = st.key_epoch + 1;
    const vk = randomBytes(32);
    const ws = st.devices.map((d) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: epoch, recipient: d }));
    const ev = nextMembershipEvent(st, {
      type: 'rekey', ts: Date.now(), author: this.owner.record.device_id,
      body: { new_key_epoch: epoch, wraps_digest: wrapsDigest(ws), needs_rotate: [...needsRotate].sort() },
    }, this.owner.signSecret);
    this.events.push(ev);
    this.wraps.set(ev.seq, ws);
    this.vks.set(epoch, vk);
    return epoch;
  }

  /** Remove a device; `fence` defaults to the current log position (a hostile server may accept an older one). */
  removeDevice(deviceId: string, fence = this.log.length): void {
    const st = this.state();
    const ev = nextMembershipEvent(st, {
      type: 'device_remove', ts: Date.now(), author: this.owner.record.device_id,
      body: { device_id: deviceId, reason: 'retired', log_fence: fence, log_head: this.logHeads[fence]! },
    }, this.owner.signSecret);
    this.events.push(ev);
  }

  /** The owner rekeys to the next epoch, wrapping it to every current device and flagging `needsRotate`. */
  ownerRekey(needsRotate: string[], ts = Date.now()): number {
    const st = this.state();
    const epoch = st.key_epoch + 1;
    const vk = randomBytes(32);
    const ws = st.devices.map((d) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: epoch, recipient: d }));
    const ev = nextMembershipEvent(st, { type: 'rekey', ts, author: this.owner.record.device_id, body: { new_key_epoch: epoch, wraps_digest: wrapsDigest(ws), needs_rotate: needsRotate } }, this.owner.signSecret);
    this.events.push(ev);
    this.wraps.set(ev.seq, ws);
    this.vks.set(epoch, vk);
    return epoch;
  }

  /** The owner CLI writes an item directly (as another device would). */
  ownerSet(name: string, value: string, meta: JsonObject = { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000 }, ts = Date.now()): string {
    const st = this.state();
    const existing = [...this.itemStates.values()].find((s) => s.revision > 0 && !s.tombstone && this.nameOf(s.item_id) === name);
    const itemId = existing?.item_id ?? randomId();
    const ctx = { vault_id: this.vaultId, item_id: itemId, base_revision: existing?.revision ?? 0, key_epoch: st.key_epoch, author: this.owner.record.device_id, tombstone: false };
    const env = sealItem({ ...ctx, vk: this.vks.get(st.key_epoch)!, payload: { name, value, meta, sensitivity: 'normal' } });
    const record = signRecord({ ...ctx, ts, resolves: [], env }, this.owner.signSecret);
    const res = this.applyServer(record, nameTag(nameIndexKey(this.vks.get(st.key_epoch)!, this.vaultId, st.key_epoch), name));
    if (res.status !== 200) throw new Error('owner write refused');
    this.names.set(itemId, name);
    return itemId;
  }

  /**
   * The owner CLI submits a record at an explicit `base` (a stale base becomes a preserved branch),
   * optionally as a tombstone or resolving branches. Returns the server's status and the branch ID.
   */
  ownerWrite(itemId: string, name: string, value: string, opts: { base: number; tombstone?: boolean; resolves?: string[]; ts?: number; meta?: JsonObject }): { status: number; conflictId: string | null } {
    const st = this.state();
    const tombstone = opts.tombstone === true;
    const ctx = { vault_id: this.vaultId, item_id: itemId, base_revision: opts.base, key_epoch: st.key_epoch, author: this.owner.record.device_id, tombstone };
    const payload = tombstone ? { deleted: true as const } : { name, value, meta: opts.meta ?? { schema: 'agentkit.secret/v1', created_ms: 1_700_000_000_000 }, sensitivity: 'normal' as const };
    const env = sealItem({ ...ctx, vk: this.vks.get(st.key_epoch)!, payload });
    const record = signRecord({ ...ctx, ts: opts.ts ?? Date.now(), resolves: opts.resolves ?? [], env }, this.owner.signSecret);
    const res = this.applyServer(record, tombstone ? null : nameTag(nameIndexKey(this.vks.get(st.key_epoch)!, this.vaultId, st.key_epoch), name));
    const body = res.body as { error?: { conflict_id?: string } };
    this.names.set(itemId, name);
    return { status: res.status, conflictId: body.error?.conflict_id ?? null };
  }

  private readonly names = new Map<string, string>();
  private nameOf(itemId: string): string | undefined {
    return this.names.get(itemId);
  }

  private applyServer(record: SignedRecord, tag: string | null): { status: number; body: unknown } {
    const st = this.state();
    try {
      verifyRecord(record, st);
      authorizeRecordWrite(st, record);
      const applied = applyRecord(this.itemStates.get(record.item_id), record);
      const logSeq = this.log.length + 1;
      const conflictId = applied.outcome.status === 'conflict' ? applied.outcome.conflict_id : null;
      this.log.push({ log_seq: logSeq, conflict_id: conflictId, record });
      this.logHeads.push(nextLogHead(this.logHeads[logSeq - 1]!, logSeq, conflictId, recordDigest(record)));
      this.itemStates.set(record.item_id, applied.state);
      if (applied.outcome.status === 'conflict') return { status: 409, body: { error: { code: 'conflict', message: 'conflict', conflict_id: conflictId } } };
      if (tag) this.tags.set(record.item_id, { key_epoch: record.key_epoch, tag });
      else this.tags.delete(record.item_id);
      return { status: 200, body: { revision: applied.outcome.revision, tombstone: record.tombstone, log_seq: logSeq } };
    } catch (err) {
      const code = isAkvError(err) ? err.code : 'internal';
      return { status: code === 'forbidden' ? 403 : code === 'rekey_required' || code === 'tombstoned' || code === 'conflict' ? 409 : 400, body: { error: { code, message: 'synthetic' } } };
    }
  }

  /**
   * What `secrets_prepare_write` does: seal the target to the epoch's seal key
   * and keep the request. `vaultId` seals for another vault (a forged intent).
   */
  prepareWrite(target: WriteIntentTarget, opts: { operation?: WriteIntentOperation; ttlMs?: number; clientId?: string; vaultId?: string } = {}): string {
    const st = this.state();
    const now = Date.now();
    const clientId = opts.clientId ?? 'https://assistant.example.test/client';
    const vaultId = opts.vaultId ?? this.vaultId;
    const wire = sealWriteIntent(deriveSealKeyPair(this.vks.get(st.key_epoch)!, vaultId, st.key_epoch).publicKey, {
      vaultId, keyEpoch: st.key_epoch, origin: { kind: 'mcp', account: ACCOUNT, client_id: clientId, grant_id: 'grant-mcp' },
      operation: opts.operation ?? 'create', ts: now, expiresAt: now + (opts.ttlMs ?? 600_000), target,
    });
    this.writeRequests.set(wire.request_id, {
      account: ACCOUNT, clientId, operation: wire.operation, state: 'pending_user', reason: null, receipt: null,
      intent: wire as unknown as JsonObject, expiresAt: wire.expires_at,
    });
    return wire.request_id;
  }

  formUrl(requestId: string, vaultId = this.vaultId): string {
    return `${ORIGIN}/app#write=${requestId}&vault=${vaultId}`;
  }

  /** The caller's open request: 404 unknown or another account's, 400 closed or expired. */
  private openRequest(id: string, sub: string): FakeWriteRequest | Response {
    const row = this.writeRequests.get(id);
    if (!row || row.account !== sub) return apiError(404, 'not_found');
    if (row.state === 'pending_user' && row.expiresAt <= Date.now()) Object.assign(row, { state: 'expired', intent: null });
    if (row.state !== 'pending_user') return apiError(400, 'bad_request');
    return row;
  }

  private closeRequest(row: FakeWriteRequest, state: FakeWriteRequest['state'], reason: string | null, receipt: string | null): void {
    Object.assign(row, { state, reason, receipt, intent: null });
  }

  /** What the authorization server does with the dashboard's redirect: returns the callback URL. */
  authorize(authUrl: string, opts: { state?: string; iss?: string } = {}): URL {
    const u = new URL(authUrl);
    if (u.origin !== ISSUER || u.pathname !== '/oauth/authorize') throw new Error('unexpected authorization endpoint');
    const p = u.searchParams;
    if (p.get('client_id') !== CLIENT_ID || p.get('redirect_uri') !== REDIRECT || p.get('resource') !== RESOURCE || p.get('code_challenge_method') !== 'S256') throw new Error('bad authorization request');
    const code = b64encode(randomBytes(16));
    this.codes.set(code, { challenge: p.get('code_challenge')!, state: p.get('state')! });
    const cb = new URL(REDIRECT);
    cb.searchParams.set('code', code);
    cb.searchParams.set('state', opts.state ?? p.get('state')!);
    if (!this.hostile.omitIss) cb.searchParams.set('iss', opts.iss ?? ISSUER);
    return cb;
  }

  private issueApp(sub: string, sid: string): Response {
    const now = Math.floor(Date.now() / 1000);
    const access = fakeJwt({ iss: ISSUER, aud: RESOURCE, sub, client_id: CLIENT_ID, grant_id: sid, sid, scope: 'vault-app:session', jti: randomId(), iat: now, nbf: now, exp: now + 600 });
    const refresh = b64encode(randomBytes(32));
    this.appTokens.set(access, { sub, sid });
    this.refreshTokens.set(refresh, { sub, sid });
    return json(200, { access_token: access, token_type: 'Bearer', expires_in: 600, refresh_token: refresh, scope: 'vault-app:session' });
  }

  /** Awaited before a request is served, so a test can hold one in flight. */
  requestGate: ((method: string, url: URL) => Promise<void>) | null = null;

  readonly fetch = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = (init.method ?? 'GET').toUpperCase();
    const requestBody = typeof init.body === 'string' ? init.body : '';
    if (this.hostile.offline) throw new TypeError('network down');
    if (this.requestGate) await this.requestGate(method, new URL(url));
    let res = await this.route(new URL(url), method, requestBody, new Headers(init.headers));
    if (this.hostile.dateOffsetMs !== 0 && new URL(url).origin === ORIGIN) {
      const headers = new Headers(res.headers);
      headers.set('Date', new Date(Date.now() + this.hostile.dateOffsetMs).toUTCString());
      res = new Response(await res.text(), { status: res.status, headers });
    }
    const responseBody = await res.clone().text();
    this.exchanges.push({ method, url, requestBody, responseBody, status: res.status });
    return res;
  };

  private async route(url: URL, method: string, body: string, headers: Headers): Promise<Response> {
    if (url.origin === ISSUER) return this.routeIssuer(url, method, body, headers);
    if (url.origin !== ORIGIN) return json(404, { error: 'unknown origin' });
    if (url.pathname === '/app/config.json') {
      return json(200, { v: 1, issuer: ISSUER, client_id: CLIENT_ID, redirect_uri: REDIRECT, resource: RESOURCE, scope: 'vault-app:session' });
    }
    return this.routeVault(url, method, body, headers);
  }

  private routeIssuer(url: URL, method: string, body: string, headers: Headers): Response {
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return json(200, {
        issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth/authorize`, token_endpoint: `${ISSUER}/oauth/token`,
        revocation_endpoint: `${ISSUER}/oauth/revoke`, code_challenge_methods_supported: ['S256'], authorization_response_iss_parameter_supported: true,
      });
    }
    if (url.pathname === '/oauth/token' && method === 'POST') {
      const f = new URLSearchParams(body);
      if (f.get('client_id') !== CLIENT_ID) return json(400, { error: 'invalid_client' });
      if (f.get('grant_type') === 'authorization_code') {
        const entry = this.codes.get(f.get('code') ?? '');
        this.codes.delete(f.get('code') ?? '');
        if (!entry || b64encode(sha256(utf8Encode(f.get('code_verifier') ?? ''))) !== entry.challenge || f.get('redirect_uri') !== REDIRECT || f.get('resource') !== RESOURCE) {
          return json(400, { error: 'invalid_grant' });
        }
        return this.issueApp(this.hostile.appSub, `grant-${++this.grants}`);
      }
      if (f.get('grant_type') === 'refresh_token') {
        const g = this.refreshTokens.get(f.get('refresh_token') ?? '');
        if (!g) return json(400, { error: 'invalid_grant' });
        return this.issueApp(g.sub, g.sid);
      }
      return json(400, { error: 'unsupported_grant_type' });
    }
    if (url.pathname === '/oauth/revoke' && method === 'POST') {
      const f = new URLSearchParams(body);
      const token = f.get('token') ?? '';
      this.revoked.push(token);
      const g = this.refreshTokens.get(token) ?? this.appTokens.get(token);
      if (g) {
        for (const m of [this.refreshTokens, this.appTokens]) for (const [k, v] of m) if (v.sid === g.sid) m.delete(k);
      }
      return new Response(null, { status: 200 });
    }
    if (url.pathname === '/api/agentkit/vault/token' && method === 'POST') {
      const bearer = (headers.get('Authorization') ?? '').replace(/^Bearer /, '');
      const app = this.appTokens.get(bearer);
      if (!app) return json(401, { error: 'not_authenticated', errorCode: 'not_authenticated' });
      const req = JSON.parse(body) as { sign_pub: string; scope: string[]; ts: number; sig: string };
      if (cjson(Object.keys(req).sort()) !== cjson(['scope', 'sig', 'sign_pub', 'ts'])) return json(400, { error: 'invalid_request' });
      if (!verifyDetached('akv1/vault-token-request', { aud: ORIGIN, scope: [...req.scope].sort(), sid: app.sid, sign_pub: req.sign_pub, ts: req.ts }, req.sig, req.sign_pub)) {
        return json(401, { error: 'invalid_signature', errorCode: 'invalid_signature' });
      }
      const did = deviceIdFromSignPub(req.sign_pub);
      if (this.hostile.revokedDids.has(did)) return json(403, { error: 'device_revoked', errorCode: 'device_revoked' });
      const bound = this.grantDevice.get(app.sid);
      if (bound && bound !== did) return json(403, { error: 'device_mismatch', errorCode: 'device_mismatch' });
      this.grantDevice.set(app.sid, did);
      const now = Math.floor(Date.now() / 1000);
      const sub = this.hostile.syncSub ?? app.sub;
      const token = fakeJwt({ iss: ISSUER, aud: ORIGIN, sub, did, sid: app.sid, session_kind: 'browser', scope: 'vault:read vault:write', iat: now, nbf: now, exp: now + 300, jti: randomId() });
      this.syncTokens.set(token, { sub: app.sub, did });
      return json(200, { access_token: token, token_type: 'Bearer', expires_in: 300, did });
    }
    return json(404, { error: 'not_found' });
  }

  /** The fixed hash a lying server reports as its head while `auditForgedHead` is set. */
  private readonly forgedAuditHash = b64encode(randomBytes(32));

  /** The head the server reports: the real one, or the forged one while lying. */
  private servedAuditHead(): { seq: number; head: string } | null {
    return this.hostile.auditForgedHead ? { seq: Math.max(0, this.audit.length - 1), head: this.forgedAuditHash } : this.auditHead();
  }

  private auditHead(): { seq: number; head: string } | null {
    const last = this.audit.length - 1;
    return last >= 0 ? { seq: last, head: auditEntryHash(this.audit[last]!) } : null;
  }

  private routeAudit(url: URL, method: string, body: string, headers: Headers): Response {
    if (method === 'GET') {
      const cursor = Number(url.searchParams.get('cursor') ?? 0);
      const limit = Number(url.searchParams.get('limit') ?? 500);
      const page = this.audit.map((entry, seq) => ({ seq, entry })).filter((e) => e.seq >= cursor).slice(0, limit);
      return json(200, { entries: page, next_cursor: cursor, has_more: false, head: this.servedAuditHead(), checkpoints: [] });
    }
    if (method !== 'POST') return apiError(404, 'not_found');
    if (!headers.get('Idempotency-Key')) return apiError(400, 'bad_request');
    if (this.hostile.auditAppendStatus !== null) return apiError(this.hostile.auditAppendStatus, 'internal');
    const b = JSON.parse(body) as { start_seq: number; prev: string; entries: unknown[] };
    const head = this.auditHead();
    if (this.hostile.auditConflicts > 0) {
      this.hostile.auditConflicts--;
      // another device appended first
      const epoch = this.state().key_epoch;
      this.audit.push(appendAuditEntry({ vk: this.vks.get(epoch)!, vaultId: this.vaultId, keyEpoch: epoch, head, event: { v: 1, type: 'item_put', device_id: this.owner.record.device_id, ts: Date.now() } }).entry);
      return apiError(409, 'conflict');
    }
    // A lying server checks the append against the head it served, so only the client's own check refuses it.
    const served = this.servedAuditHead();
    if (b.start_seq !== (served ? served.seq + 1 : 0) || b.prev !== (served ? served.head : '')) return apiError(409, 'conflict');
    const kid = epochTag(this.state().key_epoch);
    const entries = b.entries.map((e) => parseEnvelope(e, 'audit entry'));
    if (entries.some((e) => e.kid !== kid)) return apiError(400, 'bad_request');
    this.audit.push(...entries);
    return json(201, { head: this.auditHead() });
  }

  private routeVault(url: URL, method: string, body: string, headers: Headers): Response {
    const token = (headers.get('Authorization') ?? '').replace(/^Bearer /, '');
    const who = this.syncTokens.get(token);
    if (!who || this.hostile.rejectProofs) return apiError(401, 'unauthorized');
    const st = this.state();
    const device = st.devices.find((d) => d.device_id === who.did && d.account === who.sub);
    if (!device) return apiError(403, 'forbidden');
    try {
      const proof = verifyProof(headers.get('AKV-Proof') ?? '', {
        htm: method, htu: url.href, token, body: utf8Encode(body), now: Date.now(), signPub: device.sign_pub,
        isReplay: (jti) => this.jtis.has(jti),
      });
      this.jtis.add(proof.jti);
    } catch {
      return apiError(401, 'unauthorized');
    }
    const parts = url.pathname.split('/');
    if (parts[1] !== 'v1' || parts[2] !== 'vaults' || decodeURIComponent(parts[3] ?? '') !== this.vaultId) return apiError(404, 'not_found');
    const coll = parts[4];
    if (method === 'GET' && coll === 'membership') {
      const events = this.hostile.membership ?? this.events;
      const from = Number(url.searchParams.get('from') ?? 0);
      const limit = Number(url.searchParams.get('limit') ?? 1000);
      const page = events.slice(from, from + limit);
      return json(200, { events: page, has_more: from + page.length < events.length, membership: {} });
    }
    if (method === 'GET' && coll === 'wraps') {
      const seq = Number(url.searchParams.get('membership_seq'));
      const ws = this.wraps.get(seq);
      return ws ? json(200, { membership_seq: seq, wraps: ws }) : apiError(404, 'not_found');
    }
    if (method === 'GET' && coll === 'changes') {
      const base = this.hostile.truncateLog === null ? this.log : this.log.slice(0, this.hostile.truncateLog);
      const served = base.filter((e) => e.log_seq !== this.hostile.dropLogSeq).map((e) => (this.hostile.mutateEntry ? this.hostile.mutateEntry(e) : e));
      const cursor = Number(url.searchParams.get('cursor') ?? 0);
      const limit = Number(url.searchParams.get('limit') ?? 100);
      const page = served.filter((e) => e.log_seq > cursor).slice(0, limit);
      return json(200, {
        changes: page.map((e) => ({ ...e, kind: 'item', item_id: e.record.item_id, revision: 0, resolved_revision: null, log_head: '' })),
        next_cursor: page.length ? page[page.length - 1]!.log_seq : cursor,
        has_more: served.some((e) => e.log_seq > (page.length ? page[page.length - 1]!.log_seq : cursor)),
        head: { log_seq: served.length, log_head: this.logHeads[served.length] ?? '' },
      });
    }
    if (coll === 'audit') return this.routeAudit(url, method, body, headers);
    if (method === 'GET' && coll === 'lookup') {
      const tags = url.searchParams.getAll('tag');
      const epochs = url.searchParams.getAll('key_epoch').map(Number);
      const hits = [...this.tags.entries()]
        .filter(([, t]) => tags.some((tag, i) => tag === t.tag && epochs[i] === t.key_epoch))
        .map(([item_id, t]) => ({ item_id, revision: this.itemStates.get(item_id)!.revision, key_epoch: t.key_epoch, tag: t.tag }));
      return json(200, { hits });
    }
    if (coll === 'write-requests' && parts[5]) {
      const row = this.openRequest(parts[5], who.sub);
      if (method === 'GET' && parts.length === 6) {
        if (row instanceof Response) return row;
        return json(200, { request_id: parts[5], operation: row.operation, client_id: row.clientId, expires_at: row.expiresAt, intent: row.intent });
      }
      if (method === 'POST' && parts.length === 7 && parts[6] === 'close') {
        if (!headers.get('Idempotency-Key')) return apiError(400, 'bad_request');
        const b = JSON.parse(body) as { outcome?: string; reason?: string };
        if (Object.keys(b).length !== 2 || !CLOSE_REASONS[b.outcome ?? '']?.includes(b.reason ?? '')) return apiError(400, 'bad_request');
        if (row instanceof Response) return row;
        this.closeRequest(row, b.outcome as FakeWriteRequest['state'], b.reason!, null);
        return json(200, { state: b.outcome });
      }
      return apiError(404, 'not_found');
    }
    if (method === 'PUT' && coll === 'items') {
      if (this.hostile.forbidWrites) return apiError(403, 'forbidden');
      if (!headers.get('Idempotency-Key')) return apiError(400, 'bad_request');
      const b = JSON.parse(body) as { record: SignedRecord; name_tag?: { key_epoch: number; tag: string } };
      if (b.record.item_id !== decodeURIComponent(parts[5] ?? '')) return apiError(400, 'bad_request');
      const requestId = url.searchParams.get('write_request');
      if (requestId === null) {
        const res = this.applyServer(b.record, b.name_tag?.tag ?? null);
        return json(res.status, res.body);
      }
      const row = this.openRequest(requestId, who.sub);
      if (row instanceof Response) return row;
      const head = this.itemStates.get(b.record.item_id);
      const live = !!head && head.revision > 0 && !head.tombstone;
      if (live !== (row.operation === 'replace')) return apiError(400, 'bad_request');
      const res = this.applyServer(b.record, b.name_tag?.tag ?? null);
      if (res.status === 200) {
        const receipt = randomId();
        this.closeRequest(row, 'completed', null, receipt);
        return json(200, { ...(res.body as JsonObject), write_request: { state: 'completed', receipt } });
      }
      if (res.status === 409 && (res.body as { error: { code: string } }).error.code === 'conflict') this.closeRequest(row, 'conflict', 'revision_conflict', null);
      return json(res.status, res.body);
    }
    return apiError(404, 'not_found');
  }
}
