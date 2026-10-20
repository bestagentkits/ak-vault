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
  wrapToDevice,
  wrapsDigest,
  nameIndexKey,
  nameTag,
  type DeviceKeys,
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
  readonly revoked: string[] = [];
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
    /** Replace the membership chain served. */
    membership: null as MembershipEvent[] | null,
    omitIss: false,
    /** Offset of the vault origin's `Date` header from this machine's clock (a skewed device clock). */
    dateOffsetMs: 0,
    /** Answer every vault request 401, as a proof timestamp outside the window would be. */
    rejectProofs: false,
  };

  constructor() {
    const wrap = wrapToDevice({ vk: this.vks.get(1)!, vaultId: this.vaultId, keyEpoch: 1, recipient: this.owner.record });
    const genesis = buildGenesisEvent(
      {
        vault_id: this.vaultId, ts: Date.now(), author: this.owner.record.device_id,
        body: {
          vault_kind: 'personal', owner_account: ACCOUNT, recovery_sign_pub: this.recovery.record.sign_pub,
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
  approve(joinCode: string, nonceI: string, opts: { wrongSas?: boolean } = {}): void {
    const join = parseJoinCode(joinCode);
    const st = this.state();
    const ws = [...this.vks.entries()].map(([e, vk]) => wrapToDevice({ vk, vaultId: this.vaultId, keyEpoch: e, recipient: join.device }));
    const sas = sasDigest({ vault_id: this.vaultId, initiator: this.owner.record.device_id, joiner: join.device, nonce_i: opts.wrongSas ? b64encode(randomBytes(16)) : nonceI, nonce_j: join.nonce_j });
    const ev = nextMembershipEvent(st, { type: 'device_add', ts: Date.now(), author: this.owner.record.device_id, body: { device: join.device as unknown as JsonObject, sas, wraps_digest: wrapsDigest(ws) } }, this.owner.signSecret);
    this.events.push(ev);
    this.wraps.set(ev.seq, ws);
  }

  removeDevice(deviceId: string): void {
    const st = this.state();
    const ev = nextMembershipEvent(st, {
      type: 'device_remove', ts: Date.now(), author: this.owner.record.device_id,
      body: { device_id: deviceId, reason: 'retired', log_fence: this.log.length, log_head: this.logHeads[this.log.length]! },
    }, this.owner.signSecret);
    this.events.push(ev);
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

  readonly fetch = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = (init.method ?? 'GET').toUpperCase();
    const requestBody = typeof init.body === 'string' ? init.body : '';
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
      const served = this.hostile.truncateLog === null ? this.log : this.log.slice(0, this.hostile.truncateLog);
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
    if (method === 'GET' && coll === 'lookup') {
      const tags = url.searchParams.getAll('tag');
      const epochs = url.searchParams.getAll('key_epoch').map(Number);
      const hits = [...this.tags.entries()]
        .filter(([, t]) => tags.some((tag, i) => tag === t.tag && epochs[i] === t.key_epoch))
        .map(([item_id, t]) => ({ item_id, revision: this.itemStates.get(item_id)!.revision, key_epoch: t.key_epoch, tag: t.tag }));
      return json(200, { hits });
    }
    if (method === 'PUT' && coll === 'items') {
      if (!headers.get('Idempotency-Key')) return apiError(400, 'bad_request');
      const b = JSON.parse(body) as { record: SignedRecord; name_tag?: { key_epoch: number; tag: string } };
      if (b.record.item_id !== decodeURIComponent(parts[5] ?? '')) return apiError(400, 'bad_request');
      const res = this.applyServer(b.record, b.name_tag?.tag ?? null);
      return json(res.status, res.body);
    }
    return apiError(404, 'not_found');
  }
}
