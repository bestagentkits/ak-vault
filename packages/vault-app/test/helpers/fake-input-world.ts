/**
 * An in-memory ak-web (authorization server, revocation, `input` token endpoint)
 * and vault Worker (config, the two input-request routes) for input-form tests,
 * plus the device that issued the request's one-time input key, which opens each
 * submission with the protocol library under the context it recorded. The real
 * ak-web `input` token endpoint is not live yet; this fake follows spec §3.11.
 * Every request and response body is kept for the no-disclosure checks. All data
 * is synthetic.
 */
import { b64encode, generateInputKeyPair, openInput, randomBytes, randomId, sha256, utf8Encode, type InputSealContext, type InputSealPayload } from '@ak-vault/protocol';
import { InputController } from '../../src/input/input-controller.js';
import { INPUT_PENDING_KEY, sessionPendingStore } from '../../src/oauth/pkce-client.js';
import { renderInput } from '../../src/ui/input-view.js';
import { ACCOUNT, ISSUER, ORIGIN, fakeJwt } from './fake-world.js';

const CLIENT_ID = `${ORIGIN}/app/client.json`;
const REDIRECT = `${ORIGIN}/app/`;
const RESOURCE = `${ORIGIN}/app`;
export const INPUT_AUDIENCE = `${ORIGIN}/input`;
export const REQUESTING_CLIENT = 'https://assistant.example.test/client';

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

export interface LoggedExchange {
  method: string;
  url: string;
  headers: Record<string, string>;
  requestBody: string;
  responseBody: string;
  status: number;
  keepalive: boolean;
}

export interface FakeInputRequest {
  requestId: string;
  vaultId: string;
  account: string;
  deviceId: string;
  name: string;
  purpose: string | null;
  operation: 'create' | 'replace';
  state: string;
  expiresAt: number;
  receipt: string | null;
}

export class FakeInputWorld {
  readonly key = generateInputKeyPair();
  readonly request: FakeInputRequest;
  readonly exchanges: LoggedExchange[] = [];
  /** Tokens sent to the revocation endpoint. */
  readonly revoked: string[] = [];
  /** What the device opened from each delivered seal (test-side only). */
  readonly delivered: InputSealPayload[] = [];
  private readonly codes = new Map<string, { challenge: string }>();
  private readonly appTokens = new Map<string, { sub: string; sid: string }>();
  private readonly refreshTokens = new Map<string, { sub: string; sid: string }>();
  private readonly inputTokens = new Map<string, { sub: string; sid: string }>();
  private grants = 0;
  readonly knobs = {
    /** Status the input-token endpoint answers with instead of a token. */
    inputTokenStatus: null as number | null,
    /** Claims merged into (or, when undefined, removed from) the next minted input tokens. */
    inputClaims: {} as Record<string, unknown>,
    /** Status the GET answers with instead of the request. */
    getStatus: null as number | null,
    /** The request ID the GET's body names (a server answering for another request). */
    getRequestId: null as string | null,
    /** Answers for the next POSTs, in order; empty means the device opens and stores. */
    postAnswers: [] as Response[],
    /** Answer the next n Worker calls 401 (an `input` token that lapsed). */
    reject401: 0,
    offline: false,
  };

  constructor(opts: Partial<Pick<FakeInputRequest, 'name' | 'purpose' | 'operation' | 'state' | 'expiresAt'>> = {}) {
    this.request = {
      requestId: randomId(),
      vaultId: randomId(),
      account: ACCOUNT,
      deviceId: randomId(),
      name: opts.name ?? 'deploy-api-key',
      purpose: opts.purpose === undefined ? 'Deploy the staging app' : opts.purpose,
      operation: opts.operation ?? 'create',
      state: opts.state ?? 'pending_user',
      expiresAt: opts.expiresAt ?? Date.now() + 10 * 60 * 1000,
      receipt: null,
    };
  }

  get inputPub(): string {
    return b64encode(this.key.publicKey);
  }

  /** The context the device recorded when it issued the key. */
  context(): InputSealContext {
    const r = this.request;
    return { request_id: r.requestId, vault_id: r.vaultId, account: r.account, device_id: r.deviceId, name: r.name, purpose: r.purpose, operation: r.operation, expires_at: r.expiresAt };
  }

  /** The fragment the Worker builds (`inputFormUrl`). */
  linkHash(): string {
    const r = this.request;
    const parts = [`r=${r.requestId}`, `v=${r.vaultId}`, `k=${this.inputPub}`, `n=${encodeURIComponent(r.name)}`];
    if (r.purpose !== null) parts.push(`p=${encodeURIComponent(r.purpose)}`);
    return `#${parts.join('&')}`;
  }

  /** What `/input#…` becomes after the Worker's redirect: the dashboard URL with the link's fragment. */
  linkUrl(): string {
    return `${REDIRECT}${this.linkHash()}`;
  }

  authorize(authUrl: string): URL {
    const u = new URL(authUrl);
    if (u.origin !== ISSUER || u.pathname !== '/oauth/authorize') throw new Error('unexpected authorization endpoint');
    const p = u.searchParams;
    if (p.get('client_id') !== CLIENT_ID || p.get('redirect_uri') !== REDIRECT || p.get('resource') !== RESOURCE || p.get('scope') !== 'vault-app:session') throw new Error('bad authorization request');
    const code = b64encode(randomBytes(16));
    this.codes.set(code, { challenge: p.get('code_challenge')! });
    const cb = new URL(REDIRECT);
    cb.searchParams.set('code', code);
    cb.searchParams.set('state', p.get('state')!);
    cb.searchParams.set('iss', ISSUER);
    return cb;
  }

  calls(pathPart: string): LoggedExchange[] {
    return this.exchanges.filter((e) => e.url.includes(pathPart));
  }

  readonly fetch = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = (init.method ?? 'GET').toUpperCase();
    const requestBody = typeof init.body === 'string' ? init.body : '';
    const headers = new Headers(init.headers);
    if (this.knobs.offline) throw new TypeError('network down');
    const res = this.route(new URL(url), method, requestBody, headers);
    this.exchanges.push({ method, url, headers: Object.fromEntries([...headers].map(([k, v]) => [k.toLowerCase(), v])), requestBody, responseBody: await res.clone().text(), status: res.status, keepalive: init.keepalive === true });
    return res;
  };

  private issueApp(sub: string, sid: string): Response {
    const now = Math.floor(Date.now() / 1000);
    const access = fakeJwt({ iss: ISSUER, aud: RESOURCE, sub, client_id: CLIENT_ID, grant_id: sid, sid, scope: 'vault-app:session', jti: randomId(), iat: now, nbf: now, exp: now + 600 });
    const refresh = b64encode(randomBytes(32));
    this.appTokens.set(access, { sub, sid });
    this.refreshTokens.set(refresh, { sub, sid });
    return json(200, { access_token: access, token_type: 'Bearer', expires_in: 600, refresh_token: refresh, scope: 'vault-app:session' });
  }

  private route(url: URL, method: string, body: string, headers: Headers): Response {
    const bearer = (headers.get('Authorization') ?? '').replace(/^Bearer /, '');
    if (url.origin === ISSUER) {
      if (url.pathname === '/.well-known/oauth-authorization-server') {
        return json(200, {
          issuer: ISSUER, authorization_endpoint: `${ISSUER}/oauth/authorize`, token_endpoint: `${ISSUER}/oauth/token`,
          revocation_endpoint: `${ISSUER}/oauth/revoke`, code_challenge_methods_supported: ['S256'], authorization_response_iss_parameter_supported: true,
        });
      }
      if (url.pathname === '/oauth/token' && method === 'POST') {
        const f = new URLSearchParams(body);
        if (f.get('grant_type') !== 'authorization_code') return json(400, { error: 'unsupported_grant_type' });
        const entry = this.codes.get(f.get('code') ?? '');
        this.codes.delete(f.get('code') ?? '');
        if (!entry || b64encode(sha256(utf8Encode(f.get('code_verifier') ?? ''))) !== entry.challenge || f.get('resource') !== RESOURCE) return json(400, { error: 'invalid_grant' });
        return this.issueApp(ACCOUNT, `grant-${++this.grants}`);
      }
      if (url.pathname === '/oauth/revoke' && method === 'POST') {
        const token = new URLSearchParams(body).get('token') ?? '';
        this.revoked.push(token);
        const g = this.refreshTokens.get(token) ?? this.appTokens.get(token);
        // Revoking the grant also ends every `input` token minted from it (by `sid`).
        if (g) for (const m of [this.refreshTokens, this.appTokens, this.inputTokens]) for (const [k, v] of m) if (v.sid === g.sid) m.delete(k);
        return new Response(null, { status: 200 });
      }
      if (url.pathname === '/api/agentkit/vault/input-token' && method === 'POST') {
        if (body !== '') return json(400, { error: 'invalid_request' });
        const app = this.appTokens.get(bearer);
        if (!app) return json(401, { error: 'not_authenticated' });
        if (this.knobs.inputTokenStatus !== null) return json(this.knobs.inputTokenStatus, { error: 'refused' });
        const now = Math.floor(Date.now() / 1000);
        const claims: Record<string, unknown> = {
          iss: ISSUER, aud: INPUT_AUDIENCE, sub: app.sub, sid: app.sid, session_kind: 'input', jti: randomId(), iat: now, nbf: now, exp: now + 300,
          ...this.knobs.inputClaims,
        };
        for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
        const token = fakeJwt(claims);
        this.inputTokens.set(token, app);
        return json(200, { access_token: token, token_type: 'Bearer', expires_in: 300 });
      }
      return json(404, { error: 'not_found' });
    }
    if (url.origin !== ORIGIN) return json(404, { error: 'unknown origin' });
    if (url.pathname === '/app/config.json') {
      return json(200, { v: 1, issuer: ISSUER, client_id: CLIENT_ID, redirect_uri: REDIRECT, resource: RESOURCE, scope: 'vault-app:session' });
    }
    const r = this.request;
    if (url.pathname !== `/v1/vaults/${r.vaultId}/input-requests/${r.requestId}` || url.search !== '') return json(404, { error: { code: 'not_found', message: 'not found' } });
    if (this.knobs.reject401 > 0) {
      this.knobs.reject401--;
      return json(401, { error: { code: 'unauthorized', message: 'authentication failed' } });
    }
    const session = this.inputTokens.get(bearer);
    if (!session) return json(401, { error: { code: 'unauthorized', message: 'authentication failed' } });
    if (session.sub !== r.account) return json(404, { error: { code: 'not_found', message: 'not found' } });
    if (method === 'GET') {
      if (this.knobs.getStatus !== null) return json(this.knobs.getStatus, { error: { code: 'synthetic', message: 'synthetic' } });
      return json(200, { request_id: this.knobs.getRequestId ?? r.requestId, state: r.state, operation: r.operation, client_id: REQUESTING_CLIENT, device_id: r.deviceId, expires_at: r.expiresAt });
    }
    if (method !== 'POST') return json(404, { error: { code: 'not_found', message: 'not found' } });
    const answer = this.knobs.postAnswers.shift();
    if (answer) return answer;
    if (r.state !== 'pending_user') return json(409, { error: { code: 'conflict', message: 'input request is not open', state: r.state } });
    const parsed = JSON.parse(body) as Record<string, unknown>;
    if (Object.keys(parsed).join(',') !== 'sealed') return json(400, { error: { code: 'bad_request', message: 'malformed request', state: 'pending_user' } });
    try {
      this.delivered.push(openInput(this.key.secretKey, parsed['sealed'], this.context()));
    } catch {
      r.state = 'failed';
      return json(400, { error: { code: 'bad_request', message: 'the device could not open the sealed value', state: 'failed' } });
    }
    r.state = 'completed';
    r.receipt = `rcpt-${randomId()}`;
    return json(200, { status: 'stored', receipt: r.receipt });
  }

  /** A POST answer as the Worker gives it for a non-success outcome. */
  static error(status: number, code: string, state: string | null, headers: Record<string, string> = {}): Response {
    return json(status, { error: { code, message: 'synthetic', ...(state === null ? {} : { state }) } }, headers);
  }
}

export interface InputPage {
  controller: InputController;
  root: HTMLElement;
  navigated: string[];
  replaced: string[];
}

/** Load the bundle's input form at `url` in a fresh page that shares this tab's sessionStorage. */
export async function loadInputPage(world: FakeInputWorld, url: string | URL): Promise<InputPage> {
  document.body.textContent = '';
  const root = document.createElement('div');
  root.id = 'app';
  document.body.appendChild(root);
  const navigated: string[] = [];
  const replaced: string[] = [];
  const controller = new InputController({
    origin: ORIGIN,
    fetchFn: world.fetch as typeof fetch,
    pending: sessionPendingStore(window.sessionStorage, INPUT_PENDING_KEY),
    navigate: (u) => navigated.push(u),
    replaceUrl: (u) => replaced.push(u),
  });
  controller.subscribe((s) => renderInput(root, controller, s));
  await controller.boot(new URL(url));
  return { controller, root, navigated, replaced };
}

/** Open the link, press "Sign in to continue", and come back on the callback. */
export async function signInFromLink(world: FakeInputWorld): Promise<{ linkPage: InputPage; page: InputPage }> {
  const linkPage = await loadInputPage(world, world.linkUrl());
  linkPage.controller.signIn();
  const authUrl = linkPage.navigated.at(-1);
  if (!authUrl) throw new Error('no navigation');
  const page = await loadInputPage(world, world.authorize(authUrl));
  return { linkPage, page };
}
