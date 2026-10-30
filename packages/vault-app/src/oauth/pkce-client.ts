/**
 * OAuth 2.1 sign-in against the ak-web authorization server: authorization code
 * with PKCE S256 (RFC 7636), `resource` = `<origin>/app` (RFC 8707), scope
 * `vault-app:session`, `state`, and the RFC 9207 `iss` check. The client ID is
 * the dashboard's Client ID Metadata Document URL.
 *
 * Tokens live in memory only (`OAuthSession`). The only thing that survives the
 * redirect to the authorization server and back is the pending `{state,
 * verifier}` pair in `sessionStorage` (with the two opaque IDs of a write-request
 * link, or the input-request link with its name and purpose, the sign-in was
 * started from), removed the moment the callback reads it and refused after ten
 * minutes. The input form keeps its pending sign-in under its own key.
 * Revocation (RFC 7009) ends the grant when the dashboard signs out, locks, is
 * closed, or signs in again.
 */
import { b64decode, b64encode, randomBytes, sha256, utf8Decode, utf8Encode } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import { APP_SCOPE, type AppConfig } from '../config.js';
import { checkInputLink, type InputLink } from '../input/input-link.js';
import { isOpaqueId, type WriteLink } from '../sync/write-request.js';

/** The subset of RFC 8414 metadata the dashboard uses, validated. */
export interface AuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  revocation_endpoint: string;
  iss_parameter_supported: boolean;
}

/** Claims of the app access token the dashboard reads (it never verifies them; ak-web and the Worker do). */
export interface AppTokenClaims {
  sub: string;
  /** The sign-in grant ID; the browser device signs it in the token exchange. */
  sid: string;
  exp: number;
}

export interface OAuthSession {
  accessToken: string;
  refreshToken: string | null;
  /** Unix seconds when the access token expires. */
  expiresAt: number;
  claims: AppTokenClaims;
}

export interface PendingSignIn {
  state: string;
  verifier: string;
  /** Unix ms when the sign-in started. */
  createdAt: number;
  /** The write-request link this sign-in continues to. */
  writeLink?: WriteLink;
  /** The input-request link this sign-in continues to (input form only). */
  inputLink?: InputLink;
}

/** Where the pending sign-in waits across the redirect (sessionStorage in the browser). */
export interface PendingStore {
  save(pending: PendingSignIn): void;
  /** Return and delete the pending sign-in. */
  take(): PendingSignIn | null;
}

const PENDING_KEY = 'akv-dashboard-signin';
/** The input form's pending sign-in, kept apart from the dashboard's. */
export const INPUT_PENDING_KEY = 'akv-input-signin';
/** ak-web keeps a consent request for ten minutes; a slower callback is refused. */
const PENDING_MAX_AGE_MS = 10 * 60 * 1000;

export function sessionPendingStore(storage: Storage, key: string = PENDING_KEY): PendingStore {
  return {
    save(pending) {
      storage.setItem(key, JSON.stringify(pending));
    },
    take() {
      const raw = storage.getItem(key);
      storage.removeItem(key);
      if (raw === null) return null;
      try {
        const v = JSON.parse(raw) as Record<string, unknown>;
        if (typeof v['state'] !== 'string' || typeof v['verifier'] !== 'string' || typeof v['createdAt'] !== 'number') return null;
        const pending: PendingSignIn = { state: v['state'], verifier: v['verifier'], createdAt: v['createdAt'] };
        const link = v['writeLink'] as Record<string, unknown> | undefined;
        if (link !== undefined) {
          const { requestId, vaultId } = link ?? {};
          if (typeof requestId !== 'string' || typeof vaultId !== 'string' || !isOpaqueId(requestId) || !isOpaqueId(vaultId)) return null;
          pending.writeLink = { requestId, vaultId };
        }
        if (v['inputLink'] !== undefined) {
          const inputLink = checkInputLink(v['inputLink']);
          if (!inputLink) return null;
          pending.inputLink = inputLink;
        }
        return pending;
      } catch {
        return null;
      }
    },
  };
}

function sameOriginUrl(value: unknown, origin: string): string {
  if (typeof value !== 'string') throw new AppError('config_invalid');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AppError('config_invalid');
  }
  if (url.origin !== origin || url.hash || url.username || url.password) throw new AppError('config_invalid');
  return url.href;
}

/** Validate AS metadata: exact issuer, every endpoint on the issuer origin, S256 offered. */
export function parseAuthServerMetadata(value: unknown, issuer: string): AuthServerMetadata {
  if (typeof value !== 'object' || value === null) throw new AppError('config_invalid');
  const m = value as Record<string, unknown>;
  if (m['issuer'] !== issuer) throw new AppError('signin_issuer_mismatch');
  const origin = new URL(issuer).origin;
  const methods = m['code_challenge_methods_supported'];
  if (!Array.isArray(methods) || !methods.includes('S256')) throw new AppError('config_invalid');
  return {
    issuer,
    authorization_endpoint: sameOriginUrl(m['authorization_endpoint'], origin),
    token_endpoint: sameOriginUrl(m['token_endpoint'], origin),
    revocation_endpoint: sameOriginUrl(m['revocation_endpoint'], origin),
    iss_parameter_supported: m['authorization_response_iss_parameter_supported'] === true,
  };
}

export async function discoverAuthServer(fetchFn: typeof fetch, issuer: string): Promise<AuthServerMetadata> {
  let res: Response;
  try {
    res = await fetchFn(`${issuer}/.well-known/oauth-authorization-server`, { credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new AppError('network');
  }
  if (!res.ok) throw new AppError('config_invalid');
  return parseAuthServerMetadata(await res.json().catch(() => null), issuer);
}

/** PKCE S256 challenge of a verifier (RFC 7636 §4.2). */
export function pkceChallenge(verifier: string): string {
  return b64encode(sha256(utf8Encode(verifier)));
}

/**
 * Start a sign-in: store `{state, verifier}` and return the authorization URL.
 * The verifier is 32 random bytes in base64url (43 characters, RFC 7636 §4.1).
 */
export function beginSignIn(config: AppConfig, as: AuthServerMetadata, store: PendingStore, now = Date.now(), writeLink: WriteLink | null = null, inputLink: InputLink | null = null): string {
  const pending: PendingSignIn = {
    state: b64encode(randomBytes(32)), verifier: b64encode(randomBytes(32)), createdAt: now,
    ...(writeLink ? { writeLink } : {}), ...(inputLink ? { inputLink } : {}),
  };
  store.save(pending);
  const url = new URL(as.authorization_endpoint);
  const params: Record<string, string> = {
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: APP_SCOPE,
    resource: config.resource,
    state: pending.state,
    code_challenge: pkceChallenge(pending.verifier),
    code_challenge_method: 'S256',
  };
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.href;
}

/** Whether a page URL is an authorization response (it carries `code`, `error` or `state`). */
export function isAuthorizationResponse(url: URL): boolean {
  return url.searchParams.has('code') || url.searchParams.has('error') || url.searchParams.has('state');
}

function decodeClaims(token: string, config: AppConfig): AppTokenClaims {
  const parts = token.split('.');
  if (parts.length !== 3) throw new AppError('signin_refused');
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(utf8Decode(b64decode(parts[1]!))) as Record<string, unknown>;
  } catch {
    throw new AppError('signin_refused');
  }
  const { sub, sid, grant_id: grantId, exp, aud, iss, client_id: clientId } = payload;
  if (iss !== config.issuer || aud !== config.resource || clientId !== config.clientId) throw new AppError('signin_refused');
  if (typeof sub !== 'string' || !sub || typeof sid !== 'string' || !sid || sid !== grantId) throw new AppError('signin_refused');
  if (typeof exp !== 'number' || !Number.isSafeInteger(exp)) throw new AppError('signin_refused');
  if (typeof payload['scope'] !== 'string' || !payload['scope'].split(' ').includes(APP_SCOPE)) throw new AppError('signin_refused');
  return { sub, sid, exp };
}

async function tokenRequest(fetchFn: typeof fetch, as: AuthServerMetadata, config: AppConfig, form: Record<string, string>, now: number): Promise<OAuthSession> {
  let res: Response;
  try {
    res = await fetchFn(as.token_endpoint, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
    });
  } catch {
    throw new AppError('network');
  }
  if (!res.ok) throw new AppError(res.status >= 500 ? 'server' : 'signin_refused');
  const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body['access_token'] !== 'string' || typeof body['token_type'] !== 'string' || body['token_type'].toLowerCase() !== 'bearer') {
    throw new AppError('signin_refused');
  }
  const expiresIn = body['expires_in'];
  if (typeof expiresIn !== 'number' || !Number.isSafeInteger(expiresIn) || expiresIn <= 0) throw new AppError('signin_refused');
  const refresh = body['refresh_token'];
  const claims = decodeClaims(body['access_token'], config);
  return {
    accessToken: body['access_token'],
    refreshToken: typeof refresh === 'string' && refresh ? refresh : null,
    expiresAt: Math.min(claims.exp, Math.floor(now / 1000) + expiresIn),
    claims,
  };
}

/**
 * Finish a sign-in from the callback URL. Refused, without any token request,
 * when no sign-in is pending, the pending one is stale, `state` differs, the
 * server reports an error, or `iss` is missing (when advertised) or differs.
 * Returns the session and the write-request or input-request link the sign-in
 * was started from.
 */
export async function completeSignIn(
  url: URL,
  deps: { config: AppConfig; as: AuthServerMetadata; store: PendingStore; fetchFn: typeof fetch; now?: number },
): Promise<{ session: OAuthSession; writeLink: WriteLink | null; inputLink: InputLink | null }> {
  const now = deps.now ?? Date.now();
  const pending = deps.store.take();
  const q = url.searchParams;
  if (!pending || now - pending.createdAt > PENDING_MAX_AGE_MS || now < pending.createdAt) throw new AppError('signin_state_mismatch');
  if (q.getAll('state').length !== 1 || q.get('state') !== pending.state) throw new AppError('signin_state_mismatch');
  const iss = q.getAll('iss');
  if (iss.length > 1 || (iss.length === 1 && iss[0] !== deps.as.issuer) || (iss.length === 0 && deps.as.iss_parameter_supported)) {
    throw new AppError('signin_issuer_mismatch');
  }
  if (q.has('error')) throw new AppError('signin_refused');
  const code = q.getAll('code');
  if (code.length !== 1 || !code[0]) throw new AppError('signin_refused');
  const session = await tokenRequest(deps.fetchFn, deps.as, deps.config, {
    grant_type: 'authorization_code',
    code: code[0],
    redirect_uri: deps.config.redirectUri,
    client_id: deps.config.clientId,
    code_verifier: pending.verifier,
    resource: deps.config.resource,
  }, now);
  return { session, writeLink: pending.writeLink ?? null, inputLink: pending.inputLink ?? null };
}

/** Rotate the in-memory refresh token for a fresh access token of the same grant. */
export async function refreshSession(session: OAuthSession, deps: { config: AppConfig; as: AuthServerMetadata; fetchFn: typeof fetch; now?: number }): Promise<OAuthSession> {
  if (!session.refreshToken) throw new AppError('signin_required');
  const next = await tokenRequest(deps.fetchFn, deps.as, deps.config, {
    grant_type: 'refresh_token',
    refresh_token: session.refreshToken,
    client_id: deps.config.clientId,
    resource: deps.config.resource,
  }, deps.now ?? Date.now());
  // A refresh never changes the account or the grant.
  if (next.claims.sub !== session.claims.sub || next.claims.sid !== session.claims.sid) throw new AppError('signin_refused');
  return next;
}

/**
 * RFC 7009 revocation of the grant behind `session`, by its refresh token when
 * it has one (ak-web revokes the whole grant either way). `keepalive` lets it
 * finish while the page unloads. Best effort: a failure leaves a grant that
 * expires on its own (at most 12 hours) and is never pinned to a newer sign-in.
 */
export async function revokeSession(session: OAuthSession, deps: { config: AppConfig; as: AuthServerMetadata; fetchFn: typeof fetch; keepalive?: boolean }): Promise<boolean> {
  const form = session.refreshToken
    ? { token: session.refreshToken, token_type_hint: 'refresh_token', client_id: deps.config.clientId }
    : { token: session.accessToken, token_type_hint: 'access_token', client_id: deps.config.clientId };
  try {
    const res = await deps.fetchFn(deps.as.revocation_endpoint, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      keepalive: deps.keepalive === true,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
    });
    return res.ok;
  } catch {
    return false;
  }
}
