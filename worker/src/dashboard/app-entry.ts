/**
 * Vault dashboard at `/app` and `/app/*` (ADR 0002 D1): the static bundle built
 * into `./public/app` by `@ak-vault/vault-app`, its OAuth client metadata
 * document and its public configuration. The Worker entry routes these paths
 * here only where remote access is enabled and applies the dashboard security
 * headers (`withSecurityHeaders` with the path).
 *
 *   GET /app/client.json   Client ID Metadata Document; `client_id` is its own URL,
 *                          the only client ak-web lets hold an `<origin>/app` grant
 *   GET /app/config.json   the issuer the dashboard signs in with
 *   GET /app, /app/...     static assets; an unknown path is a JSON `not_found`
 *
 * Nothing here reads a token, a vault or a body, and no response sets a cookie.
 */
import { appResource, type Env } from '../env.js';
import { ApiError, errorResult } from '../http/errors.js';
import { jsonResponse, resultResponse } from '../http/responses.js';

export const APP_CLIENT_METADATA_PATH = '/app/client.json';
export const APP_CONFIG_PATH = '/app/config.json';

/** The dashboard's OAuth client ID: the URL of its metadata document. */
export function appClientId(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `${env.VAULT_AUDIENCE}${APP_CLIENT_METADATA_PATH}`;
}

/** The only redirect URI the dashboard registers: the dashboard document itself. */
export function appRedirectUri(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `${appResource(env)}/`;
}

/**
 * Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document):
 * a public client (PKCE, no secret) that may use only the authorization code
 * and refresh grants and redirects only to the dashboard on this origin.
 */
export function appClientMetadata(env: Pick<Env, 'VAULT_AUDIENCE'>): Record<string, unknown> {
  return {
    client_id: appClientId(env),
    client_name: 'AgentKit Vault dashboard',
    client_uri: appRedirectUri(env),
    redirect_uris: [appRedirectUri(env)],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    token_endpoint_auth_methods_supported: ['none'],
    scope: 'vault-app:session',
  };
}

/** Public configuration the bundle reads at start: nothing secret, all derived from deployed vars. */
export function appConfig(env: Pick<Env, 'VAULT_AUDIENCE' | 'VAULT_ISSUER'>): Record<string, unknown> {
  return {
    v: 1,
    issuer: env.VAULT_ISSUER,
    client_id: appClientId(env),
    redirect_uri: appRedirectUri(env),
    resource: appResource(env),
    scope: 'vault-app:session',
  };
}

const notFound = (): Response => resultResponse(errorResult(new ApiError('not_found')));

/** Static asset through the assets binding; never the landing site's 404 page, never a cookie. */
async function serveAppAsset(request: Request, env: Pick<Env, 'ASSETS'>): Promise<Response> {
  const asset = await env.ASSETS.fetch(request);
  // Redirects are the assets binding's own trailing-slash handling (`/app` -> `/app/`).
  if (asset.status >= 300 && asset.status < 400) {
    const location = asset.headers.get('Location');
    if (!location) return notFound();
    return new Response(null, { status: asset.status, headers: { Location: location, 'Cache-Control': 'no-store' } });
  }
  if (!asset.ok) return notFound();
  const out = new Response(request.method === 'HEAD' ? null : asset.body, asset);
  out.headers.delete('Set-Cookie');
  if ((out.headers.get('Content-Type') ?? '').startsWith('text/html')) {
    // Only the dashboard document is HTML; `no-transform` keeps the proxy from injecting scripts.
    out.headers.set('Cache-Control', 'no-store, no-transform');
  }
  return out;
}

export async function handleApp(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return notFound();
  const { pathname } = new URL(request.url);
  if (pathname === APP_CLIENT_METADATA_PATH) {
    // ak-web caches the document for at most this long.
    return jsonResponse(appClientMetadata(env), 200, { 'Cache-Control': 'public, max-age=300' });
  }
  if (pathname === APP_CONFIG_PATH) return jsonResponse(appConfig(env));
  return serveAppAsset(request, env);
}
