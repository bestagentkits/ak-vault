/**
 * ak-vault Worker entry. One Worker serves:
 *   GET /healthz, GET /v1/meta       public, always on
 *   /v1/vaults/...                    sync API (kill switch VAULT_SYNC_ENABLED)
 *   GET /v1/relay                     device relay WebSocket (remote access only)
 *   /mcp, /.well-known/oauth-protected-resource/mcp
 *                                     remote MCP endpoint (remote access only)
 *   /app, /app/*                      vault dashboard (remote access only)
 *   POST /internal/v1/revocations     HMAC-authenticated ak-web revocation feed
 *   POST /internal/v1/operator        HMAC-authenticated operator restore of one
 *                                     vault (404 unless its secret is set)
 *   everything else                   landing site from ./public
 * Remote-access paths answer 404 unless VAULT_REMOTE_ACCESS_ENABLED is "true".
 * Every response carries the security headers; every API request emits exactly
 * one operational log line (route template, status, code, latency, vault tag).
 */
import { handleApp } from './dashboard/app-entry.js';
import { remoteAccessEnabled, type Env } from './env.js';
import { ApiError, errorResult, toApiError, type ApiResult } from './http/errors.js';
import { logRequest } from './http/operational-logger.js';
import { isAppPath, resultResponse, withSecurityHeaders } from './http/responses.js';
import { serveAsset } from './http/static-assets.js';
import { handleMcp } from './mcp/mcp-entry.js';
import { PRM_MCP_PATH } from './mcp/protected-resource-metadata.js';
import { RELAY_PATH, handleApi, handleRelayUpgrade, type RouteInfo } from './routes/api-handler.js';
import { healthz } from './routes/meta-routes.js';
import { handleRevocationWebhook } from './routes/revocation-webhook.js';
import { handleOperatorRequest, OPERATOR_PATH } from './routes/operator-restore.js';

export { VaultDurableObject } from './vault/vault-durable-object.js';
export { RevocationRegistry } from './revocation/revocation-registry.js';
export { AccountRelay } from './relay/account-relay-durable-object.js';

const MCP_PATHS: ReadonlySet<string> = new Set(['/mcp', PRM_MCP_PATH]);

async function route(request: Request, env: Env, info: RouteInfo): Promise<ApiResult> {
  const { pathname } = new URL(request.url);
  if (pathname === '/healthz') {
    info.template = 'GET /healthz';
    if (request.method !== 'GET' && request.method !== 'HEAD') throw new ApiError('not_found');
    return healthz(env);
  }
  if (pathname === '/internal/v1/revocations') {
    info.template = 'POST /internal/v1/revocations';
    return handleRevocationWebhook(request, env);
  }
  if (pathname === OPERATOR_PATH) {
    info.template = 'POST /internal/v1/operator';
    return handleOperatorRequest(request, env, info);
  }
  if (pathname.startsWith('/internal/')) throw new ApiError('not_found');
  return handleApi(request, env, info);
}

/** Routes whose handlers build their own `Response` (WebSocket upgrade, MCP, dashboard). */
async function routeResponse(request: Request, env: Env, info: RouteInfo, pathname: string): Promise<Response> {
  if (pathname === RELAY_PATH) return handleRelayUpgrade(request, env, info);
  if (MCP_PATHS.has(pathname)) {
    info.template = pathname;
    if (!remoteAccessEnabled(env)) throw new ApiError('not_found');
    return handleMcp(request, env);
  }
  info.template = '/app';
  if (!remoteAccessEnabled(env)) throw new ApiError('not_found');
  return handleApp(request, env);
}

function isApiPath(pathname: string): boolean {
  return pathname === '/healthz' || pathname === '/v1' || pathname.startsWith('/v1/') || pathname.startsWith('/internal/');
}

function isResponsePath(pathname: string): boolean {
  return pathname === RELAY_PATH || MCP_PATHS.has(pathname) || isAppPath(pathname);
}

/** The stable error code of a JSON error response, for the log line; never the body itself. */
async function errorCodeOf(response: Response): Promise<string | undefined> {
  if (response.status < 400 || !response.headers.get('Content-Type')?.startsWith('application/json')) return undefined;
  try {
    const body = (await response.clone().json()) as { error?: { code?: unknown } };
    const code = body.error?.code;
    return typeof code === 'string' && /^[a-z_]{1,64}$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    const started = Date.now();
    const info: RouteInfo = { template: 'unmatched' };

    if (isResponsePath(pathname)) {
      let response: Response;
      try {
        response = await routeResponse(request, env, info, pathname);
      } catch (err) {
        response = resultResponse(errorResult(toApiError(err)));
      }
      logRequest({ route: info.template, status: response.status, code: await errorCodeOf(response), ms: Date.now() - started });
      // A 101 carries the client end of the WebSocket, which copying the response would drop.
      if (response.status === 101) return response;
      return withSecurityHeaders(response, { pathname, env });
    }

    if (!isApiPath(pathname)) return serveAsset(request, env);
    let result: ApiResult;
    try {
      result = await route(request, env, info);
    } catch (err) {
      result = errorResult(toApiError(err));
    }
    logRequest({ route: info.template, status: result.status, code: result.code, ms: Date.now() - started, vaultId: info.vaultId });
    return withSecurityHeaders(resultResponse(result));
  },
} satisfies ExportedHandler<Env>;
