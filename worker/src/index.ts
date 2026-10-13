/**
 * ak-vault Worker entry. One Worker serves:
 *   GET /healthz, GET /v1/meta       public, always on
 *   /v1/vaults/...                    sync API (kill switch VAULT_SYNC_ENABLED)
 *   POST /internal/v1/revocations     HMAC-authenticated ak-web revocation feed
 *   everything else                   landing site from ./public
 * Every response carries the security headers; every API request emits exactly
 * one operational log line (route template, status, code, latency, vault tag).
 */
import type { Env } from './env.js';
import { errorResult, toApiError, type ApiResult } from './http/errors.js';
import { logRequest } from './http/operational-logger.js';
import { resultResponse, withSecurityHeaders } from './http/responses.js';
import { serveAsset } from './http/static-assets.js';
import { handleApi, type RouteInfo } from './routes/api-handler.js';
import { healthz } from './routes/meta-routes.js';
import { handleRevocationWebhook } from './routes/revocation-webhook.js';
import { ApiError } from './http/errors.js';

export { VaultDurableObject } from './vault/vault-durable-object.js';
export { RevocationRegistry } from './revocation/revocation-registry.js';

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
  if (pathname.startsWith('/internal/')) throw new ApiError('not_found');
  return handleApi(request, env, info);
}

function isApiPath(pathname: string): boolean {
  return pathname === '/healthz' || pathname === '/v1' || pathname.startsWith('/v1/') || pathname.startsWith('/internal/');
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (!isApiPath(pathname)) return serveAsset(request, env);
    const started = Date.now();
    const info: RouteInfo = { template: 'unmatched' };
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
