/**
 * `/v1/*` pipeline in the Worker: kill switch -> route -> body limits -> ES256
 * token -> live revocation -> vault Durable Object (membership, proof, scope,
 * role, idempotency, mutation). Only `/v1/meta` bypasses auth and the kill switch.
 */
import { assertNotRevoked } from '../auth/revocation-check.js';
import { bearerToken, verifyToken } from '../auth/jwt-verify.js';
import type { Env } from '../env.js';
import { ApiError, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { LIMITS } from '../limits.js';
import { isMutation } from '../vault/vault-request.js';
import { matchVaultRoute } from './api-routes.js';
import { meta, syncEnabled } from './meta-routes.js';

export interface RouteInfo {
  template: string;
  vaultId?: string;
}

export async function handleApi(request: Request, env: Env, info: RouteInfo): Promise<ApiResult> {
  const url = new URL(request.url);
  if (url.pathname === '/v1/meta') {
    info.template = 'GET /v1/meta';
    if (request.method !== 'GET') throw new ApiError('not_found');
    return meta(env);
  }
  if (!syncEnabled(env)) throw new ApiError('sync_disabled');
  const route = matchVaultRoute(request.method, url.pathname);
  if (!route) throw new ApiError('not_found');
  info.template = route.template;
  info.vaultId = route.vaultId;

  const token = bearerToken(request);
  const claims = await verifyToken(token, env);
  await assertNotRevoked(env, claims);
  const body = await readBodyCapped(request, LIMITS.request_body_max_bytes);
  const idempotencyKey = request.headers.get('Idempotency-Key');
  if (isMutation(route.op) && !idempotencyKey) throw new ApiError('bad_request', { message: 'a valid Idempotency-Key header is required' });

  const stub = env.VAULT.get(env.VAULT.idFromName(route.vaultId));
  return stub.handle({
    op: route.op,
    vaultId: route.vaultId,
    ...(route.itemId ? { itemId: route.itemId } : {}),
    method: request.method,
    htu: request.url,
    path: url.pathname,
    query: Object.fromEntries(url.searchParams),
    token,
    proof: request.headers.get('AKV-Proof') ?? '',
    idempotencyKey,
    deviceKey: request.headers.get('AKV-Device-Key'),
    body,
    claims,
    nowMs: Date.now(),
  });
}
