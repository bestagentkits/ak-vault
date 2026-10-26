/**
 * `/v1/*` pipeline in the Worker: kill switch -> route -> body limits -> ES256
 * token -> live revocation -> vault Durable Object (rate budget, membership, proof, scope,
 * role, rate charge, idempotency, mutation). Only `/v1/meta` bypasses auth and the kill switch.
 *
 * `/v1/write-intents/*` (remote access only) is the browser half of a human-only write
 * request: the same token, revocation and proof checks, then the account's relay object.
 *
 * `GET /v1/relay` (remote access only) runs the same kill switch, token and revocation
 * checks plus the relay session rules, then hands the upgrade to the account's relay
 * object, which verifies the proof and owns the connection.
 */
import { assertDeviceNotRevoked } from '../auth/revocation-check.js';
import { bearerToken, verifyToken } from '../auth/jwt-verify.js';
import { remoteAccessEnabled, type Env } from '../env.js';
import { ApiError, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { LIMITS } from '../limits.js';
import { relayStub } from '../relay/relay-rpc.js';
import { RELAY_OPEN_HEADER, deviceKeyMatches, encodeRelayOpen, relaySessionRefusal } from '../relay/relay-session.js';
import { isMutation } from '../vault/vault-request.js';
import { matchVaultRoute } from './api-routes.js';
import { handleWriteIntent, matchWriteIntentRoute } from './write-intent-routes.js';
import { meta, syncEnabled } from './meta-routes.js';

export interface RouteInfo {
  template: string;
  vaultId?: string;
}

export const RELAY_PATH = '/v1/relay';

export async function handleApi(request: Request, env: Env, info: RouteInfo): Promise<ApiResult> {
  const url = new URL(request.url);
  if (url.pathname === '/v1/meta') {
    info.template = 'GET /v1/meta';
    if (request.method !== 'GET') throw new ApiError('not_found');
    return meta(env);
  }
  if (!syncEnabled(env)) throw new ApiError('sync_disabled');
  const remoteAccess = remoteAccessEnabled(env);
  const intentRoute = remoteAccess ? matchWriteIntentRoute(request.method, url.pathname) : null;
  if (intentRoute) {
    info.template = intentRoute.template;
    return handleWriteIntent(request, env, intentRoute);
  }
  const route = matchVaultRoute(request.method, url.pathname, { remoteAccess });
  if (!route) throw new ApiError('not_found');
  info.template = route.template;
  info.vaultId = route.vaultId;

  const token = bearerToken(request);
  const claims = await verifyToken(token, env);
  await assertDeviceNotRevoked(env, claims);
  const body = await readBodyCapped(request, LIMITS.request_body_max_bytes);
  const idempotencyKey = request.headers.get('Idempotency-Key');
  if (isMutation(route.op) && !idempotencyKey) throw new ApiError('bad_request', { message: 'a valid Idempotency-Key header is required' });

  const stub = env.VAULT.get(env.VAULT.idFromName(route.vaultId));
  return stub.handle({
    op: route.op,
    vaultId: route.vaultId,
    ...(route.itemId ? { itemId: route.itemId } : {}),
    ...(route.sealedId ? { sealedId: route.sealedId } : {}),
    method: request.method,
    htu: request.url,
    path: url.pathname,
    query: Object.fromEntries(url.searchParams),
    queryList: [...url.searchParams],
    token,
    proof: request.headers.get('AKV-Proof') ?? '',
    idempotencyKey,
    deviceKey: request.headers.get('AKV-Device-Key'),
    body,
    claims,
    nowMs: Date.now(),
    remoteAccess,
  });
}

/**
 * Authenticate a relay upgrade (spec §9.7) and forward it to the account's relay
 * object. Returns the object's response (101 on success) or throws a stable error.
 */
export async function handleRelayUpgrade(request: Request, env: Env, info: RouteInfo): Promise<Response> {
  if (!remoteAccessEnabled(env)) throw new ApiError('not_found');
  info.template = 'GET /v1/relay';
  if (request.method !== 'GET') throw new ApiError('not_found');
  if (!syncEnabled(env)) throw new ApiError('sync_disabled');
  const url = new URL(request.url);
  if (url.search !== '') throw new ApiError('bad_request', { message: 'the relay URL takes no query' });
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    throw new ApiError('bad_request', { status: 426, message: 'a WebSocket upgrade is required', headers: { Upgrade: 'websocket' } });
  }

  const token = bearerToken(request);
  const claims = await verifyToken(token, env);
  const refusal = relaySessionRefusal(claims);
  if (refusal === 'kind') throw new ApiError('forbidden', { message: 'this session kind cannot hold a relay connection' });
  if (refusal === 'scope') throw new ApiError('forbidden', { message: 'the relay needs vault:read and vault:write' });
  await assertDeviceNotRevoked(env, claims);
  const signPub = request.headers.get('AKV-Device-Key');
  if (!deviceKeyMatches(signPub, claims.did)) throw new ApiError('unauthorized', { message: 'AKV-Device-Key does not match the token device' });
  const proof = request.headers.get('AKV-Proof');
  if (!proof) throw new ApiError('unauthorized', { message: 'AKV-Proof is required' });

  const forwarded = new Request(request.url, {
    method: 'GET',
    headers: {
      Upgrade: 'websocket',
      [RELAY_OPEN_HEADER]: encodeRelayOpen({
        sub: claims.sub,
        did: claims.did,
        sid: claims.sid,
        iat: claims.iat,
        exp: claims.exp,
        signPub,
        token,
        proof,
        htu: `${url.origin}${RELAY_PATH}`,
      }),
    },
  });
  return relayStub(env, claims.sub).fetch(forwarded);
}
