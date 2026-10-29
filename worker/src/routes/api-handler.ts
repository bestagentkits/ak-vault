/**
 * `/v1/*` pipeline in the Worker: kill switch -> route -> body limits -> ES256
 * token -> live revocation -> vault Durable Object (rate budget, membership, proof, scope,
 * role, rate charge, idempotency, mutation). Only `/v1/meta` bypasses auth and the kill switch.
 *
 * `GET /v1/relay` (remote access only) runs the same kill switch, token and revocation
 * checks plus the relay session rules, then hands the upgrade to the account's relay
 * object, which verifies the proof and owns the connection.
 */
import { assertDeviceNotRevoked, isGrantRevoked } from '../auth/revocation-check.js';
import { b64decodeLength } from '@ak-vault/protocol';
import { bearerToken, verifyToken } from '../auth/jwt-verify.js';
import { remoteAccessEnabled, type Env } from '../env.js';
import { ApiError, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { LIMITS } from '../limits.js';
import { relayStub } from '../relay/relay-rpc.js';
import { RELAY_OPEN_HEADER, deviceKeyMatches, encodeRelayOpen, relaySessionRefusal } from '../relay/relay-session.js';
import { isMutation } from '../vault/vault-request.js';
import { matchVaultRoute } from './api-routes.js';
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
  const writeRequestId = route.writeRequestId ?? writeRequestParam(url, route.op, remoteAccess);
  // A human write request lives only while the MCP grant that asked for it does (spec §3.10).
  // Only the caller's own request is looked up; the vault object then runs membership and proof.
  if (writeRequestId !== undefined && route.op !== 'writereq.close') {
    const grant = await stub.writeRequestGrant(writeRequestId, claims.sub);
    if (grant && (await isGrantRevoked(env, grant))) await stub.cancelRevokedWriteRequest(writeRequestId);
  }
  // A sealed write lives only while the MCP grant that queued it does (spec §3.6): cancel the
  // caller's pending operations of any revoked grant before the queue is served.
  if (route.op === 'sealed.get') {
    for (const grant of await stub.pendingSealedGrants(claims.sub)) {
      if (await isGrantRevoked(env, { sub: claims.sub, ...grant })) await stub.cancelRevokedSealed(claims.sub, grant);
    }
  }
  return stub.handle({
    op: route.op,
    vaultId: route.vaultId,
    ...(route.itemId ? { itemId: route.itemId } : {}),
    ...(route.sealedId ? { sealedId: route.sealedId } : {}),
    ...(writeRequestId !== undefined ? { writeRequestId } : {}),
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

/** The `write_request` query of an item PUT (the person's completion of a write request), validated; undefined when absent. */
function writeRequestParam(url: URL, op: string, remoteAccess: boolean): string | undefined {
  const values = url.searchParams.getAll('write_request');
  if (values.length === 0 || op !== 'item.put') return undefined;
  if (!remoteAccess || values.length > 1) throw new ApiError('bad_request');
  try {
    b64decodeLength(values[0]!, 16);
  } catch {
    throw new ApiError('bad_request', { message: 'malformed write_request' });
  }
  return values[0];
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
