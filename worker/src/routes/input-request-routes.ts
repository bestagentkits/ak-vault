/**
 * Device-sealed input request routes (spec §3.11, ADR 0004), served only where
 * remote access and input requests are enabled:
 *
 *   GET  /v1/vaults/:vid/input-requests/:rid   state, operation, client, device, expiry
 *   POST /v1/vaults/:vid/input-requests/:rid   `{"sealed": <input seal>}`, once
 *
 * Order: kill switch (caller) -> route -> `input` session token for `<origin>/input`
 * -> live revocation of its `sid` (lookup error: 503) -> the requesting MCP grant's
 * revocation (a revoked one cancels the request) -> the vault object, scoped to the
 * token's account (another account's request is a 404 like an unknown one). The POST
 * claims the request (`pending_user` -> `submitted`) in one vault transaction, relays
 * the sealed value to the issuing device only (`input_deliver`), and settles the
 * request from the device's answer. The ciphertext is never stored, logged or put in
 * an error, and no device text is echoed.
 */
import { b64decodeLength, isAkvError, parseInputSeal, type InputSealWire, type JsonObject, type RelayErrorCode } from '@ak-vault/protocol';
import { bearerToken, verifyInputToken, type InputClaims } from '../auth/jwt-verify.js';
import { assertGrantNotRevoked, isGrantRevoked } from '../auth/revocation-check.js';
import type { Env } from '../env.js';
import { ApiError, errorResult, okResult, toApiError, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { LIMITS, REMOTE_ACCESS_LIMITS } from '../limits.js';
import { relayStub, type RelayOutcome } from '../relay/relay-rpc.js';
import { parseBodyObject, requireKeys } from '../vault/request-body.js';
import type { WriteRequestReason } from '../vault/write-request-store.js';
import type { RouteInfo } from './api-handler.js';

export interface InputRoute {
  method: 'GET' | 'POST';
  template: string;
  vaultId: string;
  requestId: string;
}

function opaqueId(value: string): string {
  try {
    b64decodeLength(value, 16);
  } catch {
    throw new ApiError('bad_request', { message: 'malformed id in path' });
  }
  return value;
}

/** Match `/v1/vaults/:vid/input-requests/:rid`; null for any other path or method (404). */
export function matchInputRoute(method: string, pathname: string): InputRoute | null {
  const parts = pathname.split('/');
  // ['', 'v1', 'vaults', vid, 'input-requests', rid]
  if (parts.length !== 6 || parts[1] !== 'v1' || parts[2] !== 'vaults' || parts[4] !== 'input-requests' || !parts[3] || !parts[5]) return null;
  if (method !== 'GET' && method !== 'POST') return null;
  return { method, template: `${method} /v1/vaults/:vid/input-requests/:rid`, vaultId: opaqueId(parts[3]), requestId: opaqueId(parts[5]) };
}

function vaultStub(env: Env, vaultId: string) {
  return env.VAULT.get(env.VAULT.idFromName(vaultId));
}

/** The `{"sealed": …}` body: exactly that key, a structurally valid seal for this request. */
function parseSubmission(body: Uint8Array, requestId: string): InputSealWire {
  const obj = parseBodyObject(body);
  requireKeys(obj, ['sealed']);
  let sealed: InputSealWire;
  try {
    sealed = parseInputSeal(obj['sealed']);
  } catch (err) {
    // Unknown v/alg keep `unsupported_version`; every other shape error is `bad_request`.
    if (isAkvError(err)) throw toApiError(err);
    throw err;
  }
  if (sealed.request_id !== requestId) throw new ApiError('bad_request', { message: 'sealed value belongs to another request' });
  return sealed;
}

/** How a device refusal of `input_deliver` closes the request, and the HTTP answer. Nothing from the device is echoed. */
const DEVICE_REFUSAL: Record<RelayErrorCode, { state: 'failed' | 'expired' | 'conflict'; reason: WriteRequestReason | null; error: () => ApiError }> = {
  not_found: { state: 'failed', reason: 'device_lost', error: () => new ApiError('expired', { message: 'the device no longer holds this request', extra: { state: 'failed' } }) },
  expired: { state: 'expired', reason: null, error: () => new ApiError('expired', { message: 'input request expired', extra: { state: 'expired' } }) },
  decrypt_failed: { state: 'failed', reason: 'decrypt_failed', error: () => new ApiError('bad_request', { message: 'the device could not open the sealed value', extra: { state: 'failed' } }) },
  conflict: { state: 'conflict', reason: 'revision_conflict', error: () => new ApiError('conflict', { message: 'the secret changed concurrently', extra: { state: 'conflict' } }) },
  invalid_args: { state: 'failed', reason: 'bad_request', error: () => new ApiError('bad_request', { message: 'the device refused the sealed value', extra: { state: 'failed' } }) },
  denied: { state: 'failed', reason: 'denied', error: () => new ApiError('forbidden', { message: 'the device refused this request', extra: { state: 'failed' } }) },
  pending_approval: { state: 'failed', reason: 'internal', error: () => new ApiError('internal', { extra: { state: 'failed' } }) },
  unsupported: { state: 'failed', reason: 'internal', error: () => new ApiError('internal', { extra: { state: 'failed' } }) },
  internal: { state: 'failed', reason: 'internal', error: () => new ApiError('internal', { extra: { state: 'failed' } }) },
};

async function submit(env: Env, claims: InputClaims, route: InputRoute, sealed: InputSealWire): Promise<ApiResult> {
  const stub = vaultStub(env, route.vaultId);
  const claimed = await stub.claimInputRequest(route.requestId, claims.sub);
  if ('error' in claimed) return claimed.error as ApiResult;
  const { claim } = claimed;
  let outcome: RelayOutcome;
  try {
    outcome = (await relayStub(env, claims.sub).dispatch({
      vaultId: route.vaultId,
      tool: 'input_deliver',
      args: { request_id: route.requestId, sealed: sealed as unknown as JsonObject },
      // The request's own MCP caller; the input tools need `vault-mcp:write`.
      caller: { clientId: claim.clientId, grantId: claim.grantId, scopes: ['vault-mcp:write'] },
      deadlineMs: REMOTE_ACCESS_LIMITS.relay_call_deadline_ms,
      deviceId: claim.deviceId,
    })) as RelayOutcome;
  } catch (err) {
    // The frame may already have reached the device, whose PUT could still land: close the
    // request rather than reopen it, so a later submission can never complete with this value.
    await stub.settleInputRequest(route.requestId, 'failed', 'internal');
    throw err;
  }
  switch (outcome.kind) {
    case 'no_device_online':
      await stub.releaseInputRequest(route.requestId);
      return errorResult(new ApiError('device_offline', { headers: { 'Retry-After': '5' }, extra: { state: 'pending_user' } }));
    case 'device_busy':
      await stub.releaseInputRequest(route.requestId);
      return errorResult(new ApiError('rate_limited', { headers: { 'Retry-After': '1' }, extra: { state: 'pending_user' } }));
    case 'invalid_args':
    case 'denied':
      // Refused by the relay before any frame was sent (oversize frame, caller); not a device answer.
      await stub.releaseInputRequest(route.requestId);
      return errorResult(new ApiError('bad_request', { message: 'the sealed value cannot be delivered', extra: { state: 'pending_user' } }));
    case 'timeout': {
      const after = await stub.settleInputRequest(route.requestId, 'failed', 'timeout');
      return errorResult(new ApiError('device_timeout', { extra: { state: after?.state ?? 'failed' } }));
    }
    case 'result':
      break;
  }
  if (!outcome.ok) {
    const refusal = DEVICE_REFUSAL[outcome.code];
    await stub.settleInputRequest(route.requestId, refusal.state, refusal.reason);
    return errorResult(refusal.error());
  }
  // The device's item PUT completed the request in the vault's transaction; its receipt must match.
  const receipt = (outcome.result as JsonObject)['receipt'];
  const after = await stub.settleInputRequest(route.requestId, 'failed', 'internal');
  if (after?.state !== 'completed' || after.receipt !== receipt) return errorResult(new ApiError('internal', { extra: { state: after?.state ?? 'failed' } }));
  return okResult({ status: 'stored', receipt });
}

/** Serve one input-request route; the caller has checked the kill switch and both flags. */
export async function handleInputRequest(request: Request, env: Env, info: RouteInfo, route: InputRoute): Promise<ApiResult> {
  info.template = route.template;
  info.vaultId = route.vaultId;
  if (new URL(request.url).search !== '') throw new ApiError('bad_request', { message: 'this route takes no query' });
  const claims = await verifyInputToken(bearerToken(request), env);
  await assertGrantNotRevoked(env, claims);
  const stub = vaultStub(env, route.vaultId);
  // A request lives only while the MCP grant that asked for it does (spec §3.10).
  const grant = await stub.writeRequestGrant(route.requestId, claims.sub);
  if (grant && (await isGrantRevoked(env, grant))) await stub.cancelRevokedWriteRequest(route.requestId);
  if (route.method === 'GET') return stub.getInputRequest(route.requestId, claims.sub);
  const sealed = parseSubmission(await readBodyCapped(request, LIMITS.request_body_max_bytes), route.requestId);
  return submit(env, claims, route, sealed);
}
