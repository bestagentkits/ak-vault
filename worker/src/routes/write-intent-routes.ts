/**
 * Browser side of human-only write requests (spec §9.9), remote access only:
 *
 *   GET  /v1/write-intents/:rid             what the form needs (vault, operation, sealed target)
 *   POST /v1/write-intents/:rid/claim       bind one browser device, item and base revision
 *   POST /v1/write-intents/:rid/complete    reconcile with the vault and report the status
 *   POST /v1/write-intents/:rid/fail        report that the browser could not write
 *   POST /v1/write-intents/:rid/cancel      the user declined
 *
 * The request ID in the path is an opaque lookup key, not a capability: every call
 * runs the shared pipeline (kill switch, ES256 sync token of a `browser` session,
 * live revocation, single-use `AKV-Proof` over the method, URL and body, verified
 * against the key the membership chain enrolled for the token's device) and the account's relay object then checks that the device is still a current
 * owner or editor of the request's vault and that the MCP grant that asked is live.
 * No call carries or returns a secret value.
 */
import { b64decodeLength, utf8Decode } from '@ak-vault/protocol';
import { assertDeviceNotRevoked } from '../auth/revocation-check.js';
import { bearerToken, verifyToken } from '../auth/jwt-verify.js';
import type { Env } from '../env.js';
import { ApiError, errorResult, okResult, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { relayStub, type IntentAction } from '../relay/relay-rpc.js';

const BODY_MAX_BYTES = 1024;
const ACTIONS: readonly IntentAction[] = ['claim', 'complete', 'fail', 'cancel'];

export interface WriteIntentRoute {
  action: IntentAction;
  rid: string;
  template: string;
}

/** Match a write-intent route; null for any other path or a method the path does not take. */
export function matchWriteIntentRoute(method: string, pathname: string): WriteIntentRoute | null {
  const parts = pathname.split('/');
  // ['', 'v1', 'write-intents', rid, action?]
  if (parts.length < 4 || parts.length > 5 || parts[1] !== 'v1' || parts[2] !== 'write-intents' || !parts[3]) return null;
  const rid = parts[3];
  if (parts.length === 4) {
    if (method !== 'GET') return null;
    return { action: 'view', rid: opaqueId(rid), template: 'GET /v1/write-intents/:rid' };
  }
  const action = ACTIONS.find((a) => a === parts[4]);
  if (!action || method !== 'POST') return null;
  return { action, rid: opaqueId(rid), template: `POST /v1/write-intents/:rid/${action}` };
}

function opaqueId(value: string): string {
  try {
    b64decodeLength(value, 16);
  } catch {
    throw new ApiError('bad_request', { message: 'malformed id in path' });
  }
  return value;
}

function parseJsonObject(body: Uint8Array, keys: readonly string[]): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(body));
  } catch {
    throw new ApiError('bad_request');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ApiError('bad_request');
  const obj = value as Record<string, unknown>;
  const names = Object.keys(obj);
  if (names.length !== keys.length || !keys.every((k) => names.includes(k))) throw new ApiError('bad_request');
  return obj;
}

export async function handleWriteIntent(request: Request, env: Env, route: WriteIntentRoute): Promise<ApiResult> {
  const token = bearerToken(request);
  const claims = await verifyToken(token, env);
  // Only the enrolled browser device holds this authority; a CLI or machine token never does.
  if (claims.kind !== 'browser') throw new ApiError('forbidden', { message: 'only a browser session can finish a write request' });
  if (!claims.scope.includes('vault:write')) throw new ApiError('forbidden', { message: 'a write request needs vault:write' });
  await assertDeviceNotRevoked(env, claims);
  const proof = request.headers.get('AKV-Proof');
  if (!proof) throw new ApiError('unauthorized', { message: 'AKV-Proof is required' });

  const body = await readBodyCapped(request, BODY_MAX_BYTES);
  let itemId: string | undefined;
  let baseRevision: number | undefined;
  let reason: 'conflict' | 'failed' | undefined;
  if (route.action === 'claim') {
    const o = parseJsonObject(body, ['item_id', 'base_revision']);
    if (typeof o['item_id'] !== 'string' || typeof o['base_revision'] !== 'number') throw new ApiError('bad_request');
    itemId = o['item_id'];
    baseRevision = o['base_revision'];
  } else if (route.action === 'fail') {
    const o = parseJsonObject(body, ['reason']);
    if (o['reason'] !== 'conflict' && o['reason'] !== 'failed') throw new ApiError('bad_request');
    reason = o['reason'];
  } else if (body.length !== 0) {
    throw new ApiError('bad_request', { message: 'this call takes no body' });
  }

  const result = await relayStub(env, claims.sub).writeIntentAction({
    action: route.action,
    rid: route.rid,
    sub: claims.sub,
    did: claims.did,
    token,
    proof,
    htm: request.method,
    htu: request.url,
    body,
    ...(itemId === undefined ? {} : { itemId }),
    ...(baseRevision === undefined ? {} : { baseRevision }),
    ...(reason === undefined ? {} : { reason }),
  });
  if ('body' in result) return okResult(result.body, 200);
  return errorResult(new ApiError(result.code, { ...(result.status === undefined ? {} : { status: result.status }), ...(result.extra ? { extra: result.extra } : {}) }));
}
