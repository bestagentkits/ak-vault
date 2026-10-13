/**
 * `POST /internal/v1/revocations` — the ak-web revocation feed.
 *
 * Authentication: `AKV-Webhook-Timestamp: <unix seconds>` and
 * `AKV-Webhook-Signature: <b64url HMAC-SHA256(secret, utf8(ts) || "\n" || body)>`.
 * The timestamp must be within ±300 s; the body's `event_id` is single-use.
 * During a secret rotation the previous secret is also accepted when configured.
 * Missing secret configuration fails closed (503). Always on, even when the
 * kill switch disables sync, so revocations are current when sync returns.
 *
 * Body: {"v":1,"event_id":str,"revoke_sids":[str],"revoke_dids":[str],"min_iat":[{"sub":str,"iat":int}]}
 */
import { b64decode, concatBytes, parseJson, utf8Decode, utf8Encode } from '@ak-vault/protocol';
import type { Env } from '../env.js';
import { ApiError, okResult, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { REVOCATION_REGISTRY_NAME } from '../auth/revocation-check.js';
import type { RevocationBatch } from '../revocation/revocation-registry.js';

export const WEBHOOK_WINDOW_SECONDS = 300;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_ENTRIES = 100;
const EVENT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_CLAIM_LENGTH = 256;

async function hmacMatches(secret: string, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', utf8Encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  // subtle.verify compares in constant time.
  return crypto.subtle.verify('HMAC', key, signature, message);
}

function claimList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_ENTRIES) throw new ApiError('bad_request');
  return value.map((v) => {
    if (typeof v !== 'string' || v.length === 0 || v.length > MAX_CLAIM_LENGTH) throw new ApiError('bad_request');
    return v;
  });
}

export function parseRevocationBatch(bytes: Uint8Array): RevocationBatch {
  let body: unknown;
  try {
    body = parseJson(utf8Decode(bytes));
  } catch {
    throw new ApiError('bad_request');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new ApiError('bad_request');
  const obj = body as Record<string, unknown>;
  const allowed = ['v', 'event_id', 'revoke_sids', 'revoke_dids', 'min_iat'];
  if (Object.keys(obj).some((k) => !allowed.includes(k)) || allowed.some((k) => !(k in obj))) throw new ApiError('bad_request');
  if (obj['v'] !== 1) throw new ApiError('unsupported_version');
  if (typeof obj['event_id'] !== 'string' || !EVENT_ID_PATTERN.test(obj['event_id'])) throw new ApiError('bad_request');
  const minIatRaw = obj['min_iat'];
  if (!Array.isArray(minIatRaw) || minIatRaw.length > MAX_ENTRIES) throw new ApiError('bad_request');
  const minIat = minIatRaw.map((entry) => {
    const e = entry as Record<string, unknown> | null;
    if (typeof e !== 'object' || e === null || Object.keys(e).length !== 2) throw new ApiError('bad_request');
    const [sub] = claimList([e['sub']]);
    if (typeof e['iat'] !== 'number' || !Number.isSafeInteger(e['iat'])) throw new ApiError('bad_request');
    return { sub: sub!, iat: e['iat'] };
  });
  const batch: RevocationBatch = { event_id: obj['event_id'], revoke_sids: claimList(obj['revoke_sids']), revoke_dids: claimList(obj['revoke_dids']), min_iat: minIat };
  if (batch.revoke_sids.length + batch.revoke_dids.length + batch.min_iat.length === 0) throw new ApiError('bad_request');
  return batch;
}

export async function handleRevocationWebhook(request: Request, env: Env, nowMs = Date.now()): Promise<ApiResult> {
  if (request.method !== 'POST') throw new ApiError('not_found');
  const secrets = [env.REVOCATION_WEBHOOK_SECRET, env.REVOCATION_WEBHOOK_SECRET_PREVIOUS].filter((s): s is string => typeof s === 'string' && s.length >= 32);
  if (secrets.length === 0) throw new ApiError('unauthorized', { status: 503, message: 'webhook not configured' });

  const tsHeader = request.headers.get('AKV-Webhook-Timestamp') ?? '';
  const sigHeader = request.headers.get('AKV-Webhook-Signature') ?? '';
  if (!/^\d{1,12}$/.test(tsHeader)) throw new ApiError('unauthorized');
  if (Math.abs(Math.floor(nowMs / 1000) - Number(tsHeader)) > WEBHOOK_WINDOW_SECONDS) throw new ApiError('unauthorized');
  let signature: Uint8Array;
  try {
    signature = b64decode(sigHeader);
  } catch {
    throw new ApiError('unauthorized');
  }
  if (signature.length !== 32) throw new ApiError('unauthorized');

  const body = await readBodyCapped(request, MAX_BODY_BYTES);

  const message = concatBytes(utf8Encode(`${tsHeader}\n`), body);
  let valid = false;
  for (const secret of secrets) if (await hmacMatches(secret, message, signature)) valid = true;
  if (!valid) throw new ApiError('unauthorized');

  const batch = parseRevocationBatch(body);
  let outcome: 'applied' | 'duplicate';
  try {
    outcome = await env.REVOCATIONS.get(env.REVOCATIONS.idFromName(REVOCATION_REGISTRY_NAME)).applyBatch(batch, nowMs);
  } catch {
    throw new ApiError('unauthorized', { status: 503, message: 'revocation registry unavailable', headers: { 'Retry-After': '5' } });
  }
  if (outcome === 'duplicate') throw new ApiError('conflict', { message: 'event already processed' });
  return okResult({ ok: true });
}
