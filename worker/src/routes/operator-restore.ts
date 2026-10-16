/**
 * `POST /internal/v1/operator` — operator point-in-time recovery of ONE vault
 * object (runbook "Durable Object backup and restore"). It never reaches the
 * revocation registry: the only binding it uses is `VAULT`.
 *
 * Off unless `VAULT_OPERATOR_SECRET` (secret, >= 32 chars) is set for the
 * environment: then the path answers 404 like any unknown path. Independent of
 * the sync kill switch, because a restore is an incident step taken with sync off.
 *
 * Body (≤ 4 KiB): `{"request": "<JSON string>", "sig": "<b64url HMAC>"}` where
 *   sig = HMAC-SHA256(secret, utf8("akv1/operator-request") || 0x0A || utf8(request))
 * The signature travels in the body, not a header, so Workers Tail (which shows
 * headers) never sees it. `request` is an object with exactly:
 *   {"v":1,"action","vault_id","origin","ts", ...action fields}
 *   - "bookmark":           +"at_ms" (integer ms, or null for the current bookmark)
 *   - "restore":            +"bookmark" (target), +"expected_current"
 * `origin` must equal this Worker's origin and `ts` (unix s) be within ±60 s.
 * Replay: a bookmark read is harmless; a restore is compare-and-swap on the
 * vault's current bookmark, so a replay is refused with `409` once the bookmark
 * has moved (every write moves it; that a restore does is to be checked on staging).
 *
 * A restore schedules the target, refuses every request to that vault from then
 * until the restart (so nothing is acknowledged that the restore discards),
 * restarts the object, confirms the restart by a new instance ID and returns the
 * target and the undo bookmark (`202` with `restart_confirmed: false` when the
 * restart could not be confirmed; any later operator request retries the restart
 * first, and answers `503` while it still cannot confirm it). Record both bookmarks on the incident issue:
 * nothing else keeps them. Logs record this route's template even when it is off;
 * responses cannot tell it from an unknown path.
 */
import { b64decode, parseJson, utf8Decode, utf8Encode, concatBytes, b64decodeLength } from '@ak-vault/protocol';
import type { Env } from '../env.js';
import { ApiError, type ApiResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { isBookmark } from '../vault/point-in-time-restore.js';
import type { RouteInfo } from './api-handler.js';

export const OPERATOR_PATH = '/internal/v1/operator';
export const OPERATOR_SIGN_CONTEXT = 'akv1/operator-request';
export const OPERATOR_WINDOW_SECONDS = 60;
const MIN_SECRET_LENGTH = 32;
const MAX_BODY_BYTES = 4 * 1024;

type OperatorRequest =
  | { action: 'bookmark'; vaultId: string; atMs: number | null }
  | { action: 'restore'; vaultId: string; bookmark: string; expectedCurrent: string };

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseObject(text: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = parseJson(text);
  } catch {
    throw new ApiError('bad_request');
  }
  if (!isObject(value)) throw new ApiError('bad_request');
  return value;
}

function exactKeys(obj: Record<string, unknown>, keys: readonly string[]): void {
  const present = Object.keys(obj);
  if (present.length !== keys.length || keys.some((k) => !Object.hasOwn(obj, k))) throw new ApiError('bad_request');
}

/** Constant-time HMAC check (subtle.verify). */
async function signatureValid(secret: string, request: string, signature: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', utf8Encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('HMAC', key, signature, concatBytes(utf8Encode(`${OPERATOR_SIGN_CONTEXT}\n`), utf8Encode(request)));
}

/** Validate the signed request after authentication. */
export function parseOperatorRequest(request: string, origin: string, nowMs: number): OperatorRequest {
  const obj = parseObject(request);
  if (obj['v'] !== 1) throw new ApiError('unsupported_version');
  if (obj['origin'] !== origin) throw new ApiError('unauthorized');
  const ts = obj['ts'];
  if (typeof ts !== 'number' || !Number.isSafeInteger(ts) || Math.abs(Math.floor(nowMs / 1000) - ts) > OPERATOR_WINDOW_SECONDS) {
    throw new ApiError('unauthorized');
  }
  const vaultId = obj['vault_id'];
  try {
    if (typeof vaultId !== 'string') throw new Error('vault_id');
    b64decodeLength(vaultId, 16);
  } catch {
    throw new ApiError('bad_request');
  }
  const base = ['v', 'action', 'vault_id', 'origin', 'ts'];
  switch (obj['action']) {
    case 'bookmark': {
      exactKeys(obj, [...base, 'at_ms']);
      const at = obj['at_ms'];
      if (at !== null && (typeof at !== 'number' || !Number.isSafeInteger(at))) throw new ApiError('bad_request');
      return { action: 'bookmark', vaultId: vaultId as string, atMs: at as number | null };
    }
    case 'restore': {
      exactKeys(obj, [...base, 'bookmark', 'expected_current']);
      const bookmark = obj['bookmark'];
      const expected = obj['expected_current'];
      if (!isBookmark(bookmark) || !isBookmark(expected)) throw new ApiError('bad_request');
      return { action: 'restore', vaultId: vaultId as string, bookmark, expectedCurrent: expected };
    }
    default:
      throw new ApiError('bad_request');
  }
}

export async function handleOperatorRequest(request: Request, env: Env, info: RouteInfo, nowMs = Date.now()): Promise<ApiResult> {
  const secret = env.VAULT_OPERATOR_SECRET;
  // Unconfigured: indistinguishable from an unknown path.
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) throw new ApiError('not_found');
  if (request.method !== 'POST') throw new ApiError('not_found');

  const envelope = parseObject(utf8Decode(await readBodyCapped(request, MAX_BODY_BYTES)));
  exactKeys(envelope, ['request', 'sig']);
  const signed = envelope['request'];
  if (typeof signed !== 'string' || typeof envelope['sig'] !== 'string') throw new ApiError('unauthorized');
  let signature: Uint8Array;
  try {
    signature = b64decode(envelope['sig']);
  } catch {
    throw new ApiError('unauthorized');
  }
  if (signature.length !== 32 || !(await signatureValid(secret, signed, signature))) throw new ApiError('unauthorized');

  const op = parseOperatorRequest(signed, new URL(request.url).origin, nowMs);
  info.vaultId = op.vaultId;
  const stub = () => env.VAULT.get(env.VAULT.idFromName(op.vaultId));
  // A restore left pending (an unconfirmed restart) is finished first, whatever the action.
  const pendingBefore = await instanceOf(stub);
  if (pendingBefore === null || pendingBefore.restorePending) {
    if (!(await restartAndConfirm(stub, pendingBefore?.instance ?? null))) throw restartUnconfirmed();
  }
  if (op.action === 'bookmark') return stub().operatorBookmark(op.atMs, nowMs);

  // RPC types `unknown` bodies as never; the value is a plain ApiResult.
  const scheduled: ApiResult = await stub().operatorScheduleRestore(op.bookmark, op.expectedCurrent);
  const before = await instanceOf(stub);
  // Nothing scheduled (a refusal before the platform call): return it as is.
  if (before && !before.restorePending) return scheduled;
  const restarted = await restartAndConfirm(stub, before?.instance ?? null);
  if (scheduled.status !== 200) return scheduled;
  return restarted ? scheduled : { status: 202, body: { ...(scheduled.body as Record<string, unknown>), restart_confirmed: false } };
}

function restartUnconfirmed(): ApiError {
  return new ApiError('internal', { status: 503, message: 'vault restart not confirmed', headers: { 'Retry-After': '5' } });
}

type VaultStub = ReturnType<Env['VAULT']['get']>;

async function instanceOf(stub: () => VaultStub): Promise<{ instance: string; restorePending: boolean } | null> {
  try {
    return await stub().operatorInstance();
  } catch {
    return null;
  }
}

/**
 * Restart the object and confirm it came back as a new instance (the restore
 * applies at that start). Two attempts; unconfirmed means the object keeps
 * refusing every request until it restarts on its own, when the restore applies.
 */
async function restartAndConfirm(stub: () => VaultStub, previous: string | null): Promise<boolean> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await stub().operatorRestart();
    } catch {
      // Expected: the restart aborts the call that requested it.
    }
    const now = await instanceOf(stub);
    // Without the previous instance ID, a start that is not pending is the best evidence.
    if (now && !now.restorePending && (previous === null || now.instance !== previous)) return true;
  }
  return false;
}
