/**
 * The input form's three calls (spec §3.11):
 *
 *   POST <issuer>/api/agentkit/vault/input-token     app access token -> `input` session token
 *   GET  <origin>/v1/vaults/{v}/input-requests/{r}   the request's state, operation, client, device, expiry
 *   POST <origin>/v1/vaults/{v}/input-requests/{r}   `{"sealed": <input seal>}`, once
 *
 * The `input` token is read (never verified; ak-web signs it and the Worker
 * verifies it) and refused unless it is the one asked for: audience
 * `<origin>/input`, session kind `input`, this account, no device. It is kept in
 * memory only. Errors carry a fixed code; no server text, token, name or value
 * ever reaches one.
 */
import { b64decode, utf8Decode, type InputSealWire, type WriteIntentOperation } from '@ak-vault/protocol';
import type { AppConfig } from '../config.js';
import type { OAuthSession } from '../oauth/pkce-client.js';
import { isOpaqueId } from '../sync/write-request.js';
import type { InputLink } from './input-link.js';

/** Why an input-form step stopped; each maps to fixed text. */
export type InputErrorCode =
  | 'signin_refused'
  | 'input_unavailable'
  | 'input_not_found'
  | 'input_invalid_response'
  | 'input_token_expired'
  | 'network'
  | 'server';

export class InputError extends Error {
  constructor(readonly code: InputErrorCode) {
    super(code);
    this.name = 'InputError';
  }
}

export interface InputToken {
  token: string;
  /** Unix seconds. */
  expiresAt: number;
}

/** What the form shows and seals with. Never a value. */
export interface InputRequestState {
  requestId: string;
  state: string;
  operation: WriteIntentOperation;
  /** The requesting MCP client, printable ASCII (shown as text only). */
  clientId: string;
  /** The device that issued the input key; bound in the seal's AAD. */
  deviceId: string;
  /** Unix ms. */
  expiresAt: number;
}

/** The POST outcome: stored with a receipt, or the Worker's stable error code, HTTP status and the request's state after it. */
export type SubmitOutcome =
  | { kind: 'stored'; receipt: string }
  | { kind: 'error'; status: number; code: string; state: string | null };

export const INPUT_TOKEN_PATH = '/api/agentkit/vault/input-token';
/** A request that has not answered by then is a network failure the person can retry. */
const REQUEST_TIMEOUT_MS = 30_000;
/** The submission waits for the device's answer through the relay (deadline 60 s) and its item PUT. */
const SUBMIT_TIMEOUT_MS = 90_000;
const STABLE_CODE = /^[a-z_]{1,64}$/;
const PRINTABLE = /^[\x20-\x7e]{1,256}$/;
const RECEIPT = /^[\x20-\x7e]{1,128}$/;

function objectOf(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function decodePayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    return objectOf(JSON.parse(utf8Decode(b64decode(parts[1]!))));
  } catch {
    return null;
  }
}

/** The audience of `input` session tokens. */
export function inputAudience(config: AppConfig): string {
  return `${config.origin}/input`;
}

/** Check a minted token against what was asked for; refused (`signin_refused`) on any difference. */
export function checkInputToken(token: string, expiresIn: unknown, config: AppConfig, session: OAuthSession, nowMs: number): InputToken {
  if (typeof expiresIn !== 'number' || !Number.isSafeInteger(expiresIn) || expiresIn <= 0) throw new InputError('signin_refused');
  const claims = decodePayload(token);
  if (
    !claims ||
    claims['iss'] !== config.issuer ||
    claims['aud'] !== inputAudience(config) ||
    claims['session_kind'] !== 'input' ||
    claims['sub'] !== session.claims.sub ||
    'did' in claims ||
    typeof claims['exp'] !== 'number' ||
    !Number.isSafeInteger(claims['exp'])
  ) {
    throw new InputError('signin_refused');
  }
  const expiresAt = Math.min(claims['exp'], Math.floor(nowMs / 1000) + expiresIn);
  if (expiresAt <= Math.floor(nowMs / 1000)) throw new InputError('signin_refused');
  return { token, expiresAt };
}

/** Mint an `input` session token at ak-web with the in-memory app access token. */
export async function mintInputToken(args: { config: AppConfig; session: OAuthSession; fetchFn: typeof fetch; now?: number }): Promise<InputToken> {
  let res: Response;
  try {
    res = await args.fetchFn(`${args.config.issuer}${INPUT_TOKEN_PATH}`, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      headers: { Authorization: `Bearer ${args.session.accessToken}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new InputError('network');
  }
  if (res.status === 404) throw new InputError('input_unavailable');
  if (res.status >= 500) throw new InputError('server');
  if (!res.ok) throw new InputError('signin_refused');
  const body = objectOf(await res.json().catch(() => null));
  const token = body?.['access_token'];
  const type = body?.['token_type'];
  if (typeof token !== 'string' || typeof type !== 'string' || type.toLowerCase() !== 'bearer') throw new InputError('signin_refused');
  return checkInputToken(token, body?.['expires_in'], args.config, args.session, args.now ?? Date.now());
}

function requestUrl(config: AppConfig, link: InputLink): string {
  return `${config.origin}/v1/vaults/${encodeURIComponent(link.vaultId)}/input-requests/${encodeURIComponent(link.requestId)}`;
}

async function send(fetchFn: typeof fetch, url: string, token: InputToken, body?: string): Promise<Response> {
  const timeout = body === undefined ? REQUEST_TIMEOUT_MS : SUBMIT_TIMEOUT_MS;
  try {
    return await fetchFn(url, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'omit',
      cache: 'no-store',
      headers: { Authorization: `Bearer ${token.token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      signal: AbortSignal.timeout(timeout),
      ...(body === undefined ? {} : { body }),
    });
  } catch {
    throw new InputError('network');
  }
}

/** Validate the Worker's answer for `link`: this request, a known operation, a device ID and an integer expiry. */
export function parseInputRequest(raw: unknown, link: InputLink): InputRequestState {
  const b = objectOf(raw);
  if (!b) throw new InputError('input_invalid_response');
  const { request_id: requestId, state, operation, client_id: clientId, device_id: deviceId, expires_at: expiresAt } = b;
  if (requestId !== link.requestId || typeof state !== 'string' || !STABLE_CODE.test(state)) throw new InputError('input_invalid_response');
  if (operation !== 'create' && operation !== 'replace') throw new InputError('input_invalid_response');
  if (typeof clientId !== 'string' || !PRINTABLE.test(clientId)) throw new InputError('input_invalid_response');
  if (typeof deviceId !== 'string' || !isOpaqueId(deviceId)) throw new InputError('input_invalid_response');
  if (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new InputError('input_invalid_response');
  return { requestId, state, operation, clientId, deviceId, expiresAt };
}

/** GET the request. 401 is `input_token_expired` (mint again), 404 `input_not_found`. */
export async function fetchInputRequest(fetchFn: typeof fetch, config: AppConfig, link: InputLink, token: InputToken): Promise<InputRequestState> {
  const res = await send(fetchFn, requestUrl(config, link), token);
  if (res.status === 401) throw new InputError('input_token_expired');
  if (res.status === 404) throw new InputError('input_not_found');
  if (!res.ok) throw new InputError('server');
  return parseInputRequest(await res.json().catch(() => null), link);
}

/** POST the sealed value. Body is exactly `{"sealed": …}`. 401 is `input_token_expired` (mint again); nothing was claimed. */
export async function submitInput(fetchFn: typeof fetch, config: AppConfig, link: InputLink, token: InputToken, sealed: InputSealWire): Promise<SubmitOutcome> {
  const res = await send(fetchFn, requestUrl(config, link), token, JSON.stringify({ sealed }));
  if (res.status === 401) throw new InputError('input_token_expired');
  const body = objectOf(await res.json().catch(() => null));
  if (res.ok) {
    const receipt = body?.['receipt'];
    if (body?.['status'] !== 'stored' || typeof receipt !== 'string' || !RECEIPT.test(receipt)) return { kind: 'error', status: 500, code: 'internal', state: null };
    return { kind: 'stored', receipt };
  }
  const err = objectOf(body?.['error']);
  const code = err?.['code'];
  const state = err?.['state'];
  return {
    kind: 'error',
    status: res.status,
    code: typeof code === 'string' && STABLE_CODE.test(code) ? code : 'unknown',
    state: typeof state === 'string' && STABLE_CODE.test(state) ? state : null,
  };
}
