/**
 * Exchange the in-memory app token for a five-minute, device-bound sync token
 * at ak-web `POST /api/agentkit/vault/token`. The body is signed by the device
 * key over the sign-in grant (`sid`), the vault audience and a 60-second window:
 *
 *   sig = Ed25519(utf8("akv1/vault-token-request") || 0x0A ||
 *                 cjson({aud, scope (sorted), sid, sign_pub, ts}))
 *
 * The returned token is checked against what was asked for (same account, this
 * device, this vault origin) before it is used. It is kept in memory only.
 */
import { b64decode, b64encode, signingInput, utf8Decode, type DeviceSigner } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { AppConfig } from '../config.js';
import type { OAuthSession } from '../oauth/pkce-client.js';

export const VAULT_TOKEN_REQUEST_CONTEXT = 'akv1/vault-token-request';
export const SYNC_SCOPES = ['vault:read', 'vault:write'] as const;

export interface SyncToken {
  token: string;
  /** Unix seconds. */
  expiresAt: number;
  did: string;
}

function decodePayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const v = JSON.parse(utf8Decode(b64decode(parts[1]!))) as unknown;
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Build the signed request body (exported for tests). */
export async function buildTokenRequest(args: { config: AppConfig; sid: string; signPub: string; signer: DeviceSigner; nowS: number }): Promise<Record<string, unknown>> {
  const scope = [...SYNC_SCOPES].sort();
  const signed = { aud: args.config.origin, scope, sid: args.sid, sign_pub: args.signPub, ts: args.nowS };
  const sig = await args.signer.sign(signingInput(VAULT_TOKEN_REQUEST_CONTEXT, signed));
  if (!(sig instanceof Uint8Array) || sig.length !== 64) throw new AppError('token_exchange_failed');
  return { sign_pub: args.signPub, scope, ts: args.nowS, sig: b64encode(sig) };
}

function errorCodeOf(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  const b = body as Record<string, unknown>;
  if (typeof b['errorCode'] === 'string') return b['errorCode'];
  if (typeof b['error'] === 'string') return b['error'];
  return null;
}

export async function exchangeSyncToken(args: {
  config: AppConfig;
  session: OAuthSession;
  deviceId: string;
  signPub: string;
  signer: DeviceSigner;
  fetchFn: typeof fetch;
  now?: number;
}): Promise<SyncToken> {
  const now = args.now ?? Date.now();
  const body = await buildTokenRequest({ config: args.config, sid: args.session.claims.sid, signPub: args.signPub, signer: args.signer, nowS: Math.floor(now / 1000) });
  let res: Response;
  try {
    res = await args.fetchFn(`${args.config.issuer}/api/agentkit/vault/token`, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      headers: { Authorization: `Bearer ${args.session.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new AppError('network');
  }
  const json = (await res.json().catch(() => null)) as unknown;
  if (!res.ok) {
    const code = errorCodeOf(json);
    if (res.status === 401) throw new AppError('signin_required');
    if (code === 'device_revoked') throw new AppError('device_removed');
    if (code === 'device_mismatch' || code === 'device_conflict') throw new AppError('device_mismatch');
    throw new AppError(res.status >= 500 ? 'server' : 'token_exchange_failed');
  }
  if (typeof json !== 'object' || json === null) throw new AppError('token_exchange_failed');
  const b = json as Record<string, unknown>;
  const token = b['access_token'];
  const expiresIn = b['expires_in'];
  if (typeof token !== 'string' || typeof b['token_type'] !== 'string' || b['token_type'].toLowerCase() !== 'bearer') throw new AppError('token_exchange_failed');
  if (typeof expiresIn !== 'number' || !Number.isSafeInteger(expiresIn) || expiresIn <= 0 || b['did'] !== args.deviceId) throw new AppError('token_exchange_failed');
  const claims = decodePayload(token);
  if (!claims || claims['aud'] !== args.config.origin || claims['sub'] !== args.session.claims.sub || claims['did'] !== args.deviceId) {
    throw new AppError('token_exchange_failed');
  }
  const exp = typeof claims['exp'] === 'number' ? claims['exp'] : Math.floor(now / 1000) + expiresIn;
  return { token, did: args.deviceId, expiresAt: Math.min(exp, Math.floor(now / 1000) + expiresIn) };
}
