/**
 * ES256 vault-resource token verification (spec §9.1) with WebCrypto.
 *
 * Header: `alg` must be exactly ES256 and `kid` must name a current JWKS key;
 * `crit`, `jku`, `jwk`, `x5u`, `x5c` are refused. Claims: exact `iss` and `aud`,
 * `exp`/`nbf`/`iat` with 60 s skew, and `sub`, `jti`, `sid`, `did`, `scope`
 * required. `scope` must be a non-empty subset of {vault:read, vault:write}.
 * `session_kind` is optional: absent means `email_otp` (the only kind issued before
 * the claim existed); a present value outside SESSION_KINDS is refused.
 * Every failure is `unauthorized`; nothing from the token is echoed.
 */
import { b64decode, b64decodeLength, utf8Decode, utf8Encode } from '@ak-vault/protocol';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { getIssuerKey } from './jwks.js';

export const SCOPES = ['vault:read', 'vault:write'] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * How the session behind a token signed in. Only `email_otp` is a human session
 * that may take the recovery-identity path; the others never may (spec §9.1).
 */
export const SESSION_KINDS = ['email_otp', 'api_key_device', 'machine'] as const;
export type SessionKind = (typeof SESSION_KINDS)[number];

export interface VerifiedClaims {
  sub: string;
  sid: string;
  did: string;
  jti: string;
  iat: number;
  exp: number;
  scope: Scope[];
  kind: SessionKind;
}

export interface TokenConfig {
  VAULT_ISSUER: string;
  VAULT_AUDIENCE: string;
  VAULT_JWKS_JSON?: string;
  VAULT_JWKS_URL?: string;
}

const MAX_TOKEN_LENGTH = 8192;
const MAX_CLAIM_LENGTH = 256;
const FORBIDDEN_HEADER_PARAMS = ['crit', 'jku', 'jwk', 'x5u', 'x5c'];

function deny(): never {
  throw new ApiError('unauthorized');
}

function decodeJsonPart(part: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(utf8Decode(b64decode(part)));
    if (typeof value !== 'object' || value === null || Array.isArray(value)) deny();
    return value as Record<string, unknown>;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    return deny();
  }
}

function boundedString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_CLAIM_LENGTH) deny();
  return value;
}

function numericDate(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) deny();
  return value;
}

function audienceMatches(aud: unknown, expected: string): boolean {
  if (typeof aud === 'string') return aud === expected;
  return Array.isArray(aud) && aud.length === 1 && aud[0] === expected;
}

function parseScope(value: unknown): Scope[] {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_CLAIM_LENGTH) deny();
  const parts = value.split(' ');
  const out = new Set<Scope>();
  for (const part of parts) {
    if (!(SCOPES as readonly string[]).includes(part)) deny();
    out.add(part as Scope);
  }
  return [...out];
}

function parseSessionKind(value: unknown): SessionKind {
  if (value === undefined) return 'email_otp';
  if (typeof value !== 'string' || !(SESSION_KINDS as readonly string[]).includes(value)) deny();
  return value as SessionKind;
}

/** Verify a bearer token and return its claims. `nowMs` is injectable for tests. */
export async function verifyToken(token: string, config: TokenConfig, nowMs = Date.now()): Promise<VerifiedClaims> {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) deny();
  const parts = token.split('.');
  if (parts.length !== 3) deny();
  const [headerPart, payloadPart, sigPart] = parts as [string, string, string];
  const header = decodeJsonPart(headerPart);
  if (header['alg'] !== 'ES256') deny();
  if (header['typ'] !== undefined && header['typ'] !== 'JWT' && header['typ'] !== 'at+jwt') deny();
  for (const param of FORBIDDEN_HEADER_PARAMS) if (param in header) deny();
  const kid = boundedString(header['kid']);

  let signature: Uint8Array;
  try {
    signature = b64decode(sigPart);
  } catch {
    return deny();
  }
  if (signature.length !== 64) deny();
  const key = await getIssuerKey(config, kid, nowMs);
  if (!key) deny();
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, utf8Encode(`${headerPart}.${payloadPart}`));
  if (!ok) deny();

  const claims = decodeJsonPart(payloadPart);
  if (claims['iss'] !== config.VAULT_ISSUER) deny();
  if (!audienceMatches(claims['aud'], config.VAULT_AUDIENCE)) deny();
  const now = Math.floor(nowMs / 1000);
  const skew = LIMITS.clock_skew_seconds;
  const exp = numericDate(claims['exp']);
  const nbf = numericDate(claims['nbf']);
  const iat = numericDate(claims['iat']);
  if (exp <= now - skew) deny();
  if (nbf > now + skew) deny();
  if (iat > now + skew) deny();
  const did = boundedString(claims['did']);
  try {
    b64decodeLength(did, 16); // a device ID is b64 of 16 bytes, canonical encoding only
  } catch {
    deny();
  }
  return {
    sub: boundedString(claims['sub']),
    sid: boundedString(claims['sid']),
    did,
    jti: boundedString(claims['jti']),
    iat,
    exp,
    scope: parseScope(claims['scope']),
    kind: parseSessionKind(claims['session_kind']),
  };
}

/** Extract the bearer token from the Authorization header. */
export function bearerToken(request: Request): string {
  const header = request.headers.get('Authorization');
  if (!header || !header.startsWith('Bearer ')) deny();
  return header.slice('Bearer '.length).trim();
}
