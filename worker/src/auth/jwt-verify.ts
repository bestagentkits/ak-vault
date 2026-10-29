/**
 * ES256 vault-resource token verification (spec §9.1) with WebCrypto.
 *
 * Header: `alg` must be exactly ES256 and `kid` must name a current JWKS key;
 * `crit`, `jku`, `jwk`, `x5u`, `x5c` are refused. Claims: exact `iss` and `aud`,
 * `exp`/`nbf`/`iat` with 60 s skew, and `sub`, `jti`, `sid`, `did`, `scope`
 * required. `scope` must be a non-empty subset of {vault:read, vault:write}.
 * `session_kind` is optional: absent means `email_otp` (the only kind issued before
 * the claim existed); a present value outside SESSION_KINDS is refused.
 * MCP access tokens (`<origin>/mcp`, spec §9.8) have their own verifier and claim set.
 * Every failure is `unauthorized`; nothing from the token is echoed.
 */
import { MCP_SCOPES, b64decode, b64decodeLength, utf8Decode, utf8Encode, type McpScope } from '@ak-vault/protocol';
import { mcpResource } from '../env.js';
import { ApiError } from '../http/errors.js';
import { LIMITS } from '../limits.js';
import { getIssuerKey } from './jwks.js';

export const SCOPES = ['vault:read', 'vault:write'] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * How the session behind a token signed in. Only `email_otp` is a human session
 * that may take the recovery-identity path or perform a recovery operation; the
 * others never may (spec §9.1, §9.4).
 * `browser` is the vault dashboard: a member device refused on genesis,
 * membership, recovery, seal-key publication, the sealed queue and the relay.
 */
export const SESSION_KINDS = ['email_otp', 'api_key_device', 'machine', 'browser'] as const;
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

interface CheckedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  iat: number;
  exp: number;
}

/**
 * Checks shared by every token kind: header, ES256 signature under a current
 * JWKS key, exact issuer and `audience`, and `exp`/`nbf`/`iat` with skew.
 */
async function verifyJwt(token: string, config: TokenConfig, audience: string, nowMs: number): Promise<CheckedJwt> {
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
  if (!audienceMatches(claims['aud'], audience)) deny();
  const now = Math.floor(nowMs / 1000);
  const skew = LIMITS.clock_skew_seconds;
  const exp = numericDate(claims['exp']);
  const nbf = numericDate(claims['nbf']);
  const iat = numericDate(claims['iat']);
  if (exp <= now - skew) deny();
  if (nbf > now + skew) deny();
  if (iat > now + skew) deny();
  return { header, claims, iat, exp };
}

/**
 * Verify a device sync token (spec §9 item 1) for the deployment's own audience
 * and return its claims. `nowMs` is injectable for tests. The `<origin>/mcp` and
 * `<origin>/app` audiences fail the exact audience check like any other.
 */
export async function verifyToken(token: string, config: TokenConfig, nowMs = Date.now()): Promise<VerifiedClaims> {
  const { claims, iat, exp } = await verifyJwt(token, config, config.VAULT_AUDIENCE, nowMs);
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

/** Claims of a verified MCP access token (spec §9.8). It has no `did` and no `session_kind`. */
export interface McpClaims {
  sub: string;
  client_id: string;
  grant_id: string;
  /** Equals `grant_id`, so revoking a grant reuses the webhook's `sids` list. */
  sid: string;
  jti: string;
  iat: number;
  exp: number;
  scope: McpScope[];
}

/** Exactly the claims an MCP access token carries (spec §9.8). */
const MCP_CLAIMS = ['iss', 'aud', 'sub', 'client_id', 'grant_id', 'sid', 'scope', 'jti', 'iat', 'nbf', 'exp'];
export const MCP_MAX_LIFETIME_SECONDS = 600;

function parseMcpScope(value: unknown): McpScope[] {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_CLAIM_LENGTH) deny();
  const out = new Set<McpScope>();
  for (const part of value.split(' ')) {
    if (!(MCP_SCOPES as readonly string[]).includes(part)) deny();
    out.add(part as McpScope);
  }
  return [...out];
}

function printableAscii(value: unknown, max: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || !/^[\x20-\x7e]+$/.test(value)) deny();
  return value;
}

/**
 * Verify an MCP access token for `<origin>/mcp` (spec §9.8): header `typ`
 * `at+jwt`, exactly the listed claims (so a sync token's `did` or `session_kind`
 * is refused), `sid` = `grant_id`, `exp` at most `iat` + 600 s and `scope` a
 * non-empty subset of the MCP scopes. Every failure is `unauthorized`. Live
 * revocation is separate: `assertGrantNotRevoked` (by `sid`), never the device check.
 */
export async function verifyMcpToken(token: string, config: TokenConfig, nowMs = Date.now()): Promise<McpClaims> {
  const { header, claims, iat, exp } = await verifyJwt(token, config, mcpResource(config), nowMs);
  if (header['typ'] !== 'at+jwt') deny();
  const keys = Object.keys(claims);
  if (keys.length !== MCP_CLAIMS.length || !keys.every((k) => MCP_CLAIMS.includes(k))) deny();
  if (exp - iat > MCP_MAX_LIFETIME_SECONDS || exp <= iat) deny();
  const grantId = printableAscii(claims['grant_id'], 64);
  if (claims['sid'] !== grantId) deny();
  return {
    sub: boundedString(claims['sub']),
    client_id: printableAscii(claims['client_id'], 256),
    grant_id: grantId,
    sid: grantId,
    jti: boundedString(claims['jti']),
    iat,
    exp,
    scope: parseMcpScope(claims['scope']),
  };
}

/** The credential of an `Authorization: Bearer <credential>` header; the scheme is case-insensitive (RFC 7235 section 2.1). Null for any other scheme or an empty credential. */
export function bearerCredential(header: string | null): string | null {
  const match = /^bearer[ \t]+(\S.*)$/i.exec(header ?? '');
  return match ? match[1]!.trim() : null;
}

/** Extract the bearer token from the Authorization header. */
export function bearerToken(request: Request): string {
  const token = bearerCredential(request.headers.get('Authorization'));
  if (!token) deny();
  return token;
}
