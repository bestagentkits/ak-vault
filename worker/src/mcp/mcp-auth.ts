/**
 * `/mcp` authentication (spec §9.8): an ES256 `at+jwt` MCP access token for
 * `<origin>/mcp` in the `Authorization` header only, then live revocation of its
 * `sid` (= grant ID) and the account's minimum `iat` on every request. Sync and
 * dashboard tokens fail the audience and claim-set checks in `verifyMcpToken`.
 * Failures answer 401 with the `resource_metadata` challenge, plus
 * `error="invalid_token"` when a bearer token was presented; a registry outage
 * stays a fail-closed 503. Scope refusals are 403 `insufficient_scope`.
 */
import type { McpScope } from '@ak-vault/protocol';
import { assertGrantNotRevoked } from '../auth/revocation-check.js';
import { bearerCredential, bearerToken, verifyMcpToken, type McpClaims } from '../auth/jwt-verify.js';
import type { Env } from '../env.js';
import { ApiError, errorResult, toApiError } from '../http/errors.js';
import { resultResponse } from '../http/responses.js';
import { bearerChallenge, insufficientScopeChallenge } from './protected-resource-metadata.js';

export type McpAuthResult = { ok: true; claims: McpClaims } | { ok: false; response: Response };

function unauthorized(env: Env, tokenPresented: boolean): Response {
  return resultResponse(errorResult(new ApiError('unauthorized', { headers: { 'WWW-Authenticate': bearerChallenge(env, tokenPresented) } })));
}

/** Whether the `Authorization` header carries a bearer token (the form `bearerToken` reads). */
function bearerPresented(request: Request): boolean {
  return bearerCredential(request.headers.get('Authorization')) !== null;
}

/** Verify the request's MCP token and its live revocation state. */
export async function authenticateMcp(request: Request, env: Env): Promise<McpAuthResult> {
  const presented = bearerPresented(request);
  // Tokens travel only in the Authorization header (PRM `bearer_methods_supported`).
  if (new URL(request.url).searchParams.has('access_token')) return { ok: false, response: unauthorized(env, presented) };
  let claims: McpClaims;
  try {
    claims = await verifyMcpToken(bearerToken(request), env);
    await assertGrantNotRevoked(env, { sub: claims.sub, sid: claims.sid, iat: claims.iat });
  } catch (err) {
    const apiError = toApiError(err);
    if (apiError.status === 401) return { ok: false, response: unauthorized(env, presented) };
    return { ok: false, response: resultResponse(errorResult(apiError)) };
  }
  return { ok: true, claims };
}

export function hasScope(claims: McpClaims, scope: McpScope): boolean {
  return claims.scope.includes(scope);
}

/**
 * 403 for a call the token's scopes do not cover. The challenge names every scope
 * the client needs (what it holds plus the missing one), so a step-up
 * authorization asks for all of them.
 */
export function insufficientScope(env: Env, claims: McpClaims, needed: McpScope): Response {
  const scopes = [...new Set<McpScope>([...claims.scope, needed])];
  return resultResponse(
    errorResult(new ApiError('forbidden', { message: 'the token scopes do not cover this tool', headers: { 'WWW-Authenticate': insufficientScopeChallenge(env, scopes) } })),
  );
}
