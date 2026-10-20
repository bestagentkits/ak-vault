/**
 * RFC 9728 protected-resource metadata for the MCP resource `<origin>/mcp`
 * (spec §9.8) and the `WWW-Authenticate` challenges `/mcp` answers with. Public:
 * the document names only the resource, its authorization server (the token
 * issuer) and the scopes.
 */
import { MCP_SCOPES, type McpScope } from '@ak-vault/protocol';
import { mcpResource, type Env } from '../env.js';
import { jsonResponse } from '../http/responses.js';

/**
 * The only metadata path (RFC 9728 §3.1: the well-known prefix plus the resource path
 * `/mcp`). The bare `/.well-known/oauth-protected-resource` would describe the origin,
 * not `<origin>/mcp`, so it is not served.
 */
export const PRM_MCP_PATH = '/.well-known/oauth-protected-resource/mcp';

type MetadataEnv = Pick<Env, 'VAULT_AUDIENCE' | 'VAULT_ISSUER'>;

/** The URL clients fetch the metadata from, named in every `resource_metadata` challenge. */
export function resourceMetadataUrl(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `${env.VAULT_AUDIENCE}${PRM_MCP_PATH}`;
}

export function protectedResourceMetadata(env: MetadataEnv): Record<string, unknown> {
  return {
    resource: mcpResource(env),
    authorization_servers: [env.VAULT_ISSUER],
    scopes_supported: [...MCP_SCOPES],
    bearer_methods_supported: ['header'],
    resource_name: 'AgentKit Vault',
  };
}

/** `GET`/`HEAD` of the metadata path; any other method is `405`. */
export function handleProtectedResourceMetadata(request: Request, env: MetadataEnv): Response {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return jsonResponse({ error: { code: 'bad_request', message: 'method not allowed' } }, 405, { Allow: 'GET, HEAD' });
  }
  const response = jsonResponse(protectedResourceMetadata(env), 200, { 'Cache-Control': 'public, max-age=300' });
  return request.method === 'HEAD' ? new Response(null, { status: 200, headers: response.headers }) : response;
}

/**
 * Challenge for a missing, invalid, expired or revoked token. A bearer token that
 * was presented and refused adds `error="invalid_token"` (RFC 6750 §3.1); a request
 * without one gets the bare challenge, with no error code.
 */
export function bearerChallenge(env: Pick<Env, 'VAULT_AUDIENCE'>, tokenPresented = false): string {
  const error = tokenPresented ? 'error="invalid_token", ' : '';
  return `Bearer ${error}resource_metadata="${resourceMetadataUrl(env)}", scope="vault-mcp:read"`;
}

/** Challenge for a valid token whose scopes do not cover the call (RFC 6750 §3.1). */
export function insufficientScopeChallenge(env: Pick<Env, 'VAULT_AUDIENCE'>, scopes: readonly McpScope[]): string {
  return `Bearer error="insufficient_scope", scope="${scopes.join(' ')}", resource_metadata="${resourceMetadataUrl(env)}"`;
}
