/**
 * RFC 9728 protected-resource metadata for the MCP resource `<origin>/mcp`
 * (spec §9.8) and the `WWW-Authenticate` challenges `/mcp` answers with. Public:
 * the document names only the resource, its authorization server (the token
 * issuer) and the scopes.
 */
import { MCP_SCOPES, type McpScope } from '@ak-vault/protocol';
import { mcpResource, type Env } from '../env.js';
import { jsonResponse } from '../http/responses.js';

export const PRM_PATH = '/.well-known/oauth-protected-resource';
export const PRM_MCP_PATH = `${PRM_PATH}/mcp`;
export const PRM_PATHS: readonly string[] = [PRM_PATH, PRM_MCP_PATH];

type MetadataEnv = Pick<Env, 'VAULT_AUDIENCE' | 'VAULT_ISSUER'>;

/** The URL clients fetch the metadata from (the path-suffixed form, tried first by MCP clients). */
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

/** `GET`/`HEAD` of either metadata path; any other method is `405`. */
export function handleProtectedResourceMetadata(request: Request, env: MetadataEnv): Response {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return jsonResponse({ error: { code: 'bad_request', message: 'method not allowed' } }, 405, { Allow: 'GET, HEAD' });
  }
  const response = jsonResponse(protectedResourceMetadata(env), 200, { 'Cache-Control': 'public, max-age=300' });
  return request.method === 'HEAD' ? new Response(null, { status: 200, headers: response.headers }) : response;
}

/** Challenge for a missing, invalid, expired or revoked token. */
export function bearerChallenge(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `Bearer resource_metadata="${resourceMetadataUrl(env)}", scope="vault-mcp:read"`;
}

/** Challenge for a valid token whose scopes do not cover the call (RFC 6750 §3.1). */
export function insufficientScopeChallenge(env: Pick<Env, 'VAULT_AUDIENCE'>, scopes: readonly McpScope[]): string {
  return `Bearer error="insufficient_scope", scope="${scopes.join(' ')}", resource_metadata="${resourceMetadataUrl(env)}"`;
}
