/**
 * JSON Schemas for the public discovery documents, derived from the fields that
 * MCP 2026-07-28 authorization requires of a protected resource (RFC 9728 §2) and
 * of an authorization server (RFC 8414 §2, plus RFC 9207 §3 and the PKCE, CIMD and
 * DCR advertisements the MCP authorization spec relies on). Unknown extension
 * members stay allowed; the required members and their value domains do not.
 */
import Ajv2020 from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';

export const MCP_SCOPES = ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use'] as const;

const httpsUrl = { type: 'string', pattern: '^https://[^\\s]+$' };

export const PROTECTED_RESOURCE_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  required: ['resource', 'authorization_servers'],
  properties: {
    resource: httpsUrl,
    authorization_servers: { type: 'array', minItems: 1, items: httpsUrl, uniqueItems: true },
    bearer_methods_supported: { type: 'array', items: { const: 'header' }, minItems: 1, uniqueItems: true },
    scopes_supported: { type: 'array', items: { enum: [...MCP_SCOPES] }, minItems: 1, uniqueItems: true },
    resource_name: { type: 'string', minLength: 1 },
  },
} as const;

export const AUTHORIZATION_SERVER_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  required: [
    'issuer',
    'authorization_endpoint',
    'token_endpoint',
    'response_types_supported',
    'grant_types_supported',
    'code_challenge_methods_supported',
    'client_id_metadata_document_supported',
    'authorization_response_iss_parameter_supported',
  ],
  properties: {
    issuer: httpsUrl,
    authorization_endpoint: httpsUrl,
    token_endpoint: httpsUrl,
    registration_endpoint: httpsUrl,
    response_types_supported: { type: 'array', contains: { const: 'code' }, minItems: 1 },
    grant_types_supported: { type: 'array', contains: { const: 'authorization_code' }, minItems: 1 },
    code_challenge_methods_supported: { type: 'array', contains: { const: 'S256' }, items: { const: 'S256' }, minItems: 1 },
    client_id_metadata_document_supported: { const: true },
    authorization_response_iss_parameter_supported: { const: true },
    token_endpoint_auth_methods_supported: { type: 'array', not: { contains: { const: 'client_secret_post' } } },
  },
} as const;

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validators: { protectedResource: ValidateFunction; authorizationServer: ValidateFunction } = {
  protectedResource: ajv.compile(PROTECTED_RESOURCE_SCHEMA),
  authorizationServer: ajv.compile(AUTHORIZATION_SERVER_SCHEMA),
};

/** Schema errors as `path message` strings; never the document values. */
export function schemaErrors(kind: keyof typeof validators, document: unknown): string[] {
  const ok = validators[kind](document);
  return ok ? [] : (validators[kind].errors ?? []).map((e) => `${e.instancePath || '/'} ${e.keyword}`);
}
