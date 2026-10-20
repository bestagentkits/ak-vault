/**
 * Remote MCP endpoint (spec §9.8): `POST /mcp` and the RFC 9728 protected-resource
 * metadata at `/.well-known/oauth-protected-resource` and
 * `/.well-known/oauth-protected-resource/mcp`. The Worker entry routes these paths
 * here only where remote access is enabled and adds the security headers.
 *
 * `/mcp` is stateless Streamable HTTP, MCP 2026-07-28, with 2025-11-25 clients
 * answered statelessly (`initialize` works, no `Mcp-Session-Id` is ever issued).
 * Order: method -> Origin -> kill switch -> MCP token and live revocation ->
 * headers and protocol version -> body (capped) -> one JSON-RPC message -> method.
 * `tools/call` also checks the tool's scope (403 `insufficient_scope`). Responses
 * are `application/json`; no CORS headers, so browsers cannot read them
 * cross-origin.
 */
import { utf8Decode } from '@ak-vault/protocol';
import type { McpClaims } from '../auth/jwt-verify.js';
import type { Env } from '../env.js';
import { ApiError, errorResult } from '../http/errors.js';
import { readBodyCapped } from '../http/read-body-capped.js';
import { jsonResponse, resultResponse } from '../http/responses.js';
import { LIMITS, WORKER_VERSION } from '../limits.js';
import { syncEnabled } from '../routes/meta-routes.js';
import { RPC, accepted, parseMessage, rpcError, rpcResult, type JsonRpcRequest } from './json-rpc.js';
import { authenticateMcp, hasScope, insufficientScope } from './mcp-auth.js';
import { PRM_PATHS, handleProtectedResourceMetadata } from './protected-resource-metadata.js';
import {
  LEGACY_VERSION,
  META_CLIENT_CAPABILITIES,
  META_PROTOCOL_VERSION,
  META_SERVER_INFO,
  PROTOCOL_VERSION_HEADER,
  SUPPORTED_VERSIONS,
  isModern,
  resolveVersion,
  type ProtocolVersion,
} from './protocol-version.js';
import { callTool } from './tool-dispatch.js';
import { TOOL_DEFINITIONS, relayToolOf, scopeOf } from './tools.js';

const SERVER_INFO = { name: 'ak-vault', title: 'AgentKit Vault', version: WORKER_VERSION };
const INSTRUCTIONS =
  'Search, describe and use the secrets in your AgentKit Vault. Secret values are never returned. Reads, requests and run need one of your devices online with `ak secrets sync now --watch --relay`; a set or delete with no device online is sealed and queued until a device applies it.';
const CAPABILITIES = { tools: { listChanged: false } };

export async function handleMcp(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (PRM_PATHS.includes(pathname)) return handleProtectedResourceMetadata(request, env);
  return handleEndpoint(request, env);
}

function plainError(status: number, code: 'bad_request' | 'forbidden', message: string, headers: Record<string, string> = {}): Response {
  return jsonResponse({ error: { code, message } }, status, headers);
}

/** Absent → allowed (non-browser clients); present → must be an `https:` origin (DNS-rebinding guard). */
function originAllowed(origin: string | null): boolean {
  if (origin === null) return true;
  try {
    const url = new URL(origin);
    return url.protocol === 'https:' && url.origin === origin;
  } catch {
    return false;
  }
}

function mediaType(header: string | null): string {
  return (header ?? '').split(';')[0]!.trim().toLowerCase();
}

/** Media ranges listed in `Accept`, lower-cased without parameters. */
function acceptRanges(header: string | null): string[] {
  return (header ?? '')
    .split(',')
    .map((part) => mediaType(part))
    .filter((r) => r.length > 0);
}

function acceptsJson(ranges: string[]): boolean {
  return ranges.some((r) => r === 'application/json' || r === 'application/*' || r === '*/*');
}

/** Decode an `Mcp-Name` value, including the `=?base64?…?=` sentinel form; null when malformed. */
function decodeHeaderValue(value: string): string | null {
  const match = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/.exec(value);
  if (!match) return /^[\x20-\x7e\t]*$/.test(value) ? value : null;
  try {
    const binary = atob(match[1]!);
    return utf8Decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function handleEndpoint(request: Request, env: Env): Promise<Response> {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { Allow: 'POST' } });
  if (request.method !== 'POST') return plainError(405, 'bad_request', 'method not allowed', { Allow: 'POST' });
  if (!originAllowed(request.headers.get('Origin'))) return plainError(403, 'forbidden', 'origin not allowed');
  if (!syncEnabled(env)) return resultResponse(errorResult(new ApiError('sync_disabled')));

  const auth = await authenticateMcp(request, env);
  if (!auth.ok) return auth.response;

  const resolved = resolveVersion(request.headers.get(PROTOCOL_VERSION_HEADER));
  if (!resolved.ok) {
    return rpcError(null, RPC.unsupportedProtocolVersion, 'Unsupported protocol version', 400, { supported: [...SUPPORTED_VERSIONS], requested: resolved.requested });
  }
  const version = resolved.version;
  if (mediaType(request.headers.get('Content-Type')) !== 'application/json') return plainError(415, 'bad_request', 'Content-Type must be application/json');
  const ranges = acceptRanges(request.headers.get('Accept'));
  // 2026-07-28 clients list both types; a 2025-11-25 client may omit Accept entirely.
  const acceptable = isModern(version) ? acceptsJson(ranges) && ranges.includes('text/event-stream') : ranges.length === 0 || acceptsJson(ranges);
  if (!acceptable) return plainError(406, 'bad_request', 'Accept must list application/json and text/event-stream');

  const parsed = parseMessage(await readBodyCapped(request, LIMITS.request_body_max_bytes));
  if (!parsed.ok) return rpcError(parsed.id, parsed.code, parsed.message, 400);
  const message = parsed.message;
  if (message.kind === 'notification') return accepted();

  if (isModern(version)) {
    const refusal = modernHeaderRefusal(request, message, version);
    if (refusal) return refusal;
  }
  return dispatchMethod(env, auth.claims, version, message);
}

/** 2026-07-28 request metadata: headers mirror the body, and `_meta` names the version (400 otherwise). */
function modernHeaderRefusal(request: Request, message: JsonRpcRequest, version: ProtocolVersion): Response | null {
  const mismatch = (what: string) => rpcError(message.id, RPC.headerMismatch, `Header mismatch: ${what}`, 400);
  if (request.headers.get('Mcp-Method') !== message.method) return mismatch('Mcp-Method is missing or does not match the body method');
  if (message.method === 'tools/call') {
    const header = request.headers.get('Mcp-Name');
    const name = header === null ? null : decodeHeaderValue(header);
    if (name === null || name !== message.params['name']) return mismatch('Mcp-Name is missing or does not match the tool name');
  }
  const meta = message.params['_meta'];
  if (!isObject(meta) || typeof meta[META_PROTOCOL_VERSION] !== 'string' || !isObject(meta[META_CLIENT_CAPABILITIES])) {
    return rpcError(message.id, RPC.invalidParams, 'Invalid params: _meta must carry the protocol version and client capabilities', 400);
  }
  if (meta[META_PROTOCOL_VERSION] !== version) return mismatch('MCP-Protocol-Version does not match _meta');
  return null;
}

function complete(version: ProtocolVersion, result: Record<string, unknown>): Record<string, unknown> {
  return isModern(version) ? { resultType: 'complete', ...result, _meta: { [META_SERVER_INFO]: SERVER_INFO } } : result;
}

async function dispatchMethod(env: Env, claims: McpClaims, version: ProtocolVersion, message: JsonRpcRequest): Promise<Response> {
  const { id, method } = message;
  switch (method) {
    case 'server/discover':
      if (!isModern(version)) break;
      return rpcResult(id, complete(version, { supportedVersions: [...SUPPORTED_VERSIONS], capabilities: CAPABILITIES, instructions: INSTRUCTIONS }));
    case 'initialize':
      if (isModern(version)) break;
      // Stateless: the negotiated version is the legacy one and no session is created.
      return rpcResult(id, { protocolVersion: LEGACY_VERSION, capabilities: CAPABILITIES, serverInfo: SERVER_INFO, instructions: INSTRUCTIONS });
    case 'ping':
      return rpcResult(id, complete(version, {}));
    case 'tools/list':
      return rpcResult(id, complete(version, { tools: TOOL_DEFINITIONS }));
    case 'tools/call':
      return toolsCall(env, claims, version, message);
  }
  // 2026-07-28 answers an unknown method with 404; 2025-11-25 with a 200 JSON-RPC error.
  return rpcError(id, RPC.methodNotFound, 'Method not found', isModern(version) ? 404 : 200);
}

async function toolsCall(env: Env, claims: McpClaims, version: ProtocolVersion, message: JsonRpcRequest): Promise<Response> {
  const { id, params } = message;
  const name = params['name'];
  const tool = typeof name === 'string' ? relayToolOf(name) : null;
  if (tool === null) return rpcError(id, RPC.invalidParams, 'Unknown tool', 200);
  const args = params['arguments'] ?? {};
  if (!isObject(args)) return rpcError(id, RPC.invalidParams, 'Invalid params: arguments must be an object', 200);
  const needed = scopeOf(tool);
  if (!hasScope(claims, needed)) return insufficientScope(env, claims, needed);
  const result = await callTool(env, claims, tool, args);
  return rpcResult(id, complete(version, { ...result }));
}
