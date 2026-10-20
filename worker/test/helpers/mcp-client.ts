/**
 * A test MCP client for `POST /mcp` through the real Worker: mints MCP access
 * tokens (at+jwt for `<audience>/mcp`) with the test issuer and builds 2026-07-28
 * or 2025-11-25 requests with the matching headers and `_meta`.
 */
import { env } from 'cloudflare:workers';
import { buildSealKeyDoc, randomId, type JsonObject, type RelayErrorCode } from '@ak-vault/protocol';
import worker from '../../src/index.js';
import type { Env } from '../../src/env.js';
import { BASE, call, type TestDevice } from './api-client.js';
import { signJwt, TEST_AUDIENCE, TEST_ISSUER } from './issuer.js';
import type { RelayConnection } from './relay-client.js';
import type { VaultFixture } from './vault-fixture.js';

export const MCP_URL = `${BASE}/mcp`;
export const MCP_RESOURCE = `${TEST_AUDIENCE}/mcp`;
export const ALL_MCP_SCOPES = 'vault-mcp:read vault-mcp:write vault-mcp:use';
const KID = 'test-issuer-key-1';

export interface McpTokenArgs {
  sub: string;
  scope?: string;
  grantId?: string;
  clientId?: string;
  /** Extra or replacement claims (undefined removes one). */
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
}

export async function mintMcpToken(args: McpTokenArgs): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const grant = args.grantId ?? `grant-${randomId()}`;
  const claims: Record<string, unknown> = {
    iss: TEST_ISSUER,
    aud: MCP_RESOURCE,
    sub: args.sub,
    client_id: args.clientId ?? 'https://client.example/oauth/client.json',
    grant_id: grant,
    sid: grant,
    scope: args.scope ?? ALL_MCP_SCOPES,
    jti: randomId(),
    iat: now,
    nbf: now,
    exp: now + 300,
    ...args.claims,
  };
  for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
  return signJwt({ alg: 'ES256', typ: 'at+jwt', kid: KID, ...args.header }, claims);
}

export interface McpResponse {
  status: number;
  headers: Headers;
  text: string;
  // Response JSON is untyped wire data; tests assert on its shape.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
}

export interface PostOptions {
  /** `MCP-Protocol-Version`; `null` sends none. Default 2026-07-28. */
  version?: string | null;
  headers?: Record<string, string>;
  method?: string;
  env?: Partial<Env>;
  url?: string;
  rawBody?: string;
}

async function toResponse(res: Response): Promise<McpResponse> {
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: res.status, headers: res.headers, text, json };
}

/** POST one body to `/mcp` with the given bearer token (null sends none). */
export async function mcpPost(token: string | null, body: unknown, opts: PostOptions = {}): Promise<McpResponse> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
  const version = opts.version === undefined ? '2026-07-28' : opts.version;
  if (version !== null) headers['MCP-Protocol-Version'] = version;
  if (token) headers['Authorization'] = `Bearer ${token}`;
  Object.assign(headers, opts.headers);
  const method = opts.method ?? 'POST';
  const init: RequestInit = { method, headers };
  if (method !== 'GET' && method !== 'HEAD') init.body = opts.rawBody ?? JSON.stringify(body);
  return toResponse(await worker.fetch(new Request(opts.url ?? MCP_URL, init), { ...env, ...opts.env } as Env));
}

export function modernMeta(version = '2026-07-28'): JsonObject {
  return {
    'io.modelcontextprotocol/protocolVersion': version,
    'io.modelcontextprotocol/clientInfo': { name: 'test-client', version: '1.0.0' },
    'io.modelcontextprotocol/clientCapabilities': {},
  };
}

/** A 2026-07-28 request with `_meta` and the mirrored `Mcp-Method` / `Mcp-Name` headers. */
export function modern(token: string | null, method: string, params: Record<string, unknown> = {}, opts: PostOptions = {}): Promise<McpResponse> {
  const headers: Record<string, string> = { 'Mcp-Method': method };
  if (method === 'tools/call' && typeof params['name'] === 'string') headers['Mcp-Name'] = params['name'];
  return mcpPost(token, { jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: modernMeta() } }, { ...opts, headers: { ...headers, ...opts.headers } });
}

/** A 2025-11-25 request (header `2025-11-25` unless overridden). */
export function legacy(token: string | null, method: string, params: Record<string, unknown> = {}, opts: PostOptions = {}): Promise<McpResponse> {
  return mcpPost(token, { jsonrpc: '2.0', id: 1, method, params }, { version: '2025-11-25', ...opts });
}

/** `tools/call` in 2026-07-28 form. */
export function callTool(token: string, name: string, args: Record<string, unknown> = {}, opts: PostOptions = {}): Promise<McpResponse> {
  return modern(token, 'tools/call', { name, arguments: args }, opts);
}

/** The structured result of a successful `tools/call` response. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function structured(res: McpResponse): any {
  if (res.status !== 200 || !res.json?.result) throw new Error(`tools/call failed: ${res.status} ${res.text}`);
  return res.json.result.structuredContent;
}

/**
 * Answer the next relay call on `conn` with `answer(call)` and return that call, while
 * `pending` (the MCP request) runs. The device signs the result like a real device.
 */
export async function answerNext(conn: RelayConnection, answer: (call: JsonObject) => { ok: true; result: JsonObject } | { ok: false; code: RelayErrorCode }): Promise<JsonObject> {
  const frame = await conn.next();
  if (frame['type'] !== 'call') throw new Error(`expected a call frame, got ${String(frame['type'])}`);
  const reply = answer(frame);
  const callId = frame['call_id'] as string;
  if (reply.ok) conn.result({ call_id: callId, ok: true, result: reply.result });
  else conn.result({ call_id: callId, ok: false, error: { code: reply.code } });
  return frame;
}

/** Publish the vault's current seal-key document so sealed writes can be queued. */
export async function publishSealKey(fx: VaultFixture, author: TestDevice = fx.owner): Promise<void> {
  const doc = buildSealKeyDoc(
    { vk: fx.vk.get(fx.keyEpoch)!, vaultId: fx.vaultId, keyEpoch: fx.keyEpoch, membershipSeq: fx.state.seq, author: author.keys.record.device_id, ts: Date.now() },
    author.keys.signSecret,
  );
  const res = await call(author, 'PUT', `/v1/vaults/${fx.vaultId}/seal-key`, { seal_key: doc });
  if (res.status !== 200) throw new Error(`seal-key publish failed: ${res.status}`);
}