/**
 * JSON-RPC 2.0 framing for `/mcp`: exactly one request or notification per POST
 * (batches and client responses are refused), and response builders. Error
 * messages are fixed strings: nothing from the request body is ever echoed.
 */
import { utf8Decode } from '@ak-vault/protocol';
import { jsonResponse } from '../http/responses.js';

export type JsonRpcId = string | number;

export const RPC = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
  /** 2026-07-28: headers missing, malformed or not matching the body. */
  headerMismatch: -32020,
  /** 2026-07-28: the requested protocol version is not served. */
  unsupportedProtocolVersion: -32022,
} as const;

export interface JsonRpcRequest {
  kind: 'request';
  id: JsonRpcId;
  method: string;
  params: Record<string, unknown>;
}

export interface JsonRpcNotification {
  kind: 'notification';
  method: string;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification;

export type ParseOutcome = { ok: true; message: JsonRpcMessage } | { ok: false; code: number; message: string; id: JsonRpcId | null };

const MAX_METHOD_LENGTH = 128;
const MAX_ID_LENGTH = 256;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validId(value: unknown): value is JsonRpcId {
  if (typeof value === 'string') return value.length <= MAX_ID_LENGTH;
  return typeof value === 'number' && Number.isSafeInteger(value);
}

/** Parse one JSON-RPC message from a request body. */
export function parseMessage(body: Uint8Array): ParseOutcome {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(body));
  } catch {
    return { ok: false, code: RPC.parseError, message: 'parse error', id: null };
  }
  if (Array.isArray(value)) return { ok: false, code: RPC.invalidRequest, message: 'batches are not supported', id: null };
  if (!isObject(value)) return { ok: false, code: RPC.invalidRequest, message: 'invalid request', id: null };
  const id = validId(value['id']) ? value['id'] : null;
  if (value['jsonrpc'] !== '2.0') return { ok: false, code: RPC.invalidRequest, message: 'invalid request', id };
  if ('result' in value || 'error' in value) return { ok: false, code: RPC.invalidRequest, message: 'the server accepts requests and notifications only', id };
  const method = value['method'];
  if (typeof method !== 'string' || method.length === 0 || method.length > MAX_METHOD_LENGTH) return { ok: false, code: RPC.invalidRequest, message: 'invalid request', id };
  const params = value['params'];
  if (params !== undefined && !isObject(params)) return { ok: false, code: RPC.invalidRequest, message: 'params must be an object', id };
  if (!('id' in value)) return { ok: true, message: { kind: 'notification', method } };
  if (id === null) return { ok: false, code: RPC.invalidRequest, message: 'id must be a string or an integer', id: null };
  return { ok: true, message: { kind: 'request', id, method, params: params ?? {} } };
}

const MCP_HEADERS = { 'Cache-Control': 'no-store' };

export function rpcResult(id: JsonRpcId, result: Record<string, unknown>): Response {
  return jsonResponse({ jsonrpc: '2.0', id, result }, 200, MCP_HEADERS);
}

export function rpcError(id: JsonRpcId | null, code: number, message: string, status: number, data?: Record<string, unknown>): Response {
  const error: Record<string, unknown> = { code, message };
  if (data !== undefined) error['data'] = data;
  // JSON-RPC 2.0 §5: an error response always has `id`, null when the request's could not be read.
  return jsonResponse({ jsonrpc: '2.0', id, error }, status, MCP_HEADERS);
}

/** A notification the server accepts: `202 Accepted` with no body. */
export function accepted(): Response {
  return new Response(null, { status: 202, headers: MCP_HEADERS });
}
