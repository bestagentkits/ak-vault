/**
 * Device relay frames (spec §9.7): a closed set of canonical-JSON text frames.
 * The device signs `hello` (context `akv1/relay`) and every `result`
 * (context `akv1/relay-result`) with its device key, over the frame without `sig`.
 * The frame size cap is the deployment's `relay_frame_max_bytes` (owned by the
 * Worker limits), passed in by the caller.
 */
import { utf8Encode } from './bytes.js';
import { cjsonParse, type JsonObject } from './canonical-json.js';
import { fail } from './errors.js';
import { PROOF_MAX_SKEW_MS } from './proof.js';
import { SIGN_CONTEXT, deviceIdFromSignPub, signObject, verifyObject } from './signing.js';
import { asArray, asB64, asBool, asEnum, asId, asIdList, asInt, asObject, asPrintableAscii, asString, checkVersion, exactKeys } from './validate.js';

export const RELAY_FRAME_TYPES = ['hello', 'ready', 'reauth', 'call', 'result'] as const;
export type RelayFrameType = (typeof RELAY_FRAME_TYPES)[number];
export const RELAY_TOOLS = ['search', 'list', 'describe', 'set', 'delete', 'request', 'run'] as const;
export type RelayTool = (typeof RELAY_TOOLS)[number];
export const MCP_SCOPES = ['vault-mcp:read', 'vault-mcp:write', 'vault-mcp:use'] as const;
export type McpScope = (typeof MCP_SCOPES)[number];
export const RELAY_ERROR_CODES = ['denied', 'pending_approval', 'not_found', 'invalid_args', 'conflict', 'unsupported', 'internal'] as const;
export type RelayErrorCode = (typeof RELAY_ERROR_CODES)[number];
/** Scope each tool needs (spec §9.7). */
export const TOOL_SCOPE: Record<RelayTool, McpScope> = {
  search: 'vault-mcp:read',
  list: 'vault-mcp:read',
  describe: 'vault-mcp:read',
  set: 'vault-mcp:write',
  delete: 'vault-mcp:write',
  request: 'vault-mcp:use',
  run: 'vault-mcp:use',
};
export const MAX_HELLO_VAULTS = 16;

export interface HelloFrame {
  v: 1;
  type: 'hello';
  device_id: string;
  vaults: string[];
  tools: RelayTool[];
  ts: number;
  sig: string;
}
export interface ReadyFrame {
  v: 1;
  type: 'ready';
  exp: number;
}
export interface ReauthFrame {
  v: 1;
  type: 'reauth';
  token: string;
  proof: string;
}
export interface RelayCaller {
  client_id: string;
  grant_id: string;
  scopes: McpScope[];
}
export interface CallFrame {
  v: 1;
  type: 'call';
  call_id: string;
  vault_id: string;
  tool: RelayTool;
  args: JsonObject;
  caller: RelayCaller;
  deadline_ms: number;
}
export type ResultFrame =
  | { v: 1; type: 'result'; call_id: string; ok: true; result: JsonObject; sig: string }
  | { v: 1; type: 'result'; call_id: string; ok: false; error: { code: RelayErrorCode }; sig: string };
export type RelayFrame = HelloFrame | ReadyFrame | ReauthFrame | CallFrame | ResultFrame;

function uniqueEnumList<T extends string>(value: unknown, allowed: readonly T[], what: string, min: number, max: number): T[] {
  const list = asArray(value, what, max).map((v, i) => asEnum(v, allowed, `${what}[${i}]`));
  if (list.length < min) fail('bad_request', `${what} must have ${min}..${max} entries`);
  if (new Set(list).size !== list.length) fail('bad_request', `${what} contains duplicates`);
  return list;
}

function parseCaller(value: unknown, what: string): RelayCaller {
  const obj = asObject(value, what);
  exactKeys(obj, ['client_id', 'grant_id', 'scopes'], what);
  return {
    client_id: asPrintableAscii(obj['client_id'], `${what}.client_id`, 256, 1),
    grant_id: asPrintableAscii(obj['grant_id'], `${what}.grant_id`, 64, 1),
    scopes: uniqueEnumList(obj['scopes'], MCP_SCOPES, `${what}.scopes`, 1, MCP_SCOPES.length),
  };
}

/** Validate a frame object (already decoded) by its `type`. */
export function parseRelayFrameObject(value: unknown, what = 'relay frame'): RelayFrame {
  const obj = asObject(value, what);
  checkVersion(obj, what);
  const type = asEnum(obj['type'], RELAY_FRAME_TYPES, `${what}.type`);
  switch (type) {
    case 'hello': {
      exactKeys(obj, ['v', 'type', 'device_id', 'vaults', 'tools', 'ts', 'sig'], what);
      const vaults = asIdList(obj['vaults'], `${what}.vaults`, MAX_HELLO_VAULTS);
      if (vaults.length < 1) fail('bad_request', `${what}.vaults must not be empty`);
      return {
        v: 1,
        type,
        device_id: asId(obj['device_id'], `${what}.device_id`),
        vaults,
        tools: uniqueEnumList(obj['tools'], RELAY_TOOLS, `${what}.tools`, 1, RELAY_TOOLS.length),
        ts: asInt(obj['ts'], `${what}.ts`),
        sig: asB64(obj['sig'], `${what}.sig`, 64),
      };
    }
    case 'ready':
      exactKeys(obj, ['v', 'type', 'exp'], what);
      return { v: 1, type, exp: asInt(obj['exp'], `${what}.exp`) };
    case 'reauth':
      exactKeys(obj, ['v', 'type', 'token', 'proof'], what);
      return { v: 1, type, token: asString(obj['token'], `${what}.token`, Number.MAX_SAFE_INTEGER, 1), proof: asString(obj['proof'], `${what}.proof`, Number.MAX_SAFE_INTEGER, 1) };
    case 'call':
      exactKeys(obj, ['v', 'type', 'call_id', 'vault_id', 'tool', 'args', 'caller', 'deadline_ms'], what);
      return {
        v: 1,
        type,
        call_id: asId(obj['call_id'], `${what}.call_id`),
        vault_id: asId(obj['vault_id'], `${what}.vault_id`),
        tool: asEnum(obj['tool'], RELAY_TOOLS, `${what}.tool`),
        args: asObject(obj['args'], `${what}.args`) as JsonObject,
        caller: parseCaller(obj['caller'], `${what}.caller`),
        deadline_ms: asInt(obj['deadline_ms'], `${what}.deadline_ms`, 1),
      };
    default: {
      const ok = asBool(obj['ok'], `${what}.ok`);
      const call_id = asId(obj['call_id'], `${what}.call_id`);
      const sig = asB64(obj['sig'], `${what}.sig`, 64);
      if (ok) {
        exactKeys(obj, ['v', 'type', 'call_id', 'ok', 'result', 'sig'], what);
        return { v: 1, type: 'result', call_id, ok, result: asObject(obj['result'], `${what}.result`) as JsonObject, sig };
      }
      exactKeys(obj, ['v', 'type', 'call_id', 'ok', 'error', 'sig'], what);
      const error = asObject(obj['error'], `${what}.error`);
      exactKeys(error, ['code'], `${what}.error`);
      return { v: 1, type: 'result', call_id, ok, error: { code: asEnum(error['code'], RELAY_ERROR_CODES, `${what}.error.code`) }, sig };
    }
  }
}

/**
 * Parse one received WebSocket frame. A binary frame (`Uint8Array`), a text
 * frame over `maxBytes` UTF-8 bytes, non-canonical JSON, an unknown `type`
 * or a wrong key set is refused (`bad_request`; `v` ≠ 1 is
 * `unsupported_version`). Callers close the connection with 4400.
 */
export function parseRelayFrame(data: string | Uint8Array, opts: { maxBytes: number }): RelayFrame {
  if (typeof data !== 'string') fail('bad_request', 'relay frames are text only');
  if (utf8Encode(data).length > asInt(opts.maxBytes, 'maxBytes', 1)) fail('bad_request', 'relay frame is too large');
  return parseRelayFrameObject(cjsonParse(data));
}

export function signHello(fields: Omit<HelloFrame, 'v' | 'type' | 'sig'>, secretKey: Uint8Array): HelloFrame {
  const frame = signObject(SIGN_CONTEXT.relay, { v: 1 as const, type: 'hello' as const, ...fields }, secretKey);
  return parseRelayFrameObject(frame) as HelloFrame;
}

/**
 * Verify a `hello` against the upgrade key: `device_id` = `kid(signPub)`
 * (`forbidden`), signature (`invalid_signature`), `ts` within ±60 s of `now`
 * (`unauthorized`).
 */
export function verifyHello(value: unknown, opts: { signPub: string | Uint8Array; now: number; maxSkewMs?: number }): HelloFrame {
  const frame = parseRelayFrameObject(value);
  if (frame.type !== 'hello') fail('bad_request', 'expected a hello frame');
  if (frame.device_id !== deviceIdFromSignPub(opts.signPub)) fail('forbidden', 'hello device_id does not match the upgrade key');
  verifyObject(SIGN_CONTEXT.relay, frame, opts.signPub);
  if (Math.abs(opts.now - frame.ts) > (opts.maxSkewMs ?? PROOF_MAX_SKEW_MS)) fail('unauthorized', 'hello outside the time window');
  return frame;
}

export type UnsignedResult =
  | { call_id: string; ok: true; result: JsonObject }
  | { call_id: string; ok: false; error: { code: RelayErrorCode } };

export function signResult(fields: UnsignedResult, secretKey: Uint8Array): ResultFrame {
  const frame = signObject(SIGN_CONTEXT.relayResult, { v: 1 as const, type: 'result' as const, ...fields }, secretKey);
  return parseRelayFrameObject(frame) as ResultFrame;
}

/** Verify a `result` signed by the device that holds `signPub` (`invalid_signature` otherwise). */
export function verifyResult(value: unknown, signPub: string | Uint8Array): ResultFrame {
  const frame = parseRelayFrameObject(value);
  if (frame.type !== 'result') fail('bad_request', 'expected a result frame');
  verifyObject(SIGN_CONTEXT.relayResult, frame, signPub);
  return frame;
}
