/**
 * `secrets_prepare_write`, `secrets_request_input` and `secrets_write_status` (spec
 * §3.10, §3.11, §9.8): the Worker-local tools for a secret the AI must never see. They
 * take a name, never a value.
 *
 * - `prepare_write` (dashboard flow, ADR 0002 D8) seals the target to the vault's seal
 *   key, stores the request and answers a link for the person to open in the dashboard.
 * - `request_input` (ADR 0004) asks an online writer device of the account for a
 *   one-time input key (relay tool `request_input`), stores the request bound to that
 *   device and answers a `/input` link whose fragment carries the public key. With no
 *   device online it falls back to the dashboard flow, and fails `device_offline` when
 *   that cannot run either. While input requests are off it is the dashboard flow.
 *
 * The name transits Worker memory as in ADR 0002 D7 (sealed, or relayed to the device
 * and returned in the link's fragment) and is never stored in the clear, logged or put
 * in an error; the log line carries the tool, a stable outcome code, latency and
 * hashed client/account only.
 */
import { b64decodeLength, b64encode, parseToolResult, randomBytes, sealWriteIntent, type JsonObject, type RelayErrorCode, type Role } from '@ak-vault/protocol';
import type { McpClaims } from '../auth/jwt-verify.js';
import { inputRequestsEnabled, type Env } from '../env.js';
import { accountLogTag, clientLogTag, logMcpCall } from '../http/operational-logger.js';
import { REMOTE_ACCESS_LIMITS as L } from '../limits.js';
import { relayStub, type RelayOutcome } from '../relay/relay-rpc.js';
import type { CallToolResult } from './tool-dispatch.js';
import type { LocalTool } from './tools.js';

type LocalErrorCode =
  | 'invalid_args'
  | 'rate_limited'
  | 'not_found'
  | 'no_seal_key'
  | 'too_many_requests'
  | 'internal'
  | 'device_offline'
  | 'device_timeout'
  | 'conflict'
  | 'denied';

const MESSAGES: Record<LocalErrorCode, string> = {
  invalid_args: 'The arguments do not match the tool input schema.',
  rate_limited: 'Too many calls. Retry after retry_after_s seconds.',
  not_found: 'No write request matches.',
  no_seal_key: 'The vault has no seal key for requests yet. Run `ak secrets sync now` once on an owner device.',
  too_many_requests: 'Too many open write requests. Ask the user to finish or cancel one, or wait for them to expire.',
  internal: 'Internal error.',
  device_offline:
    'No device can take this request: start `ak secrets sync now --watch --relay` on one of your devices, then call secrets_request_input again. Do not ask the user for the value.',
  device_timeout: 'The device did not answer in time. Call secrets_request_input again.',
  conflict: 'The device refused the operation: "create" names a secret that already exists, or "replace" one that does not.',
  denied: 'The device refused this request (its own grants, or it holds too many open input requests).',
};

const VAULT_REQUIRED = 'Pass vault_id: your online devices hold several vaults, or none is online to choose one.';
const REFUSED = 'The vault cannot take a write request now (a key rotation is pending, or the account lost write access). Retry after the vault syncs.';
const OWNER_ONLY = 'Only a vault owner can fill in a write request: it is completed in the dashboard, and a browser device enrolls only as an owner. Ask an owner of the vault, or use secrets_set with a device online.';
const VAULT_UNKNOWN = 'vault_id does not name a vault this account can use.';
const READ_ONLY = 'This account can only read this vault.';
const NEXT = 'Give form_url to the user to open in their browser and type the value there. Then poll secrets_write_status.';

interface Outcome {
  result: CallToolResult;
  code: string;
}

function result(structured: Record<string, unknown>, isError: boolean): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured, isError };
}

function fail(code: LocalErrorCode, extra: Record<string, unknown> = {}, message?: string): Outcome {
  return { result: result({ code, message: message ?? MESSAGES[code], ...extra }, true), code };
}

function ok(structured: Record<string, unknown>, code = 'ok'): Outcome {
  return { result: result(structured, false), code };
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Exactly the keys in `allowed`, each of the given primitive type; anything else is invalid. */
function checkArgs(args: Record<string, unknown>, shape: Record<string, 'string' | 'integer'>, required: readonly string[]): boolean {
  for (const key of required) if (args[key] === undefined) return false;
  for (const [key, value] of Object.entries(args)) {
    if (key === 'vault_id') {
      if (typeof value !== 'string') return false;
      try {
        b64decodeLength(value, 16);
      } catch {
        return false;
      }
      continue;
    }
    const type = shape[key];
    if (type === undefined) return false;
    if (type === 'string' ? typeof value !== 'string' : typeof value !== 'number' || !Number.isSafeInteger(value)) return false;
  }
  return true;
}

/** The checked arguments of a write request: a name and its intent, never a value. */
interface WriteArgs {
  operation: 'create' | 'replace';
  ttlS: number;
  purpose?: string;
  sensitivity?: 'normal' | 'high';
}

/** Validate the shared arguments of `prepare_write` and `request_input`; null when invalid. The name stays in `args`. */
function parseWriteArgs(args: Record<string, unknown>): WriteArgs | null {
  const shape = { name: 'string', operation: 'string', purpose: 'string', sensitivity: 'string', ttl_s: 'integer' } as const;
  if (!checkArgs(args, shape, ['name'])) return null;
  const operation = args['operation'] ?? 'create';
  const ttlS = (args['ttl_s'] as number | undefined) ?? L.write_request_ttl_s;
  if ((operation !== 'create' && operation !== 'replace') || ttlS < L.write_request_min_ttl_s || ttlS > L.write_request_ttl_s) return null;
  const sensitivity = args['sensitivity'];
  if (sensitivity !== undefined && sensitivity !== 'normal' && sensitivity !== 'high') return null;
  return {
    operation,
    ttlS,
    ...(args['purpose'] === undefined ? {} : { purpose: args['purpose'] as string }),
    ...(sensitivity === undefined ? {} : { sensitivity }),
  };
}

function vaultStub(env: Env, vaultId: string) {
  return env.VAULT.get(env.VAULT.idFromName(vaultId));
}

/** The vault the call targets: `vault_id`, or the only vault the account's online devices hold. */
async function selectVault(env: Env, claims: McpClaims, args: Record<string, unknown>): Promise<{ vaultId: string } | Outcome> {
  const named = args['vault_id'] as string | undefined;
  if (named !== undefined) return { vaultId: named };
  const known = await relayStub(env, claims.sub).knownVaults();
  return known.length === 1 ? { vaultId: known[0]! } : fail('invalid_args', {}, VAULT_REQUIRED);
}

function formUrl(env: Env, vaultId: string, requestId: string): string {
  return `${env.VAULT_AUDIENCE}/app#write=${requestId}&vault=${vaultId}`;
}

/** `<origin>/input#r=…&v=…&k=…&n=…[&p=…]`: IDs and the public input key are b64url, name and purpose percent-encoded. */
function inputFormUrl(env: Env, vaultId: string, requestId: string, inputPub: string, name: string, purpose: string | undefined): string {
  const parts = [`r=${requestId}`, `v=${vaultId}`, `k=${inputPub}`, `n=${encodeURIComponent(name)}`];
  if (purpose !== undefined) parts.push(`p=${encodeURIComponent(purpose)}`);
  return `${env.VAULT_AUDIENCE}/input#${parts.join('&')}`;
}

/** The account's role in the vault, or the refusal: an unknown vault and another account's answer alike. */
async function memberRole(env: Env, claims: McpClaims, vaultId: string, args: Record<string, unknown>): Promise<Role | Outcome> {
  const role = await vaultStub(env, vaultId).accountRole(claims.sub);
  if (role === null) return fail('invalid_args', {}, args['vault_id'] === undefined ? undefined : VAULT_UNKNOWN);
  return role;
}

/**
 * The dashboard flow (spec §3.10) for an `owner` account: seal the target to the
 * current seal key and store the request. `flow` is added to the answer when set
 * (`request_input`); `prepare_write` answers without it.
 */
async function dashboardWrite(env: Env, claims: McpClaims, vaultId: string, args: Record<string, unknown>, parsed: WriteArgs, flow?: 'dashboard'): Promise<Outcome> {
  const vault = vaultStub(env, vaultId);
  const doc = await vault.getSealKey();
  if (!doc) return fail('no_seal_key');

  const now = Date.now();
  let wire;
  try {
    wire = sealWriteIntent(doc.seal_pub, {
      vaultId,
      keyEpoch: doc.key_epoch,
      origin: { kind: 'mcp', account: claims.sub, client_id: claims.client_id, grant_id: claims.grant_id },
      operation: parsed.operation,
      ts: now,
      expiresAt: now + parsed.ttlS * 1000,
      target: {
        name: args['name'] as string,
        ...(parsed.purpose === undefined ? {} : { purpose: parsed.purpose }),
        ...(parsed.sensitivity === undefined ? {} : { sensitivity: parsed.sensitivity }),
      },
    });
  } catch {
    return fail('invalid_args');
  } finally {
    // Drop the name reference as soon as the ciphertext exists (strings cannot be zeroized).
    delete args['name'];
  }
  const created = await vault.createWriteRequest(wire, claims.iat, now);
  if (created === 'too_many') return fail('too_many_requests');
  if (created === 'refused') return fail('invalid_args', {}, REFUSED);
  return ok(
    {
      status: 'pending_user',
      request_id: wire.request_id,
      vault_id: vaultId,
      ...(flow === undefined ? {} : { flow }),
      form_url: formUrl(env, vaultId, wire.request_id),
      expires_at: wire.expires_at,
      next: NEXT,
    },
    'pending_user',
  );
}

async function prepareWrite(env: Env, claims: McpClaims, args: Record<string, unknown>, flow?: 'dashboard'): Promise<Outcome> {
  const parsed = parseWriteArgs(args);
  if (!parsed) return fail('invalid_args');
  const selected = await selectVault(env, claims, args);
  if ('result' in selected) return selected;
  const role = await memberRole(env, claims, selected.vaultId, args);
  if (typeof role !== 'string') return role;
  if (role === 'editor') return fail('invalid_args', {}, OWNER_ONLY);
  if (role !== 'owner') return fail('invalid_args', {}, VAULT_UNKNOWN);
  return dashboardWrite(env, claims, selected.vaultId, args, parsed, flow);
}

/** A device's refusal of `request_input` as a tool error; nothing from the device is echoed. */
function fromDeviceError(code: RelayErrorCode): Outcome {
  if (code === 'conflict' || code === 'denied' || code === 'invalid_args') return fail(code);
  return fail('internal');
}

/**
 * `secrets_request_input` while input requests are on (spec §3.11): an `owner` or
 * `editor` account, room under the caps, then the device flow; with no device online
 * the dashboard flow for an owner, else `device_offline` (never a request for the value).
 */
async function requestInput(env: Env, claims: McpClaims, args: Record<string, unknown>): Promise<Outcome> {
  if (!inputRequestsEnabled(env)) return prepareWrite(env, claims, args, 'dashboard');
  const parsed = parseWriteArgs(args);
  if (!parsed) return fail('invalid_args');
  const selected = await selectVault(env, claims, args);
  if ('result' in selected) return selected;
  const { vaultId } = selected;
  const role = await memberRole(env, claims, vaultId, args);
  if (typeof role !== 'string') return role;
  if (role !== 'owner' && role !== 'editor') return fail('invalid_args', {}, READ_ONLY);
  const vault = vaultStub(env, vaultId);
  if (!(await vault.writeRequestRoom(claims.sub, claims.client_id))) return fail('too_many_requests');

  const name = args['name'] as string;
  const requestId = b64encode(randomBytes(16));
  const createdAt = Date.now();
  const expiresAt = createdAt + parsed.ttlS * 1000;
  const relayArgs: JsonObject = {
    request_id: requestId,
    name,
    operation: parsed.operation,
    expires_at: expiresAt,
    ...(parsed.purpose === undefined ? {} : { purpose: parsed.purpose }),
    ...(parsed.sensitivity === undefined ? {} : { sensitivity: parsed.sensitivity }),
  };
  // Typed as the plain outcome: the RPC stub's serialized view drops the `unknown` result.
  const outcome = (await relayStub(env, claims.sub).dispatch({
    vaultId,
    tool: 'request_input',
    args: relayArgs,
    caller: { clientId: claims.client_id, grantId: claims.grant_id, scopes: [...claims.scope] },
    deadlineMs: L.relay_call_deadline_ms,
  })) as RelayOutcome;

  switch (outcome.kind) {
    case 'no_device_online': {
      // The dashboard is the only other way to complete it, and only an owner has one.
      if (role !== 'owner') return fail('device_offline');
      const fallback = await dashboardWrite(env, claims, vaultId, args, parsed, 'dashboard');
      return fallback.code === 'no_seal_key' ? fail('device_offline') : fallback;
    }
    case 'timeout':
      return fail('device_timeout');
    case 'device_busy':
      return fail('rate_limited', { retry_after_s: 1 });
    case 'invalid_args':
      return fail('invalid_args');
    case 'denied':
      return fail('denied');
    case 'result':
      break;
  }
  if (!outcome.ok) return fromDeviceError(outcome.code);

  let inputPub: string;
  try {
    const answer = parseToolResult('request_input', outcome.result);
    if (answer['request_id'] !== requestId) return fail('internal');
    inputPub = answer['input_pub'] as string;
  } catch {
    return fail('internal');
  }
  const created = await vault.createInputRequest({
    request_id: requestId,
    account: claims.sub,
    client_id: claims.client_id,
    grant_id: claims.grant_id,
    token_iat: claims.iat,
    operation: parsed.operation,
    device_id: outcome.deviceId,
    input_pub: inputPub,
    created_at: createdAt,
    expires_at: expiresAt,
  });
  if (created === 'too_many') return fail('too_many_requests');
  if (created === 'refused') return fail('invalid_args', {}, REFUSED);
  return ok(
    {
      status: 'pending_user',
      request_id: requestId,
      vault_id: vaultId,
      flow: 'device',
      form_url: inputFormUrl(env, vaultId, requestId, inputPub, name, parsed.purpose),
      expires_at: expiresAt,
      next: NEXT,
    },
    'pending_user',
  );
}

async function writeStatus(env: Env, claims: McpClaims, args: Record<string, unknown>): Promise<Outcome> {
  if (!checkArgs(args, { request_id: 'string' }, ['request_id'])) return fail('invalid_args');
  const requestId = args['request_id'] as string;
  try {
    b64decodeLength(requestId, 16);
  } catch {
    return fail('not_found');
  }
  const selected = await selectVault(env, claims, args);
  if ('result' in selected) return selected;
  const status = await vaultStub(env, selected.vaultId).writeRequestStatus(requestId, { account: claims.sub, client_id: claims.client_id, grant_id: claims.grant_id });
  if (!status) return fail('not_found');
  return ok({ ...(status as unknown as JsonObject) }, status.state);
}

/**
 * Run one Worker-local tool for an authenticated token whose scopes cover it. Never throws.
 * The rate budget is charged before the arguments are checked, as for relay tools: a call
 * refused for its arguments still spends it. Both request-creating tools share the
 * `prepare_write` budget.
 */
export async function callLocalTool(env: Env, claims: McpClaims, tool: LocalTool, rawArgs: unknown): Promise<CallToolResult> {
  const started = Date.now();
  let outcome: Outcome;
  try {
    const creates = tool === 'prepare_write' || tool === 'request_input';
    const rate = await relayStub(env, claims.sub).takeRate(claims.client_id, creates ? 'prepare_write' : null);
    if (!rate.ok) outcome = fail('rate_limited', { retry_after_s: rate.retryAfterS ?? 60 });
    else if (!isObject(rawArgs)) outcome = fail('invalid_args');
    else if (tool === 'prepare_write') outcome = await prepareWrite(env, claims, rawArgs);
    else if (tool === 'request_input') outcome = await requestInput(env, claims, rawArgs);
    else outcome = await writeStatus(env, claims, rawArgs);
  } catch {
    outcome = fail('internal');
  }
  logMcpCall({ tool: `secrets_${tool}`, outcome: outcome.code, ms: Date.now() - started, client: clientLogTag(claims.client_id), account: accountLogTag(claims.sub), audited: false });
  return outcome.result;
}
