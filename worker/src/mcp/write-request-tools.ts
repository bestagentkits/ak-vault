/**
 * `secrets_prepare_write` and `secrets_write_status` (spec §3.10, §9.8): the
 * Worker-local tools for a secret the AI must never see. `prepare_write` takes a
 * name, never a value: it seals the target to the vault's seal key, stores the
 * request and answers a link for the person to open in the dashboard. The name
 * transits Worker memory as in ADR 0002 D7 and is never stored in the clear,
 * logged or put in an error; the log line carries the tool, a stable outcome code,
 * latency and hashed client/account only.
 */
import { b64decodeLength, sealWriteIntent, type JsonObject } from '@ak-vault/protocol';
import type { McpClaims } from '../auth/jwt-verify.js';
import type { Env } from '../env.js';
import { accountLogTag, clientLogTag, logMcpCall } from '../http/operational-logger.js';
import { REMOTE_ACCESS_LIMITS as L } from '../limits.js';
import { relayStub } from '../relay/relay-rpc.js';
import type { CallToolResult } from './tool-dispatch.js';
import type { LocalTool } from './tools.js';

type LocalErrorCode = 'invalid_args' | 'rate_limited' | 'not_found' | 'no_seal_key' | 'too_many_requests' | 'internal';

const MESSAGES: Record<LocalErrorCode, string> = {
  invalid_args: 'The arguments do not match the tool input schema.',
  rate_limited: 'Too many calls. Retry after retry_after_s seconds.',
  not_found: 'No write request matches.',
  no_seal_key: 'The vault has no seal key for requests yet. Run `ak secrets sync now` once on an owner device.',
  too_many_requests: 'Too many open write requests. Ask the user to finish or cancel one, or wait for them to expire.',
  internal: 'Internal error.',
};

const VAULT_REQUIRED = 'Pass vault_id: your online devices hold several vaults, or none is online to choose one.';
const REFUSED = 'The vault cannot take a write request now (a key rotation is pending, or the account lost write access). Retry after the vault syncs.';
const VAULT_UNKNOWN = 'vault_id does not name a vault this account can use.';

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

async function prepareWrite(env: Env, claims: McpClaims, args: Record<string, unknown>): Promise<Outcome> {
  const shape = { name: 'string', operation: 'string', purpose: 'string', sensitivity: 'string', ttl_s: 'integer' } as const;
  if (!checkArgs(args, shape, ['name'])) return fail('invalid_args');
  const operation = args['operation'] ?? 'create';
  const ttl = (args['ttl_s'] as number | undefined) ?? L.write_request_ttl_s;
  if ((operation !== 'create' && operation !== 'replace') || ttl < L.write_request_min_ttl_s || ttl > L.write_request_ttl_s) return fail('invalid_args');
  const sensitivity = args['sensitivity'];
  if (sensitivity !== undefined && sensitivity !== 'normal' && sensitivity !== 'high') return fail('invalid_args');

  const selected = await selectVault(env, claims, args);
  if ('result' in selected) return selected;
  const { vaultId } = selected;
  const vault = vaultStub(env, vaultId);
  const role = await vault.accountRole(claims.sub);
  if (role === null) return fail('invalid_args', {}, args['vault_id'] === undefined ? undefined : VAULT_UNKNOWN);
  if (role !== 'owner' && role !== 'editor') return fail('invalid_args', {}, VAULT_UNKNOWN);
  const doc = await vault.getSealKey();
  if (!doc) return fail('no_seal_key');

  const now = Date.now();
  let wire;
  try {
    wire = sealWriteIntent(doc.seal_pub, {
      vaultId,
      keyEpoch: doc.key_epoch,
      origin: { kind: 'mcp', account: claims.sub, client_id: claims.client_id, grant_id: claims.grant_id },
      operation,
      ts: now,
      expiresAt: now + ttl * 1000,
      target: {
        name: args['name'] as string,
        ...(args['purpose'] === undefined ? {} : { purpose: args['purpose'] as string }),
        ...(sensitivity === undefined ? {} : { sensitivity }),
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
      form_url: formUrl(env, vaultId, wire.request_id),
      expires_at: wire.expires_at,
      next: 'Give form_url to the user to open in their browser and type the value there. Then poll secrets_write_status.',
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
 * refused for its arguments still spends it.
 */
export async function callLocalTool(env: Env, claims: McpClaims, tool: LocalTool, rawArgs: unknown): Promise<CallToolResult> {
  const started = Date.now();
  let outcome: Outcome;
  try {
    const rate = await relayStub(env, claims.sub).takeRate(claims.client_id, tool === 'prepare_write' ? 'prepare_write' : null);
    if (!rate.ok) outcome = fail('rate_limited', { retry_after_s: rate.retryAfterS ?? 60 });
    else if (!isObject(rawArgs)) outcome = fail('invalid_args');
    else outcome = tool === 'prepare_write' ? await prepareWrite(env, claims, rawArgs) : await writeStatus(env, claims, rawArgs);
  } catch {
    outcome = fail('internal');
  }
  logMcpCall({ tool: `secrets_${tool}`, outcome: outcome.code, ms: Date.now() - started, client: clientLogTag(claims.client_id), account: accountLogTag(claims.sub), audited: false });
  return outcome.result;
}
