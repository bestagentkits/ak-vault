/**
 * The two human-only write tools (spec §9.9): `secrets_prepare_write` opens a request
 * the user finishes in the dashboard, `secrets_write_status` reports how it went.
 * Neither takes or returns a secret value: the AI client gets a request ID and a URL,
 * the user types the value into the browser, and the browser seals and signs it as
 * its own enrolled device.
 *
 * Both need `vault-mcp:write`. The request is bound to the MCP grant and client that
 * made it, so another client or grant gets `not_found` for the same ID. The form URL
 * puts the opaque request ID in the fragment, which browsers send to no server; the ID
 * is a lookup key, not authorization (the browser still signs in and proves its device).
 */
import { b64decodeLength, sealOp, type McpScope } from '@ak-vault/protocol';
import type { McpClaims } from '../auth/jwt-verify.js';
import { appResource, type Env } from '../env.js';
import { accountLogTag, clientLogTag, logMcpCall } from '../http/operational-logger.js';
import { relayStub } from '../relay/relay-rpc.js';
import type { ToolDefinition } from './tools.js';

export const PREPARE_WRITE_TOOL = 'secrets_prepare_write';
export const WRITE_STATUS_TOOL = 'secrets_write_status';
export const INTENT_SCOPE: McpScope = 'vault-mcp:write';

const NAME = { type: 'string', minLength: 1, maxLength: 4096, description: 'Secret name.' };
const VAULT_ID = { type: 'string', description: 'Vault ID. Needed when your online devices hold more than one vault, or none is online.' };

export const INTENT_TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  {
    name: PREPARE_WRITE_TOOL,
    title: 'Ask the user to enter a secret value',
    description:
      'Prefer this to secrets_set for any real secret. It takes no value: it returns a form_url that you give to the user, who types the value into their own vault dashboard, where it is encrypted in the browser. The value never passes through you, this conversation or the vault server in plaintext. Pass operation "create" for a new name or "replace" for an existing one. Then poll secrets_write_status with the request_id until it is no longer pending_user or processing. The request expires after expires_at.',
    inputSchema: {
      type: 'object',
      properties: {
        name: NAME,
        operation: { type: 'string', enum: ['create', 'replace'], description: 'create fails if the name exists; replace fails if it does not.' },
        sensitivity: { type: 'string', enum: ['normal', 'high'], description: 'Preselected sensitivity in the form.' },
        vault_id: VAULT_ID,
      },
      required: ['name', 'operation'],
      additionalProperties: false,
    },
    annotations: { title: 'Ask the user to enter a secret value', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: WRITE_STATUS_TOOL,
    title: 'Check a secret write request',
    description: 'Report the status of a secrets_prepare_write request: pending_user, processing, queued, completed, conflict, expired, cancelled or failed. Never returns a secret value or name.',
    inputSchema: {
      type: 'object',
      properties: { request_id: { type: 'string', minLength: 1, maxLength: 64, description: 'request_id from secrets_prepare_write.' } },
      required: ['request_id'],
      additionalProperties: false,
    },
    annotations: { title: 'Check a secret write request', readOnlyHint: true, openWorldHint: false },
  },
];

export function isIntentTool(name: string): boolean {
  return name === PREPARE_WRITE_TOOL || name === WRITE_STATUS_TOOL;
}

interface ToolResult {
  content: { type: 'text'; text: string }[];
  structuredContent: Record<string, unknown>;
  isError: boolean;
}

function result(structured: Record<string, unknown>, isError: boolean): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured, isError };
}

const MESSAGES = {
  invalid_args: 'The arguments do not match the tool input schema.',
  denied: 'This account cannot write to that vault.',
  no_seal_key: 'The vault has no seal key yet. Run `ak secrets sync now` once on an owner device, or start `ak secrets sync now --watch --relay`.',
  too_many_open: 'Too many write requests are waiting for the user. Wait for them to finish or expire.',
  not_found: 'No write request matches.',
  rate_limited: 'Too many calls. Retry after retry_after_s seconds.',
  internal: 'Internal error.',
} as const;
type Code = keyof typeof MESSAGES;

interface Outcome {
  result: ToolResult;
  code: string;
}

function fail(code: Code, extra: Record<string, number> = {}): Outcome {
  return { result: result({ code, message: MESSAGES[code], ...extra }, true), code };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isVaultId(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  try {
    b64decodeLength(v, 16);
    return true;
  } catch {
    return false;
  }
}

/** The dashboard URL for a request: the ID rides in the fragment, so no server or Referer sees it. */
export function formUrl(env: Pick<Env, 'VAULT_AUDIENCE'>, requestId: string): string {
  return `${appResource(env)}/#write=${requestId}`;
}

async function prepare(env: Env, claims: McpClaims, args: Record<string, unknown>): Promise<Outcome> {
  const allowed = ['name', 'operation', 'sensitivity', 'vault_id'];
  if (!Object.keys(args).every((k) => allowed.includes(k))) return fail('invalid_args');
  const { name, operation, sensitivity, vault_id: vault } = args;
  if (typeof name !== 'string' || name.length < 1 || name.length > 4096) return fail('invalid_args');
  if (operation !== 'create' && operation !== 'replace') return fail('invalid_args');
  if (sensitivity !== undefined && sensitivity !== 'normal' && sensitivity !== 'high') return fail('invalid_args');
  if (vault !== undefined && !isVaultId(vault)) return fail('invalid_args');

  const relay = relayStub(env, claims.sub);
  const rate = await relay.takeRate(claims.client_id, null);
  if (!rate.ok) return fail('rate_limited', { retry_after_s: rate.retryAfterS ?? 60 });

  let vaultId = vault;
  if (vaultId === undefined) {
    const known = await relay.knownVaults();
    if (known.length !== 1) return fail('invalid_args');
    vaultId = known[0]!;
  }
  const vaultStub = env.VAULT.get(env.VAULT.idFromName(vaultId));
  const role = await vaultStub.accountRole(claims.sub);
  if (role === null) return fail('invalid_args');
  if (role !== 'owner' && role !== 'editor') return fail('denied');

  // The target name is sealed so the account object keeps only ciphertext for it; only an
  // enrolled device of the vault can open it. A rekey pending or no seal key: no request.
  const doc = await vaultStub.getSealKey();
  if (!doc) return fail('no_seal_key');
  let target;
  try {
    target = sealOp(doc.seal_pub, {
      vaultId,
      keyEpoch: doc.key_epoch,
      origin: { kind: 'mcp', account: claims.sub, client_id: claims.client_id, grant_id: claims.grant_id },
      ts: Date.now(),
      op: { op: 'set', name, value: '', ...(sensitivity === undefined ? {} : { sensitivity }) },
    });
  } catch {
    return fail('invalid_args');
  }
  const prepared = await relay.prepareWriteIntent({
    vaultId,
    grantId: claims.grant_id,
    grantIat: claims.iat,
    clientId: claims.client_id,
    op: operation,
    ...(sensitivity === undefined ? {} : { sensitivity }),
    target,
  });
  if (!prepared.ok) return fail(prepared.code === 'too_many_open' ? 'too_many_open' : 'invalid_args');
  return {
    result: result(
      { request_id: prepared.requestId, form_url: formUrl(env, prepared.requestId), expires_at: new Date(prepared.expiresAt).toISOString(), status: 'pending_user' },
      false,
    ),
    code: 'pending_user',
  };
}

async function status(env: Env, claims: McpClaims, args: Record<string, unknown>): Promise<Outcome> {
  if (Object.keys(args).some((k) => k !== 'request_id') || typeof args['request_id'] !== 'string' || !isVaultId(args['request_id'])) return fail('invalid_args');
  const relay = relayStub(env, claims.sub);
  const rate = await relay.takeRate(claims.client_id, null);
  if (!rate.ok) return fail('rate_limited', { retry_after_s: rate.retryAfterS ?? 60 });
  const s = await relay.writeIntentStatus({ requestId: args['request_id'], grantId: claims.grant_id, clientId: claims.client_id });
  if (!s) return fail('not_found');
  return { result: result({ request_id: args['request_id'], status: s.status, expires_at: new Date(s.expiresAt).toISOString() }, false), code: s.status };
}

/**
 * Run one write-request tool for a token whose scopes cover it. Never throws: an
 * unavailable object is an `internal` tool error. The log line carries the tool, a
 * stable outcome and hashed client and account only.
 */
export async function callIntentTool(env: Env, claims: McpClaims, name: string, rawArgs: unknown): Promise<ToolResult> {
  const started = Date.now();
  let outcome: Outcome;
  try {
    if (!isObject(rawArgs)) outcome = fail('invalid_args');
    else outcome = name === PREPARE_WRITE_TOOL ? await prepare(env, claims, rawArgs) : await status(env, claims, rawArgs);
  } catch {
    outcome = fail('internal');
  }
  logMcpCall({ tool: name, outcome: outcome.code, ms: Date.now() - started, client: clientLogTag(claims.client_id), account: accountLogTag(claims.sub), audited: false });
  return outcome.result;
}
