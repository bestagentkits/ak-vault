/**
 * The MCP tools (spec §9.8): one per MCP relay tool (§9.7), same arguments plus an
 * optional `vault_id`, same scopes, and the Worker-local write-request tools. The
 * input relay tools (`request_input`, `input_deliver`) are never MCP tools: the Worker
 * calls them itself. No tool returns a secret value: reads return names and profile
 * metadata, writes return a status, and `run` returns output the device redacted.
 */
import { MCP_RELAY_TOOLS, SEARCH_FIELDS, TOOL_SCOPE, b64decodeLength, parseToolArgs, type JsonObject, type McpRelayTool, type McpScope } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../limits.js';

export interface ToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint: boolean;
}

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: ToolAnnotations;
}

const MCP_TOOL_PREFIX = 'secrets_';

const NEVER_VALUES = 'Secret values are never returned.';

const vaultId = {
  type: 'string',
  description: 'Vault ID. Needed when your online devices hold more than one vault, and for a write while no device is online.',
};
const itemName = { type: 'string', minLength: 1, maxLength: 4096, description: 'Secret name.' };

function schema(properties: Record<string, unknown>, required: string[] = []): Record<string, unknown> {
  return { type: 'object', properties: { ...properties, vault_id: vaultId }, required, additionalProperties: false };
}

const DEFINITIONS: Record<McpRelayTool, Omit<ToolDefinition, 'name'>> = {
  search: {
    title: 'Search secrets',
    description: `Find secrets by name and profile metadata (description, provider, account, environment, projects, tags). Needs one of your devices online with \`ak secrets sync now --watch --relay\`. ${NEVER_VALUES}`,
    inputSchema: schema(
      {
        query: { type: 'string', minLength: 1, maxLength: 200, description: 'Text to look for.' },
        fields: { type: 'array', items: { type: 'string', enum: [...SEARCH_FIELDS] }, minItems: 1, maxItems: SEARCH_FIELDS.length, uniqueItems: true, description: 'Fields to search; all when omitted.' },
        limit: { type: 'integer', minimum: 1, maximum: 50 },
      },
      ['query'],
    ),
    annotations: { title: 'Search secrets', readOnlyHint: true, openWorldHint: false },
  },
  list: {
    title: 'List secrets',
    description: `List secret names with their profile metadata, page by page. Needs one of your devices online. ${NEVER_VALUES}`,
    inputSchema: schema({
      cursor: { type: 'string', minLength: 1, maxLength: 256, description: 'next_cursor of the previous page.' },
      limit: { type: 'integer', minimum: 1, maximum: 100 },
    }),
    annotations: { title: 'List secrets', readOnlyHint: true, openWorldHint: false },
  },
  describe: {
    title: 'Describe a secret',
    description: `Show one secret's profile metadata, sensitivity and timestamps. Needs one of your devices online. ${NEVER_VALUES}`,
    inputSchema: schema({ name: itemName }, ['name']),
    annotations: { title: 'Describe a secret', readOnlyHint: true, openWorldHint: false },
  },
  set: {
    title: 'Set a secret',
    description:
      'Create or replace a secret value (write-only: the value is never shown again). An online device writes it at once; with no device online it is sealed to your vault and queued until a device drains it (status "queued"). The value passes through the vault server in memory only and is never stored or logged in plaintext.',
    inputSchema: schema(
      {
        name: itemName,
        value: { type: 'string', maxLength: 65536, description: 'The secret value.' },
        sensitivity: { type: 'string', enum: ['normal', 'high'] },
      },
      ['name', 'value'],
    ),
    annotations: { title: 'Set a secret', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  delete: {
    title: 'Delete a secret',
    description: 'Delete a secret. An online device deletes it at once; with no device online the delete is sealed and queued until a device drains it (status "queued").',
    inputSchema: schema({ name: itemName }, ['name']),
    annotations: { title: 'Delete a secret', readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  },
  request: {
    title: 'Request access to a secret',
    description: `Ask for access to a secret for a stated purpose. A pending request must be approved on one of your devices with \`ak secrets approve\`. ${NEVER_VALUES}`,
    inputSchema: schema(
      {
        name: itemName,
        purpose: { type: 'string', minLength: 1, maxLength: 200, description: 'Why the access is needed.' },
        project: { type: 'string', minLength: 1, maxLength: 128 },
        ttl_s: { type: 'integer', minimum: 1, maximum: 86400 },
      },
      ['name', 'purpose'],
    ),
    annotations: { title: 'Request access to a secret', readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  },
  run: {
    title: 'Run a command with secrets',
    description: `Run a command on one of your online devices with secrets in its environment. The device runs only commands you pinned with an \`exec\` grant on that device, and answers pending_approval otherwise. Output comes back with every released value redacted; a command that prints a value transformed (encoded, split) is not caught. ${NEVER_VALUES}`,
    inputSchema: schema(
      {
        argv: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 64, description: 'Command and arguments.' },
        env: {
          type: 'array',
          minItems: 1,
          maxItems: 16,
          items: {
            type: 'object',
            properties: {
              var: { type: 'string', pattern: '^[A-Z_][A-Z0-9_]*$', maxLength: 128, description: 'Environment variable name.' },
              name: itemName,
            },
            required: ['var', 'name'],
            additionalProperties: false,
          },
          description: 'Secrets to place in the environment.',
        },
        cwd_project: { type: 'string', minLength: 1, maxLength: 128 },
        timeout_s: { type: 'integer', minimum: 1, maximum: 110 },
      },
      ['argv', 'env'],
    ),
    annotations: { title: 'Run a command with secrets', readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
};

/**
 * Tools the Worker answers itself: a human write request (spec §3.10) and a
 * device-sealed input request (spec §3.11). None takes a secret value: the person
 * types it into a form in their browser.
 */
export const LOCAL_TOOLS = ['prepare_write', 'request_input', 'write_status'] as const;
export type LocalTool = (typeof LOCAL_TOOLS)[number];

const LOCAL_SCOPE: Record<LocalTool, McpScope> = { prepare_write: 'vault-mcp:write', request_input: 'vault-mcp:write', write_status: 'vault-mcp:write' };

/** Default and maximum write-request lifetime, in whole minutes, for the tool description. */
const WRITE_TTL_MINUTES = Math.floor(REMOTE_ACCESS_LIMITS.write_request_ttl_s / 60);

const requestId = { type: 'string', minLength: 1, maxLength: 64, description: 'request_id returned by secrets_request_input or secrets_prepare_write.' };

/** Arguments of both write-request tools: a name and its intent, never a value. */
const WRITE_REQUEST_SCHEMA = schema(
  {
    name: itemName,
    operation: { type: 'string', enum: ['create', 'replace'], description: '"create" (default) refuses a name that already exists; "replace" needs one that does.' },
    purpose: { type: 'string', minLength: 1, maxLength: 200, description: 'Why the secret is needed; shown to the user on the form.' },
    sensitivity: { type: 'string', enum: ['normal', 'high'] },
    ttl_s: {
      type: 'integer',
      minimum: REMOTE_ACCESS_LIMITS.write_request_min_ttl_s,
      maximum: REMOTE_ACCESS_LIMITS.write_request_ttl_s,
      description: `How long the link stays valid, in seconds; default ${REMOTE_ACCESS_LIMITS.write_request_ttl_s}.`,
    },
  },
  ['name'],
);

const LOCAL_DEFINITIONS: Record<LocalTool, Omit<ToolDefinition, 'name'>> = {
  prepare_write: {
    title: 'Ask the user to enter a secret',
    description:
      `Create or replace a secret WITHOUT seeing its value: returns a one-time form_url for the user to open in the vault dashboard and type the value there. Prefer secrets_request_input, which also works for users without a browser device. Never ask the user to paste a secret value into this chat and never pass one to any tool. Give the form_url to the user, then poll secrets_write_status with request_id. The link expires (default ${WRITE_TTL_MINUTES} minutes), works once, and only the signed-in vault owner can use it, so a request from an editor account is refused (use secrets_request_input instead). ` +
      NEVER_VALUES,
    inputSchema: WRITE_REQUEST_SCHEMA,
    annotations: { title: 'Ask the user to enter a secret', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  request_input: {
    title: 'Request a secret from the user',
    description:
      `Create or replace a secret WITHOUT seeing its value: returns a one-time form_url for the user to open in their browser, sign in and type the value there. The value is sealed in the browser to one of the user's online devices (flow "device") or completed in the vault dashboard (flow "dashboard"); with neither available the tool fails with device_offline. Never ask the user to paste a secret value into this chat and never pass one to any tool, even when this tool fails. Give the form_url to the user, then poll secrets_write_status with request_id. The link expires (default ${WRITE_TTL_MINUTES} minutes), works once, and only the signed-in account that asked can use it. ` +
      NEVER_VALUES,
    inputSchema: WRITE_REQUEST_SCHEMA,
    annotations: { title: 'Request a secret from the user', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  write_status: {
    title: 'Check a secret write request',
    description: `Status of a request made with secrets_request_input or secrets_prepare_write: pending_user, submitted, completed, conflict, cancelled, expired or failed, with a sanitized reason and, once completed, an opaque receipt. ${NEVER_VALUES}`,
    inputSchema: schema({ request_id: requestId }, ['request_id']),
    annotations: { title: 'Check a secret write request', readOnlyHint: true, openWorldHint: false },
  },
};

/** Tool definitions for `tools/list`, in a fixed order. */
export const TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  ...MCP_RELAY_TOOLS.map((tool) => ({ name: `${MCP_TOOL_PREFIX}${tool}`, ...DEFINITIONS[tool] })),
  ...LOCAL_TOOLS.map((tool) => ({ name: `${MCP_TOOL_PREFIX}${tool}`, ...LOCAL_DEFINITIONS[tool] })),
];

/** The Worker-local tool an MCP tool name maps to, or null. */
export function localToolOf(name: string): LocalTool | null {
  if (!name.startsWith(MCP_TOOL_PREFIX)) return null;
  const tool = name.slice(MCP_TOOL_PREFIX.length);
  return (LOCAL_TOOLS as readonly string[]).includes(tool) ? (tool as LocalTool) : null;
}

export function localScopeOf(tool: LocalTool): McpScope {
  return LOCAL_SCOPE[tool];
}

/** The MCP relay tool an MCP tool name maps to, or null for an unknown name (the input relay tools included). */
export function relayToolOf(name: string): McpRelayTool | null {
  if (!name.startsWith(MCP_TOOL_PREFIX)) return null;
  const tool = name.slice(MCP_TOOL_PREFIX.length);
  return (MCP_RELAY_TOOLS as readonly string[]).includes(tool) ? (tool as McpRelayTool) : null;
}

export function scopeOf(tool: McpRelayTool): McpScope {
  return TOOL_SCOPE[tool];
}

export type SplitArgs = { ok: true; vaultId?: string; args: JsonObject } | { ok: false };

/** Separate the optional `vault_id` from the relay arguments and validate both (spec §9.7, §9.8). */
export function splitArgs(tool: McpRelayTool, value: unknown): SplitArgs {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return { ok: false };
  const { vault_id: vault, ...rest } = value as Record<string, unknown>;
  if (vault !== undefined) {
    if (typeof vault !== 'string') return { ok: false };
    try {
      b64decodeLength(vault, 16);
    } catch {
      return { ok: false };
    }
  }
  try {
    const args = parseToolArgs(tool, rest);
    return vault === undefined ? { ok: true, args } : { ok: true, vaultId: vault, args };
  } catch {
    return { ok: false };
  }
}
