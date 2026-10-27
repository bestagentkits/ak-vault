/**
 * Remote-access checks for `staging-smoke.ts --remote-access`: the public discovery
 * surface (healthz flag, `/mcp` challenge, protected-resource and authorization-server
 * metadata) and audience refusals. Nothing here needs a signed-in device, so the
 * public part also runs without AK_STAGING_SESSION_TOKEN_PATH. Output is step names,
 * HTTP statuses and fixed strings only: never a token, a proof or a response body.
 */
import { readFileSync } from 'node:fs';
import { assertOutsideRepo, fail } from './staging-smoke-ak-web-token.js';

export const REMOTE_AUDIENCE = 'https://vault-staging.agentkit.best';
const MCP_RESOURCE = `${REMOTE_AUDIENCE}/mcp`;
const PRM_PATH = '/.well-known/oauth-protected-resource/mcp';
const MCP_PROTOCOL = '2026-07-28';

/** Steps that were not checked. Printed as `pending`; never counted as passed. */
const pending: string[] = [];

/**
 * The target cannot run these checks yet: an environment state, never a test failure.
 * Thrown rather than `process.exit`ed, because exiting while undici sockets are open
 * trips a libuv assertion on Windows (Node 24); the caller sets the exit code instead.
 */
export class BlockedError extends Error {
  readonly exitCode = 3;
}

export function blocked(message: string): never {
  throw new BlockedError(message);
}

export function markPending(step: string, why: string): void {
  pending.push(step);
  process.stdout.write(`pending ${step}: ${why}\n`);
}

export function pendingCount(): number {
  return pending.length;
}

export interface PlainResult {
  status: number;
  headers: Headers;
  text: string;
}

/** A request with no vault proof: the remote-access routes take a bearer token only. */
export async function plainRequest(method: string, url: string, headers: Record<string, string> = {}, body?: unknown): Promise<PlainResult> {
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail(`${method} ${new URL(url).pathname} network error`);
  }
  return { status: res.status, headers: res.headers, text: await res.text() };
}

/** Step 1: the target must report remote access on. Exit 3 otherwise. */
export function requireRemoteAccessFlag(health: { json: Record<string, unknown> | null }): void {
  if (health.json?.['remote_access'] !== true) {
    blocked('the target does not report remote_access=true: the remote-access deploy is not live on this target');
  }
  process.stdout.write('ok   healthz remote_access=true\n');
}

/**
 * Step 2 (challenge, both metadata documents) and the no-token part of step 3. `syncToken`
 * is null when no signed-in device session is available; the sync-token refusal is then pending.
 */
export async function checkDiscoveryAndAudience(base: string, issuer: string, akWebOrigin: string, syncToken: string | null): Promise<void> {
  const challenge = await plainRequest('POST', `${base}/mcp`, {}, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  if (challenge.status !== 401) fail(`POST /mcp without a token: expected 401, got ${challenge.status}`);
  const expected = `Bearer resource_metadata="${REMOTE_AUDIENCE}${PRM_PATH}", scope="vault-mcp:read"`;
  if (challenge.headers.get('www-authenticate') !== expected) fail('POST /mcp challenge is not the expected Bearer challenge');
  process.stdout.write('ok   mcp challenge (401, resource_metadata, scope)\n');

  const prm = await plainRequest('GET', `${base}${PRM_PATH}`);
  if (prm.status !== 200) fail(`protected-resource metadata: expected 200, got ${prm.status}`);
  const doc = JSON.parse(prm.text) as { resource?: unknown; authorization_servers?: unknown };
  if (doc.resource !== MCP_RESOURCE) fail('protected-resource metadata names a different resource than <audience>/mcp');
  if (JSON.stringify(doc.authorization_servers) !== JSON.stringify([issuer])) fail('protected-resource metadata does not name the vault issuer');
  // The origin-level path would describe the origin, not /mcp (RFC 9728 section 3.1), so it is not served.
  const rootPrm = await plainRequest('GET', `${base}/.well-known/oauth-protected-resource`);
  if (rootPrm.status !== 404) fail(`origin-level protected-resource path: expected 404, got ${rootPrm.status}`);
  process.stdout.write('ok   protected-resource metadata (path-suffixed; origin-level path 404)\n');

  const as = await plainRequest('GET', `${akWebOrigin}/.well-known/oauth-authorization-server`);
  if (as.status !== 200) {
    markPending('authorization-server metadata', `ak-web answers ${as.status} (env blocker: OAuth signing configuration)`);
  } else {
    const d = JSON.parse(as.text) as Record<string, unknown>;
    const methods = d['code_challenge_methods_supported'];
    if (d['issuer'] !== issuer) fail('authorization-server issuer does not match the vault issuer');
    if (!Array.isArray(methods) || methods.length !== 1 || methods[0] !== 'S256') fail('authorization server does not advertise PKCE S256 only');
    if (d['client_id_metadata_document_supported'] !== true) fail('authorization server does not advertise CIMD');
    if (d['authorization_response_iss_parameter_supported'] !== true) fail('authorization server does not advertise the RFC 9207 iss parameter');
    process.stdout.write('ok   authorization-server metadata (S256, CIMD, iss)\n');
  }

  if (syncToken === null) {
    markPending('audience: sync token refused on /mcp', 'needs AK_STAGING_SESSION_TOKEN_PATH (a signed-in device session)');
    return;
  }
  const syncOnMcp = await plainRequest('POST', `${base}/mcp`, { Authorization: `Bearer ${syncToken}` }, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  if (syncOnMcp.status !== 401) fail(`sync token on /mcp: expected 401, got ${syncOnMcp.status}`);
  process.stdout.write('ok   audience: sync token refused on /mcp (401)\n');
}

/** Step 3 with an MCP token from a consented client (optional file). Needs a vault path. */
export async function checkMcpTokenAudience(base: string, vaultPath: string): Promise<void> {
  const path = process.env['AK_STAGING_MCP_TOKEN_PATH'];
  if (!path) {
    markPending('audience: MCP token on the sync API and app token refusals', 'AK_STAGING_MCP_TOKEN_PATH is unset');
    return;
  }
  assertOutsideRepo(path, 'AK_STAGING_MCP_TOKEN_PATH');
  const mcpToken = readFileSync(path, 'utf8').trim();
  const onSync = await plainRequest('GET', `${base}${vaultPath}/changes`, { Authorization: `Bearer ${mcpToken}` });
  if (onSync.status !== 401) fail(`MCP token on the sync API: expected 401, got ${onSync.status}`);
  const onMcp = await plainRequest('POST', `${base}/mcp`, { Authorization: `Bearer ${mcpToken}`, 'MCP-Protocol-Version': MCP_PROTOCOL }, { jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} });
  if (onMcp.status !== 200) fail(`MCP token on /mcp: expected 200, got ${onMcp.status}`);
  process.stdout.write('ok   audience: MCP token refused on the sync API (401), accepted on /mcp (200)\n');
}

/** Public-only run (no signed-in session): steps 1 and 2 and the no-token audience checks. */
export async function runPublicRemoteAccessChecks(base: string, akWebOrigin: string): Promise<void> {
  const health = await plainRequest('GET', `${base}/healthz`);
  if (health.status !== 200) fail(`healthz: expected 200, got ${health.status}`);
  requireRemoteAccessFlag({ json: JSON.parse(health.text) as Record<string, unknown> });
  const meta = await plainRequest('GET', `${base}/v1/meta`);
  if (meta.status !== 200) fail(`meta: expected 200, got ${meta.status}`);
  const issuer = String((JSON.parse(meta.text) as { auth?: { issuer?: unknown } }).auth?.issuer);
  await checkDiscoveryAndAudience(base, issuer, akWebOrigin, null);
  markPending('signed-in dashboard, MCP tools and sealed-write steps', 'needs AK_STAGING_SESSION_TOKEN_PATH; see the e2e suites');
  markPending('step 9, revoked MCP client refused', 'needs a connected-apps revoke in ak-web (a human action)');
  markPending('step 11, live leak scan', 'the e2e suite runs the wrangler tail leak scan (e2e/remote-access/leak-scan.ts)');
  process.stdout.write(`public remote-access checks passed; ${pendingCount()} step(s) pending and not checked\n`);
}
