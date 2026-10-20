/**
 * A scripted public MCP client: ak-web dynamic client registration, OAuth with PKCE S256
 * and the RFC 8707 `resource`, the RFC 9207 `iss` check, and JSON-RPC calls to `/mcp`.
 * Tokens and codes stay in memory and are never printed.
 */
import { createServer, type Server } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { expect, type APIRequestContext, type Browser } from '@playwright/test';
import { AK_WEB_ORIGIN, BASE_URL } from './env.js';
import { MCP_SCOPES } from './metadata-schemas.js';

export const MCP_PROTOCOL = '2026-07-28';

export interface McpSession {
  accessToken: string;
  issuer: string;
  clientId: string;
}

export interface JsonRpcReply {
  status: number;
  body: string;
  json: { result?: unknown; error?: { code?: number; message?: string; data?: { code?: string } } } | null;
}

function b64url(bytes: Buffer): string {
  return bytes.toString('base64url');
}

/** Serves one callback on 127.0.0.1 and resolves with the query of the first request to it. */
function listenForCallback(): Promise<{ server: Server; redirectUri: string; query: Promise<URLSearchParams> }> {
  return new Promise((resolve) => {
    let deliver!: (q: URLSearchParams) => void;
    const query = new Promise<URLSearchParams>((r) => (deliver = r));
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      res.writeHead(200, { 'Content-Type': 'text/plain' }).end('done');
      if (url.pathname === '/callback') deliver(url.searchParams);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, redirectUri: `http://127.0.0.1:${port}/callback`, query });
    });
  });
}

/**
 * Registers a client and completes consent for the account whose ak-web session is in
 * `storageState`. The consent button is found by its label; a UI change there is the
 * first thing to check when the suites fail here.
 */
export async function authorizeMcpClient(browser: Browser, request: APIRequestContext, storageState: string): Promise<McpSession> {
  const meta = await (await request.get(`${AK_WEB_ORIGIN}/.well-known/oauth-authorization-server`)).json();
  const callback = await listenForCallback();
  try {
    const reg = await request.post(meta.registration_endpoint, {
      data: {
        client_name: 'ak-vault e2e (phase 11)',
        redirect_uris: [callback.redirectUri],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      },
    });
    expect(reg.status()).toBe(201);
    const clientId = (await reg.json()).client_id as string;

    const verifier = b64url(randomBytes(48));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const state = b64url(randomBytes(16));
    const url = new URL(meta.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback.redirectUri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      resource: `${BASE_URL}/mcp`,
      scope: MCP_SCOPES.join(' '),
    }).toString();

    const context = await browser.newContext({ storageState });
    const page = await context.newPage();
    await page.goto(url.toString());
    await page.getByRole('button', { name: /allow|approve|authorize|continue/i }).first().click({ timeout: 60_000 });
    const params = await callback.query;
    await context.close();

    expect(params.get('state')).toBe(state);
    // RFC 9207: the authorization response names its issuer, which must be the advertised one.
    expect(params.get('iss')).toBe(meta.issuer);
    const code = params.get('code');
    expect(code).toBeTruthy();

    const token = await request.post(meta.token_endpoint, {
      form: { grant_type: 'authorization_code', code: code!, code_verifier: verifier, client_id: clientId, redirect_uri: callback.redirectUri, resource: `${BASE_URL}/mcp` },
    });
    expect(token.status()).toBe(200);
    return { accessToken: (await token.json()).access_token as string, issuer: meta.issuer as string, clientId };
  } finally {
    callback.server.close();
  }
}

/** One stateless JSON-RPC call to `/mcp` with a bearer token. */
export async function rpc(request: APIRequestContext, token: string, id: number, method: string, params: unknown = {}): Promise<JsonRpcReply> {
  const res = await request.post(`${BASE_URL}/mcp`, {
    data: { jsonrpc: '2.0', id, method, params },
    headers: { Authorization: `Bearer ${token}`, 'MCP-Protocol-Version': MCP_PROTOCOL },
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  const body = await res.text();
  let json: JsonRpcReply['json'] = null;
  try {
    json = JSON.parse(body) as JsonRpcReply['json'];
  } catch {
    json = null;
  }
  return { status: res.status(), body, json };
}
