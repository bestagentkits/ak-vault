/**
 * Device-sealed input requests (spec §3.11, ADR 0004): `secrets_request_input` asks an
 * online device for a one-time input key and hands the AI a `/input` link; the signed-in
 * account's `input` session submits the sealed value once; the Worker relays it to the
 * issuing device only, never stores it, and completes the request in the same
 * transaction as that device's item PUT. Off unless VAULT_INPUT_REQUESTS_ENABLED.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { b64encode, generateInputKeyPair, isAkvError, openInput, randomId, sealInput, type InputSealContext, type InputSealWire, type JsonObject, type RelayErrorCode, type RelayTool } from '@ak-vault/protocol';
import worker from '../src/index.js';
import { verifyInputToken } from '../src/auth/jwt-verify.js';
import type { Env } from '../src/env.js';
import { BASE, call, type CallResult, type TestDevice } from './helpers/api-client.js';
import { mintToken, signJwt, TEST_AUDIENCE, TEST_ISSUER } from './helpers/issuer.js';
import { MCP_RESOURCE, answerNext, callTool, mintMcpToken, modern, publishSealKey, structured } from './helpers/mcp-client.js';
import { ALL_TOOLS, readyRelay, upgrade, type RelayConnection } from './helpers/relay-client.js';
import { sendRevocation } from './helpers/webhook.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const ON: Partial<Env> = { VAULT_INPUT_REQUESTS_ENABLED: 'true' };
const INPUT_TOOLS: RelayTool[] = [...ALL_TOOLS, 'request_input', 'input_deliver'];
const INPUT_RESOURCE = `${TEST_AUDIENCE}/input`;
const KID = 'test-issuer-key-1';
const NAME = 'SENTINEL_INPUT_NAME_4b1e';
const VALUE = 'sentinel-input-value-c7d0';

interface InputTokenArgs {
  sub: string;
  sid?: string;
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
}

/** An `input` session token as ak-web will mint it for the signed-in account. */
async function mintInputToken(args: InputTokenArgs): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    iss: TEST_ISSUER,
    aud: INPUT_RESOURCE,
    sub: args.sub,
    sid: args.sid ?? `sid-${randomId()}`,
    session_kind: 'input',
    jti: randomId(),
    iat: now,
    nbf: now,
    exp: now + 300,
    ...args.claims,
  };
  for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
  const header: Record<string, unknown> = { alg: 'ES256', typ: 'JWT', kid: KID, ...args.header };
  for (const [k, v] of Object.entries(header)) if (v === undefined) delete header[k];
  return signJwt(header, claims);
}

interface RouteResponse {
  status: number;
  headers: Headers;
  text: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
}

/** Call an input-request route through the real Worker with `token` (null sends none). */
async function inputRoute(token: string | null, method: string, vaultId: string, requestId: string, body?: unknown, envOverride: Partial<Env> = ON): Promise<RouteResponse> {
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await worker.fetch(new Request(`${BASE}/v1/vaults/${vaultId}/input-requests/${requestId}`, init), { ...env, ...envOverride } as Env);
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: res.status, headers: res.headers, text, json };
}

interface Setup {
  fx: VaultFixture;
  conn: RelayConnection;
  token: string;
  clientId: string;
  grantId: string;
  /** The requesting account's `input` session token. */
  input: string;
}

async function setup(kind: 'personal' | 'shared' = 'personal'): Promise<Setup> {
  const fx = await VaultFixture.create(kind);
  const conn = await readyRelay(fx.owner, [fx.vaultId], INPUT_TOOLS);
  const clientId = `client-${randomId()}`;
  const grantId = `grant-${randomId()}`;
  const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write', clientId, grantId });
  return { fx, conn, token, clientId, grantId, input: await mintInputToken({ sub: fx.owner.account }) };
}

interface Requested {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: any;
  args: JsonObject;
  keys: { secretKey: Uint8Array; publicKey: Uint8Array };
  ctx: InputSealContext;
}

/** `secrets_request_input` answered by the online device with a fresh input key. */
async function request(s: Setup, args: Record<string, unknown> = {}): Promise<Requested> {
  const keys = generateInputKeyPair();
  const pending = callTool(s.token, 'secrets_request_input', { name: NAME, vault_id: s.fx.vaultId, ...args }, { env: ON });
  const frame = await answerNext(s.conn, (c) => ({ ok: true, result: { request_id: (c['args'] as JsonObject)['request_id']!, input_pub: b64encode(keys.publicKey) } }));
  const body = structured(await pending);
  const relayed = frame['args'] as JsonObject;
  const ctx: InputSealContext = {
    request_id: relayed['request_id'] as string,
    vault_id: s.fx.vaultId,
    account: s.fx.owner.account,
    device_id: s.fx.owner.keys.record.device_id,
    name: relayed['name'] as string,
    purpose: (relayed['purpose'] as string | undefined) ?? null,
    operation: relayed['operation'] as 'create' | 'replace',
    expires_at: relayed['expires_at'] as number,
  };
  return { body, args: relayed, keys, ctx };
}

type DeviceReply = { ok: true; result: JsonObject } | { ok: false; code: RelayErrorCode };

function itemPut(device: TestDevice, fx: VaultFixture, itemId: string, requestId: string, base = 0, value = VALUE, opts: Parameters<typeof call>[4] = {}): Promise<CallResult> {
  const record = fx.record(device, itemId, base, { name: NAME, value });
  return call(device, 'PUT', `/v1/vaults/${fx.vaultId}/items/${itemId}?input_request=${requestId}`, record, { env: ON, ...opts });
}

/** What the issuing device does with `input_deliver`: open the seal under its recorded context, write, answer. */
function realDevice(s: Setup, req: Requested, itemId: string, base = 0): (frame: JsonObject) => Promise<DeviceReply> {
  return async (frame) => {
    const args = frame['args'] as JsonObject;
    let value: string;
    try {
      value = openInput(req.keys.secretKey, args['sealed'], req.ctx).value;
    } catch (err) {
      return { ok: false, code: isAkvError(err) && err.code === 'decrypt_failed' ? 'decrypt_failed' : 'invalid_args' };
    }
    const put = await itemPut(s.fx.owner, s.fx, itemId, req.ctx.request_id, base, value);
    if (put.status === 409) return { ok: false, code: 'conflict' };
    if (put.status !== 200) throw new Error(`device PUT failed: ${put.status} ${JSON.stringify(put.json)}`);
    return { ok: true, result: { status: 'stored', receipt: put.json.input_request.receipt } };
  };
}

/** POST the sealed value while the device answers the relayed `input_deliver` with `device`. */
async function submit(s: Setup, req: Requested, sealed: InputSealWire, device: (frame: JsonObject) => Promise<DeviceReply>, token = s.input): Promise<{ res: RouteResponse; frame: JsonObject }> {
  const pending = inputRoute(token, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed });
  const frame = await s.conn.next();
  if (frame['type'] !== 'call') throw new Error(`expected a call frame, got ${String(frame['type'])}`);
  const reply = await device(frame);
  const callId = frame['call_id'] as string;
  if (reply.ok) s.conn.result({ call_id: callId, ok: true, result: reply.result });
  else s.conn.result({ call_id: callId, ok: false, error: { code: reply.code } });
  return { res: await pending, frame };
}

async function status(s: Setup, id: string) {
  return structured(await callTool(s.token, 'secrets_write_status', { request_id: id, vault_id: s.fx.vaultId }, { env: ON }));
}

function vaultRows(fx: VaultFixture): Promise<Record<string, unknown>[]> {
  return runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => state.storage.sql.exec('SELECT * FROM write_requests').toArray() as Record<string, unknown>[]);
}

function setExpiry(fx: VaultFixture, expiresAt: number): Promise<void> {
  return runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
    state.storage.sql.exec('UPDATE write_requests SET expires_at = ?', expiresAt);
  });
}

describe('input session token verification', () => {
  const config = () => ({ VAULT_ISSUER: env.VAULT_ISSUER, VAULT_AUDIENCE: env.VAULT_AUDIENCE, VAULT_JWKS_JSON: env.VAULT_JWKS_JSON });

  it('accepts exactly the input contract (typ JWT or at+jwt)', async () => {
    const sub = `acct-${randomId()}`;
    for (const typ of ['JWT', 'at+jwt']) {
      const claims = await verifyInputToken(await mintInputToken({ sub, sid: 'sid-1', header: { typ } }), config());
      expect(claims).toMatchObject({ sub, sid: 'sid-1' });
    }
  });

  it('refuses every deviation as unauthorized', async () => {
    const sub = `acct-${randomId()}`;
    const now = Math.floor(Date.now() / 1000);
    const refused: [string, Promise<string>][] = [
      ['no typ', mintInputToken({ sub, header: { typ: undefined } })],
      ['typ other', mintInputToken({ sub, header: { typ: 'dpop+jwt' } })],
      ['alg', mintInputToken({ sub, header: { alg: 'ES384' } })],
      ['kid', mintInputToken({ sub, header: { kid: 'unknown-kid' } })],
      ['sync audience', mintInputToken({ sub, claims: { aud: TEST_AUDIENCE } })],
      ['mcp audience', mintInputToken({ sub, claims: { aud: MCP_RESOURCE } })],
      ['app audience', mintInputToken({ sub, claims: { aud: `${TEST_AUDIENCE}/app` } })],
      ['two audiences', mintInputToken({ sub, claims: { aud: [INPUT_RESOURCE, TEST_AUDIENCE] } })],
      ['issuer', mintInputToken({ sub, claims: { iss: 'https://elsewhere.invalid' } })],
      ['did', mintInputToken({ sub, claims: { did: randomId() } })],
      ['scope', mintInputToken({ sub, claims: { scope: 'vault:read' } })],
      ['missing sid', mintInputToken({ sub, claims: { sid: undefined } })],
      ['missing jti', mintInputToken({ sub, claims: { jti: undefined } })],
      ['email_otp kind', mintInputToken({ sub, claims: { session_kind: 'email_otp' } })],
      ['browser kind', mintInputToken({ sub, claims: { session_kind: 'browser' } })],
      ['no kind', mintInputToken({ sub, claims: { session_kind: undefined } })],
      ['lifetime over 600 s', mintInputToken({ sub, claims: { iat: now, nbf: now, exp: now + 601 } })],
      ['exp not after iat', mintInputToken({ sub, claims: { iat: now, nbf: now, exp: now } })],
      ['expired', mintInputToken({ sub, claims: { iat: now - 500, nbf: now - 500, exp: now - 100 } })],
      ['not yet valid', mintInputToken({ sub, claims: { nbf: now + 600, exp: now + 900, iat: now + 300 } })],
    ];
    for (const [what, token] of refused) await expect(verifyInputToken(await token, config()), what).rejects.toMatchObject({ code: 'unauthorized' });
  });
});

describe('input token audience separation', () => {
  it('a sync route, the relay upgrade and /mcp refuse an input token', async () => {
    const fx = await VaultFixture.create();
    const input = await mintInputToken({ sub: fx.owner.account });
    expect((await fx.get(fx.owner, '/changes', { token: input, env: ON })).status).toBe(401);
    expect((await upgrade(fx.owner, { token: input, env: ON })).status).toBe(401);
    expect((await modern(input, 'tools/list', {}, { env: ON })).status).toBe(401);
  });

  it('the input routes refuse sync, browser, MCP and dashboard tokens', async () => {
    const s = await setup();
    const { body } = await request(s);
    const sub = s.fx.owner.account;
    const did = s.fx.owner.keys.record.device_id;
    const refused = [
      await mintToken({ sub, did }),
      await mintToken({ sub, did, claims: { session_kind: 'browser' } }),
      await mintToken({ sub, did, claims: { aud: INPUT_RESOURCE } }),
      await mintMcpToken({ sub }),
      await mintMcpToken({ sub, claims: { aud: INPUT_RESOURCE } }),
      await mintMcpToken({ sub, claims: { aud: `${TEST_AUDIENCE}/app`, scope: 'vault-app:session' } }),
    ];
    for (const [i, token] of refused.entries()) {
      expect((await inputRoute(token, 'GET', s.fx.vaultId, body.request_id)).status, `token ${i}`).toBe(401);
      expect((await inputRoute(token, 'POST', s.fx.vaultId, body.request_id, { sealed: {} })).status, `token ${i}`).toBe(401);
    }
    expect((await inputRoute(null, 'GET', s.fx.vaultId, body.request_id)).status).toBe(401);
    expect((await inputRoute(s.input, 'GET', s.fx.vaultId, body.request_id)).status).toBe(200);
    s.conn.close();
  });
});

describe('VAULT_INPUT_REQUESTS_ENABLED', () => {
  it('off: the routes are 404, ?input_request= is refused, and the tool uses only the dashboard flow', async () => {
    const s = await setup();
    const { body } = await request(s);
    for (const off of [{}, { VAULT_INPUT_REQUESTS_ENABLED: 'false' }, { VAULT_INPUT_REQUESTS_ENABLED: 'TRUE' }, { ...ON, VAULT_REMOTE_ACCESS_ENABLED: 'false' }]) {
      const offEnv = { VAULT_INPUT_REQUESTS_ENABLED: undefined, ...off } as Partial<Env>;
      expect((await inputRoute(s.input, 'GET', s.fx.vaultId, body.request_id, undefined, offEnv)).status).toBe(404);
      expect((await inputRoute(s.input, 'POST', s.fx.vaultId, body.request_id, { sealed: {} }, offEnv)).status).toBe(404);
      const itemId = randomId();
      expect((await itemPut(s.fx.owner, s.fx, itemId, body.request_id, 0, VALUE, { env: offEnv })).status).toBe(400);
    }

    // With the flag off the online device is never asked: the dashboard flow answers.
    const noSeal = structured(await callTool(s.token, 'secrets_request_input', { name: NAME, vault_id: s.fx.vaultId }));
    expect(noSeal.code).toBe('no_seal_key');
    await publishSealKey(s.fx);
    const dashboard = structured(await callTool(s.token, 'secrets_request_input', { name: NAME, vault_id: s.fx.vaultId }));
    expect(dashboard).toMatchObject({ status: 'pending_user', flow: 'dashboard' });
    expect(dashboard.form_url).toBe(`${env.VAULT_AUDIENCE}/app#write=${dashboard.request_id}&vault=${s.fx.vaultId}`);
    s.conn.close();
  });

  it('secrets_prepare_write is unchanged by the flag', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write' });
    const res = structured(await callTool(token, 'secrets_prepare_write', { name: NAME, vault_id: fx.vaultId }, { env: ON }));
    expect(res.status).toBe('pending_user');
    expect(res.flow).toBeUndefined();
  });
});

describe('secrets_request_input, device flow', () => {
  it('asks the online device for a key and returns a /input link; the row holds no name', async () => {
    const s = await setup();
    const req = await request(s, { purpose: 'deploy key', operation: 'create', sensitivity: 'high' });
    expect(req.args).toEqual({ request_id: req.body.request_id, name: NAME, operation: 'create', expires_at: req.body.expires_at, purpose: 'deploy key', sensitivity: 'high' });
    expect(req.body).toMatchObject({ status: 'pending_user', flow: 'device', vault_id: s.fx.vaultId });
    const pub = b64encode(req.keys.publicKey);
    expect(req.body.form_url).toBe(`${env.VAULT_AUDIENCE}/input#r=${req.body.request_id}&v=${s.fx.vaultId}&k=${pub}&n=${encodeURIComponent(NAME)}&p=${encodeURIComponent('deploy key')}`);
    expect(req.body.expires_at - Date.now()).toBeLessThanOrEqual(600_000);
    const rows = await vaultRows(s.fx);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ flow: 'device', state: 'pending_user', device_id: s.fx.owner.keys.record.device_id, input_pub: pub, intent: null });
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(NAME);
    expect(dump).not.toContain('deploy key');
    expect(await status(s, req.body.request_id)).toMatchObject({ state: 'pending_user' });
    s.conn.close();
  });

  it('the form reads the request, the device stores the value, and the request completes with a receipt', async () => {
    const s = await setup();
    const req = await request(s);
    const got = await inputRoute(s.input, 'GET', s.fx.vaultId, req.ctx.request_id);
    expect(got.status).toBe(200);
    expect(got.json).toEqual({ request_id: req.ctx.request_id, state: 'pending_user', operation: 'create', client_id: s.clientId, device_id: s.fx.owner.keys.record.device_id, expires_at: req.ctx.expires_at });

    const itemId = randomId();
    const sealed = sealInput(req.keys.publicKey, req.ctx, { value: VALUE });
    const lines: string[] = [];
    const original = console.log;
    console.log = (...a: unknown[]) => void lines.push(a.map(String).join(' '));
    let res: RouteResponse;
    let frame: JsonObject;
    try {
      ({ res, frame } = await submit(s, req, sealed, realDevice(s, req, itemId)));
    } finally {
      console.log = original;
    }
    expect(frame).toMatchObject({ tool: 'input_deliver', vault_id: s.fx.vaultId, args: { request_id: req.ctx.request_id, sealed }, caller: { client_id: s.clientId, grant_id: s.grantId, scopes: ['vault-mcp:write'] } });
    expect(res.status).toBe(200);
    expect(res.json).toEqual({ status: 'stored', receipt: expect.any(String) });
    expect(await status(s, req.ctx.request_id)).toEqual({ state: 'completed', receipt: res.json.receipt, expires_at: req.ctx.expires_at });
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(200);
    expect((await inputRoute(s.input, 'GET', s.fx.vaultId, req.ctx.request_id)).json.state).toBe('completed');
    // Neither the ciphertext nor the name nor the value reached a log or the stored row.
    const logged = lines.join('\n');
    for (const secret of [NAME, VALUE, sealed.ct]) expect(logged).not.toContain(secret);
    const dump = JSON.stringify(await vaultRows(s.fx));
    for (const secret of [NAME, VALUE, sealed.ct]) expect(dump).not.toContain(secret);
    s.conn.close();
  });

  it('a device refusal of request_input stores nothing', async () => {
    const s = await setup();
    for (const [code, expected] of [['conflict', 'conflict'], ['denied', 'denied'], ['invalid_args', 'invalid_args'], ['internal', 'internal']] as const) {
      const pending = callTool(s.token, 'secrets_request_input', { name: NAME, vault_id: s.fx.vaultId }, { env: ON });
      await answerNext(s.conn, () => ({ ok: false, code }));
      const res = structured(await pending);
      expect(res.code).toBe(expected);
      expect(JSON.stringify(res)).not.toContain(NAME);
    }
    expect(await vaultRows(s.fx)).toHaveLength(0);
    s.conn.close();
  });

  it('refuses a device answer for another request id as internal', async () => {
    const s = await setup();
    const pending = callTool(s.token, 'secrets_request_input', { name: NAME, vault_id: s.fx.vaultId }, { env: ON });
    await answerNext(s.conn, () => ({ ok: true, result: { request_id: randomId(), input_pub: b64encode(generateInputKeyPair().publicKey) } }));
    expect(structured(await pending).code).toBe('internal');
    expect(await vaultRows(s.fx)).toHaveLength(0);
    s.conn.close();
  });

  it('refuses a reader account', async () => {
    const s = await setup('shared');
    const reader = await s.fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const token = await mintMcpToken({ sub: reader.account, scope: 'vault-mcp:write' });
    expect(structured(await callTool(token, 'secrets_request_input', { name: NAME, vault_id: s.fx.vaultId }, { env: ON })).code).toBe('invalid_args');
    s.conn.close();
  });

  it('input tools are never MCP tools', async () => {
    const token = await mintMcpToken({ sub: `acct-${randomId()}` });
    const list = await modern(token, 'tools/list', {}, { env: ON });
    const names = (list.json.result.tools as { name: string }[]).map((t) => t.name);
    expect(names).toContain('secrets_request_input');
    expect(names).not.toContain('secrets_input_deliver');
    for (const tool of ['secrets_input_deliver']) expect((await callTool(token, tool, {}, { env: ON })).json.error.code).toBe(-32602);
  });
});

describe('secrets_request_input without an online device', () => {
  it('falls back to the dashboard flow for an owner with a seal key', async () => {
    const fx = await VaultFixture.create();
    await publishSealKey(fx);
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write' });
    const res = structured(await callTool(token, 'secrets_request_input', { name: NAME, vault_id: fx.vaultId }, { env: ON }));
    expect(res).toMatchObject({ status: 'pending_user', flow: 'dashboard' });
    expect(res.form_url).toBe(`${env.VAULT_AUDIENCE}/app#write=${res.request_id}&vault=${fx.vaultId}`);
  });

  it('fails device_offline without a seal key, and for an editor, never asking for the value', async () => {
    const fx = await VaultFixture.create('shared');
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write' });
    const noSeal = structured(await callTool(token, 'secrets_request_input', { name: NAME, vault_id: fx.vaultId }, { env: ON }));
    expect(noSeal.code).toBe('device_offline');
    await publishSealKey(fx);
    const editor = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const editorToken = await mintMcpToken({ sub: editor.account, scope: 'vault-mcp:write' });
    const res = structured(await callTool(editorToken, 'secrets_request_input', { name: NAME, vault_id: fx.vaultId }, { env: ON }));
    expect(res.code).toBe('device_offline');
    expect(res.message).toContain('Do not ask the user for the value');
  });
});

describe('input request routes', () => {
  it('another account, a dashboard request and an unknown id answer 404 alike', async () => {
    const s = await setup();
    const req = await request(s);
    const stranger = await mintInputToken({ sub: `acct-${randomId()}` });
    for (const method of ['GET', 'POST'] as const) {
      const body = method === 'POST' ? { sealed: sealInput(req.keys.publicKey, req.ctx, { value: VALUE }) } : undefined;
      const res = await inputRoute(stranger, method, s.fx.vaultId, req.ctx.request_id, body);
      expect(res.status, method).toBe(404);
      expect(res.json.error.code).toBe('not_found');
    }
    expect((await inputRoute(s.input, 'GET', s.fx.vaultId, randomId())).status).toBe(404);
    await publishSealKey(s.fx);
    const dashboard = structured(await callTool(s.token, 'secrets_prepare_write', { name: NAME, vault_id: s.fx.vaultId }, { env: ON }));
    expect((await inputRoute(s.input, 'GET', s.fx.vaultId, dashboard.request_id)).status).toBe(404);
    expect((await inputRoute(s.input, 'GET', (await VaultFixture.create()).vaultId, req.ctx.request_id)).status).toBe(404);
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'pending_user' });
    s.conn.close();
  });

  it('refuses a malformed body, another request\'s seal and an unknown seal version without consuming the request', async () => {
    const s = await setup();
    const req = await request(s);
    const sealed = sealInput(req.keys.publicKey, req.ctx, { value: VALUE });
    const cases: [unknown, number, string][] = [
      [{}, 400, 'bad_request'],
      [{ sealed, extra: 1 }, 400, 'bad_request'],
      [{ sealed: { ...sealed, ct: 'not b64!' } }, 400, 'bad_request'],
      [{ sealed: { ...sealed, request_id: randomId() } }, 400, 'bad_request'],
      [{ sealed: { ...sealed, alg: 'x25519-xc20p-other' } }, 400, 'unsupported_version'],
      [{ sealed: { ...sealed, v: 2 } }, 400, 'unsupported_version'],
    ];
    for (const [body, code, error] of cases) {
      const res = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, body);
      expect(res.status, JSON.stringify(body)).toBe(code);
      expect(res.json.error.code).toBe(error);
      expect(res.text).not.toContain(sealed.ct);
    }
    expect((await inputRoute(s.input, 'POST', s.fx.vaultId, 'not-an-id', { sealed })).status).toBe(400);
    expect((await inputRoute(s.input, 'GET', s.fx.vaultId, req.ctx.request_id)).json.state).toBe('pending_user');
    s.conn.close();
  });

  it('is single use: a second POST is refused while the first is in flight and after it completed', async () => {
    const s = await setup();
    const req = await request(s);
    const sealed = sealInput(req.keys.publicKey, req.ctx, { value: VALUE });
    const itemId = randomId();
    const { res } = await submit(s, req, sealed, async (frame) => {
      const second = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed });
      expect(second.status).toBe(409);
      expect(second.json.error).toMatchObject({ code: 'conflict', state: 'submitted' });
      expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'submitted' });
      return realDevice(s, req, itemId)(frame);
    });
    expect(res.status).toBe(200);
    const after = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed });
    expect(after.status).toBe(409);
    expect(after.json.error.state).toBe('completed');
    s.conn.close();
  });

  it('a POST after expires_at is refused as expired and marks the request expired', async () => {
    const s = await setup();
    const req = await request(s);
    await setExpiry(s.fx, Date.now() - 1);
    const res = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed: sealInput(req.keys.publicKey, req.ctx, { value: VALUE }) });
    expect(res.status).toBe(410);
    expect(res.json.error).toMatchObject({ code: 'expired', state: 'expired' });
    expect((await vaultRows(s.fx))[0]).toMatchObject({ state: 'expired' });
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'expired' });
    s.conn.close();
  });

  it('the item PUT after expiry is refused without writing; the device answers expired', async () => {
    const s = await setup();
    const req = await request(s);
    const itemId = randomId();
    const { res } = await submit(s, req, sealInput(req.keys.publicKey, req.ctx, { value: VALUE }), async () => {
      await setExpiry(s.fx, Date.now() - 1);
      const put = await itemPut(s.fx.owner, s.fx, itemId, req.ctx.request_id);
      expect(put.status).toBe(410);
      expect(put.json.error.code).toBe('expired');
      return { ok: false, code: 'expired' };
    });
    expect(res.status).toBe(410);
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(404);
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'expired' });
    s.conn.close();
  });

  it('a POST while the issuing device is offline is refused and the request stays pending_user', async () => {
    const s = await setup();
    const req = await request(s);
    s.conn.close();
    await s.conn.closedWith();
    // Another online device of the account is not the issuing device: it never receives the value.
    const other = await s.fx.addDevice({ account: s.fx.owner.account });
    const otherConn = await readyRelay(other, [s.fx.vaultId], INPUT_TOOLS);
    const res = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed: sealInput(req.keys.publicKey, req.ctx, { value: VALUE }) });
    expect(res.status).toBe(503);
    expect(res.json.error).toMatchObject({ code: 'device_offline', state: 'pending_user' });
    expect(res.headers.get('Retry-After')).toBe('5');
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'pending_user' });
    otherConn.close();
  });

  it('a tampered seal fails decrypt_failed on the device and the request is failed', async () => {
    const s = await setup();
    const req = await request(s);
    // The page showed (and sealed under) another name than the device recorded.
    const tampered = sealInput(req.keys.publicKey, { ...req.ctx, name: 'OTHER_NAME' }, { value: VALUE });
    const itemId = randomId();
    const { res } = await submit(s, req, tampered, realDevice(s, req, itemId));
    expect(res.status).toBe(400);
    expect(res.json.error).toMatchObject({ code: 'bad_request', state: 'failed' });
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'failed', reason: 'decrypt_failed' });
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(404);
    s.conn.close();
  });

  it('maps each device refusal to a closed state and a stable error', async () => {
    const cases: [RelayErrorCode, number, string, string, string | undefined][] = [
      ['not_found', 410, 'expired', 'failed', 'device_lost'],
      ['invalid_args', 400, 'bad_request', 'failed', 'bad_request'],
      ['denied', 403, 'forbidden', 'failed', 'denied'],
      ['conflict', 409, 'conflict', 'conflict', 'revision_conflict'],
      ['internal', 500, 'internal', 'failed', 'internal'],
    ];
    const s = await setup();
    for (const [code, httpStatus, error, state, reason] of cases) {
      const req = await request(s);
      const { res } = await submit(s, req, sealInput(req.keys.publicKey, req.ctx, { value: VALUE }), async () => ({ ok: false, code }));
      expect(res.status, code).toBe(httpStatus);
      expect(res.json.error.code, code).toBe(error);
      expect(await status(s, req.ctx.request_id), code).toEqual({ state, ...(reason ? { reason } : {}), expires_at: req.ctx.expires_at });
    }
    s.conn.close();
  });

  it('refuses a device that claims stored without the item PUT', async () => {
    const s = await setup();
    const req = await request(s);
    const { res } = await submit(s, req, sealInput(req.keys.publicKey, req.ctx, { value: VALUE }), async () => ({ ok: true, result: { status: 'stored', receipt: 'made-up-receipt' } }));
    expect(res.status).toBe(500);
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'failed', reason: 'internal' });
    s.conn.close();
  });

  it('a revoked requesting grant cancels the request; a revoked input session is refused', async () => {
    const s = await setup();
    const req = await request(s);
    const sid = `sid-${randomId()}`;
    const input = await mintInputToken({ sub: s.fx.owner.account, sid });
    expect((await sendRevocation({ revoke_sids: [sid] })).status).toBe(200);
    expect((await inputRoute(input, 'GET', s.fx.vaultId, req.ctx.request_id)).status).toBe(401);

    expect((await sendRevocation({ revoke_sids: [s.grantId] })).status).toBe(200);
    const res = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed: sealInput(req.keys.publicKey, req.ctx, { value: VALUE }) });
    expect(res.status).toBe(409);
    expect(res.json.error.state).toBe('cancelled');
    expect((await vaultRows(s.fx))[0]).toMatchObject({ state: 'cancelled', reason: 'grant_revoked' });
    s.conn.close();
  });

  it('answers 503 and changes nothing when a revocation lookup fails', async () => {
    const s = await setup();
    const req = await request(s);
    const down = { REVOCATIONS: { idFromName: () => ({}), get: () => ({ isGrantRevoked: () => Promise.reject(new Error('registry unavailable')) }) } as unknown as Env['REVOCATIONS'] };
    const res = await inputRoute(s.input, 'POST', s.fx.vaultId, req.ctx.request_id, { sealed: sealInput(req.keys.publicKey, req.ctx, { value: VALUE }) }, { ...ON, ...down });
    expect(res.status).toBe(503);
    expect((await inputRoute(s.input, 'GET', s.fx.vaultId, req.ctx.request_id)).json.state).toBe('pending_user');
    s.conn.close();
  });
});

describe('completing an input request with the item PUT', () => {
  it('is bound to the issuing device, the account and a device session; mismatches write nothing', async () => {
    const s = await setup('shared');
    const req = await request(s);
    const itemId = randomId();
    const sameAccount = await s.fx.addDevice({ account: s.fx.owner.account });
    const otherAccount = await s.fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const { res } = await submit(s, req, sealInput(req.keys.publicKey, req.ctx, { value: VALUE }), async (frame) => {
      expect((await itemPut(sameAccount, s.fx, itemId, req.ctx.request_id)).status).toBe(403);
      expect((await itemPut(otherAccount, s.fx, itemId, req.ctx.request_id)).status).toBe(404);
      expect((await itemPut(s.fx.owner, s.fx, itemId, req.ctx.request_id, 0, VALUE, { sessionKind: 'browser' })).status).toBe(403);
      expect((await itemPut(s.fx.owner, s.fx, itemId, req.ctx.request_id, 0, VALUE, { sessionKind: 'machine' })).status).toBe(403);
      // write_request and input_request together are refused.
      const record = s.fx.record(s.fx.owner, itemId, 0, { name: NAME, value: VALUE });
      expect((await call(s.fx.owner, 'PUT', `/v1/vaults/${s.fx.vaultId}/items/${itemId}?input_request=${req.ctx.request_id}&write_request=${req.ctx.request_id}`, record, { env: ON })).status).toBe(400);
      expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(404);
      expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'submitted' });
      return realDevice(s, req, itemId)(frame);
    });
    expect(res.status).toBe(200);
    s.conn.close();
  });

  it('refuses a PUT before submission, and one whose item does not match the operation', async () => {
    const s = await setup();
    const existing = randomId();
    expect((await s.fx.write(s.fx.owner, existing, 0, { name: NAME, value: '1' })).status).toBe(200);
    const req = await request(s, { operation: 'create' });
    // Not yet submitted: the device cannot complete it on its own.
    expect((await itemPut(s.fx.owner, s.fx, randomId(), req.ctx.request_id)).status).toBe(400);
    const { res } = await submit(s, req, sealInput(req.keys.publicKey, req.ctx, { value: VALUE }), async () => {
      const put = await itemPut(s.fx.owner, s.fx, existing, req.ctx.request_id, 1);
      expect(put.status).toBe(400);
      expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'submitted' });
      return { ok: false, code: 'invalid_args' };
    });
    expect(res.status).toBe(400);
    expect((await s.fx.get(s.fx.owner, `/items/${existing}`)).json.revision).toBe(1);
    s.conn.close();
  });

  it('a replace that loses compare-and-swap closes the request as conflict in the PUT transaction', async () => {
    const s = await setup();
    const existing = randomId();
    expect((await s.fx.write(s.fx.owner, existing, 0, { name: NAME, value: '1' })).status).toBe(200);
    const req = await request(s, { operation: 'replace' });
    expect((await s.fx.write(s.fx.owner, existing, 1, { name: NAME, value: '2' })).status).toBe(200);
    const { res } = await submit(s, req, sealInput(req.keys.publicKey, req.ctx, { value: VALUE }), realDevice(s, req, existing, 1));
    expect(res.status).toBe(409);
    expect(await status(s, req.ctx.request_id)).toMatchObject({ state: 'conflict', reason: 'revision_conflict' });
    s.conn.close();
  });

  it('device rows count against the per-client cap shared with dashboard requests', async () => {
    const s = await setup();
    await publishSealKey(s.fx);
    // One dashboard request, then device requests up to the per-client cap.
    expect(structured(await callTool(s.token, 'secrets_prepare_write', { name: 'D0', vault_id: s.fx.vaultId }, { env: ON })).status).toBe('pending_user');
    for (let i = 1; i < 4; i++) expect((await request(s, { name: `N${i}` })).body.flow).toBe('device');
    // At the cap the device is not even asked.
    const res = structured(await callTool(s.token, 'secrets_request_input', { name: 'over', vault_id: s.fx.vaultId }, { env: ON }));
    expect(res.code).toBe('too_many_requests');
    s.conn.close();
  });
});
