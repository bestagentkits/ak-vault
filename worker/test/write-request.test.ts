/**
 * Human write requests (spec §3.9): `secrets_prepare_write` hands the AI a link,
 * never a value; the dashboard (a `browser` session) completes the request with a
 * sealed, signed record. The Worker stores neither the name nor the value.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { deriveSealKeyPair, openWriteIntent, randomId, type WriteIntentWire } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS as L } from '../src/limits.js';
import { call, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { callTool, mintMcpToken, publishSealKey, structured } from './helpers/mcp-client.js';
import { sendRevocation } from './helpers/webhook.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const BROWSER: CallOptions = { sessionKind: 'browser' };
const SENTINEL_NAME = 'SENTINEL_SECRET_NAME_7f3a';
const SENTINEL_VALUE = 'sentinel-secret-value-91c2';

interface Setup {
  fx: VaultFixture;
  token: string;
  clientId: string;
  grantId: string;
}

async function setup(kind: 'personal' | 'shared' = 'personal'): Promise<Setup> {
  const fx = await VaultFixture.create(kind);
  await publishSealKey(fx);
  const clientId = `client-${randomId()}`;
  const grantId = `grant-${randomId()}`;
  const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write', clientId, grantId });
  return { fx, token, clientId, grantId };
}

async function prepare(s: Setup, args: Record<string, unknown> = {}, token = s.token) {
  const res = await callTool(token, 'secrets_prepare_write', { name: SENTINEL_NAME, vault_id: s.fx.vaultId, ...args });
  return { res, body: structured(res) };
}

const requestPath = (fx: VaultFixture, id: string, sub = '') => `/v1/vaults/${fx.vaultId}/write-requests/${id}${sub}`;

function openIntent(fx: VaultFixture, wire: WriteIntentWire) {
  return openWriteIntent(deriveSealKeyPair(fx.vk.get(wire.key_epoch)!, fx.vaultId, wire.key_epoch).secretKey, wire, { vaultId: fx.vaultId });
}

async function fetchIntent(fx: VaultFixture, id: string, device: TestDevice = fx.owner, opts: CallOptions = BROWSER) {
  return call(device, 'GET', requestPath(fx, id), undefined, opts);
}

/** The dashboard's PUT: a record for `itemId` completing request `id`. */
function complete(fx: VaultFixture, id: string, itemId: string, base: number, device: TestDevice = fx.owner, opts: CallOptions = BROWSER) {
  const record = fx.record(device, itemId, base, { name: SENTINEL_NAME, value: SENTINEL_VALUE });
  return call(device, 'PUT', `/v1/vaults/${fx.vaultId}/items/${itemId}?write_request=${id}`, record, opts);
}

async function status(s: Setup, id: string, token = s.token) {
  return structured(await callTool(token, 'secrets_write_status', { request_id: id, vault_id: s.fx.vaultId }));
}

describe('secrets_prepare_write', () => {
  it('returns a human link and stores no name or value', async () => {
    const s = await setup();
    const { res, body } = await prepare(s, { purpose: 'deploy key', operation: 'create' });
    expect(res.json.result.isError).toBe(false);
    expect(body.status).toBe('pending_user');
    expect(body.form_url).toBe(`${env.VAULT_AUDIENCE}/app#write=${body.request_id}&vault=${s.fx.vaultId}`);
    expect(body.expires_at - Date.now()).toBeLessThanOrEqual(L.write_request_ttl_s * 1000);
    expect(JSON.stringify(body)).not.toContain(SENTINEL_NAME);

    // The enrolled device opens the intent; the stored row holds ciphertext only.
    const got = await fetchIntent(s.fx, body.request_id);
    expect(got.status).toBe(200);
    expect(openIntent(s.fx, got.json.intent).target).toEqual({ name: SENTINEL_NAME, purpose: 'deploy key' });
    const dump = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(s.fx.vaultId)), (_i: unknown, state: DurableObjectState) => JSON.stringify(state.storage.sql.exec('SELECT * FROM write_requests').toArray()));
    expect(dump).not.toContain(SENTINEL_NAME);
    expect(dump).not.toContain('deploy key');
  });

  it('refuses a value argument and unknown keys without echoing them', async () => {
    const s = await setup();
    const { res, body } = await prepare(s, { value: SENTINEL_VALUE });
    expect(res.json.result.isError).toBe(true);
    expect(body.code).toBe('invalid_args');
    expect(res.text).not.toContain(SENTINEL_VALUE);
    expect((await prepare(s, { operation: 'delete' })).body.code).toBe('invalid_args');
    expect((await prepare(s, { ttl_s: L.write_request_ttl_s + 1 })).body.code).toBe('invalid_args');
  });

  it('needs the write scope', async () => {
    const s = await setup();
    const readOnly = await mintMcpToken({ sub: s.fx.owner.account, scope: 'vault-mcp:read' });
    const res = await callTool(readOnly, 'secrets_prepare_write', { name: 'A', vault_id: s.fx.vaultId });
    expect(JSON.stringify(res.json)).not.toContain('pending_user');
  });

  it('refuses without a seal key, for a reader and for another account', async () => {
    const fx = await VaultFixture.create('shared');
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:write' });
    expect(structured(await callTool(token, 'secrets_prepare_write', { name: 'A', vault_id: fx.vaultId })).code).toBe('no_seal_key');

    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    await publishSealKey(fx);
    const readerToken = await mintMcpToken({ sub: reader.account, scope: 'vault-mcp:write' });
    expect(structured(await callTool(readerToken, 'secrets_prepare_write', { name: 'A', vault_id: fx.vaultId })).code).toBe('invalid_args');
    const stranger = await mintMcpToken({ sub: `acct-${randomId()}`, scope: 'vault-mcp:write' });
    expect(structured(await callTool(stranger, 'secrets_prepare_write', { name: 'A', vault_id: fx.vaultId })).code).toBe('invalid_args');
  });

  it('refuses while a rekey is pending', async () => {
    const s = await setup();
    expect((await s.fx.rekey()).status).toBe(201);
    // The published seal key names the previous epoch, so nothing is sealed or stored.
    expect((await prepare(s)).body.code).toBe('no_seal_key');
  });

  it('rate-limits per client and caps open requests per account', async () => {
    const s = await setup();
    for (let i = 0; i < L.mcp_prepare_write_per_minute_per_client; i++) expect((await prepare(s, { name: `N${i}` })).body.status).toBe('pending_user');
    const limited = await prepare(s, { name: 'overflow' });
    expect(limited.body.code).toBe('rate_limited');
    expect(limited.body.retry_after_s).toBeGreaterThan(0);
    // Another client of the same account is not throttled by this one's budget.
    const other = await mintMcpToken({ sub: s.fx.owner.account, scope: 'vault-mcp:write', clientId: 'second-client', grantId: 'second-grant' });
    expect((await prepare(s, { name: 'fits' }, other)).body.status).toBe('pending_user');
  });
});

describe('secrets_write_status', () => {
  it('reports only to the requesting account, client and grant', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
    const otherClient = await mintMcpToken({ sub: s.fx.owner.account, scope: 'vault-mcp:write', clientId: 'other-client', grantId: s.grantId });
    expect((await status(s, body.request_id, otherClient)).code).toBe('not_found');
    const otherGrant = await mintMcpToken({ sub: s.fx.owner.account, scope: 'vault-mcp:write', clientId: s.clientId, grantId: 'other-grant' });
    expect((await status(s, body.request_id, otherGrant)).code).toBe('not_found');
    const stranger = await mintMcpToken({ sub: `acct-${randomId()}`, scope: 'vault-mcp:write', clientId: s.clientId, grantId: s.grantId });
    expect((await status(s, body.request_id, stranger)).code).toBe('not_found');
    expect((await status(s, randomId())).code).toBe('not_found');
  });

  it('expires a request and clears its ciphertext', async () => {
    const s = await setup();
    const { body } = await prepare(s, { ttl_s: L.write_request_min_ttl_s });
    await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(s.fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
      state.storage.sql.exec('UPDATE write_requests SET expires_at = ?', Date.now() - 1);
    });
    expect(await status(s, body.request_id)).toMatchObject({ state: 'expired' });
    expect((await fetchIntent(s.fx, body.request_id)).status).toBe(400);
    const intent = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(s.fx.vaultId)), (_i: unknown, state: DurableObjectState) => state.storage.sql.exec('SELECT intent FROM write_requests').one().intent);
    expect(intent).toBeNull();
  });
});

describe('completing a write request from the dashboard', () => {
  it('completes once: the PUT and the consumption are one step; a replay fails', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const itemId = randomId();
    const done = await complete(s.fx, body.request_id, itemId, 0);
    expect(done.status).toBe(200);
    expect(done.json.write_request.state).toBe('completed');
    const final = await status(s, body.request_id);
    expect(final).toMatchObject({ state: 'completed', receipt: done.json.write_request.receipt });
    expect(JSON.stringify(final)).not.toContain(SENTINEL_VALUE);

    expect((await complete(s.fx, body.request_id, randomId(), 0)).status).toBe(400);
    expect((await fetchIntent(s.fx, body.request_id)).status).toBe(400);
  });

  it('is bound to the account: a device of another account cannot read or complete it', async () => {
    const s = await setup('shared');
    const other = await s.fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const { body } = await prepare(s);
    expect((await fetchIntent(s.fx, body.request_id, other)).status).toBe(404);
    expect((await complete(s.fx, body.request_id, randomId(), 0, other)).status).toBe(404);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
  });

  it('is bound to the vault', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const another = await VaultFixture.create('personal', s.fx.owner.account);
    expect((await fetchIntent(another, body.request_id)).status).toBe(404);
  });

  it('refuses every non-browser session', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    expect((await fetchIntent(s.fx, body.request_id, s.fx.owner, {})).status).toBe(403);
    expect((await complete(s.fx, body.request_id, randomId(), 0, s.fx.owner, {})).status).toBe(403);
    expect((await call(s.fx.owner, 'POST', requestPath(s.fx, body.request_id, '/close'), { outcome: 'cancelled', reason: 'user_cancelled' }, {})).status).toBe(403);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
  });

  it('matches the operation to the item: create needs a new item, replace an existing one', async () => {
    const s = await setup();
    const existing = randomId();
    expect((await s.fx.write(s.fx.owner, existing, 0, { name: 'EXISTING', value: '1' })).status).toBe(200);

    const create = (await prepare(s, { operation: 'create' })).body;
    expect((await complete(s.fx, create.request_id, existing, 1)).status).toBe(400);
    const replace = (await prepare(s, { operation: 'replace', name: 'EXISTING' })).body;
    expect((await complete(s.fx, replace.request_id, randomId(), 0)).status).toBe(400);
    // The mismatches left both requests open; the right target completes the replace.
    expect((await complete(s.fx, replace.request_id, existing, 1)).status).toBe(200);
    expect(await status(s, replace.request_id)).toMatchObject({ state: 'completed' });
  });

  it('closes as conflict on a stale base revision and keeps the preserved branch', async () => {
    const s = await setup();
    const existing = randomId();
    expect((await s.fx.write(s.fx.owner, existing, 0, { name: 'X', value: '1' })).status).toBe(200);
    const { body } = await prepare(s, { operation: 'replace', name: 'X' });
    expect((await s.fx.write(s.fx.owner, existing, 1, { name: 'X', value: '2' })).status).toBe(200);
    const stale = await complete(s.fx, body.request_id, existing, 1);
    expect(stale.status).toBe(409);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'conflict', reason: 'revision_conflict' });
  });

  it('closes as conflict when the base predates a later delete', async () => {
    const s = await setup();
    const existing = randomId();
    expect((await s.fx.write(s.fx.owner, existing, 0, { name: 'T', value: '1' })).status).toBe(200);
    const { body } = await prepare(s, { operation: 'replace', name: 'T' });
    expect((await s.fx.write(s.fx.owner, existing, 1, null)).status).toBe(200);
    expect((await s.fx.write(s.fx.owner, existing, 2, { name: 'T', value: '3' })).status).toBe(200);
    const stale = await complete(s.fx, body.request_id, existing, 1);
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe('tombstoned');
    expect(await status(s, body.request_id)).toMatchObject({ state: 'conflict', reason: 'revision_conflict' });
  });

  it('does not replay one request\'s completion for another under the same idempotency key', async () => {
    const s = await setup();
    const first = (await prepare(s, { name: 'I1' })).body;
    const second = (await prepare(s, { name: 'I2' })).body;
    const itemId = randomId();
    const record = s.fx.record(s.fx.owner, itemId, 0, { name: 'I1', value: SENTINEL_VALUE });
    const put = (id: string) => call(s.fx.owner, 'PUT', `/v1/vaults/${s.fx.vaultId}/items/${itemId}?write_request=${id}`, record, { ...BROWSER, idempotencyKey: 'same-key-1' });
    expect((await put(first.request_id)).status).toBe(200);
    const mismatch = await put(second.request_id);
    expect(mismatch.status).toBe(422);
    expect(mismatch.json.error.code).toBe('idempotency_mismatch');
    expect(await status(s, second.request_id)).toMatchObject({ state: 'pending_user' });
  });

  it('cancels from the dashboard with a closed reason set', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const bad = await call(s.fx.owner, 'POST', requestPath(s.fx, body.request_id, '/close'), { outcome: 'cancelled', reason: SENTINEL_NAME }, BROWSER);
    expect(bad.status).toBe(400);
    expect(bad.json.error.message ?? '').not.toContain(SENTINEL_NAME);
    const ok = await call(s.fx.owner, 'POST', requestPath(s.fx, body.request_id, '/close'), { outcome: 'cancelled', reason: 'user_cancelled' }, BROWSER);
    expect(ok.status).toBe(200);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'cancelled', reason: 'user_cancelled' });
    expect((await complete(s.fx, body.request_id, randomId(), 0)).status).toBe(400);

    const failed = (await prepare(s)).body;
    expect((await call(s.fx.owner, 'POST', requestPath(s.fx, failed.request_id, '/close'), { outcome: 'failed', reason: 'already_exists' }, BROWSER)).status).toBe(200);
    expect(await status(s, failed.request_id)).toMatchObject({ state: 'failed', reason: 'already_exists' });
  });

  it('fails closed once the requesting grant is revoked', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    expect((await sendRevocation({ revoke_sids: [s.grantId] })).status).toBe(200);
    expect((await fetchIntent(s.fx, body.request_id)).status).toBe(400);
    expect((await complete(s.fx, body.request_id, randomId(), 0)).status).toBe(400);
    // The revoked token can no longer poll, and the row records why it closed.
    const reason = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(s.fx.vaultId)), (_i: unknown, state: DurableObjectState) => state.storage.sql.exec('SELECT state, reason FROM write_requests').one());
    expect(reason).toEqual({ state: 'cancelled', reason: 'grant_revoked' });
  });

  it('rejects a malformed or foreign write_request parameter', async () => {
    const s = await setup();
    const itemId = randomId();
    const record = s.fx.record(s.fx.owner, itemId, 0, { name: 'A', value: '1' });
    const path = `/v1/vaults/${s.fx.vaultId}/items/${itemId}`;
    expect((await call(s.fx.owner, 'PUT', `${path}?write_request=not-an-id`, record, BROWSER)).status).toBe(400);
    expect((await call(s.fx.owner, 'PUT', `${path}?write_request=${randomId()}`, record, BROWSER)).status).toBe(404);
    // Nothing was written by the refused attempts.
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(404);
  });

  it('writes no plaintext name or value to the logs', async () => {
    const s = await setup();
    const lines: string[] = [];
    const original = console.log;
    console.log = (...a: unknown[]) => void lines.push(a.map(String).join(' '));
    try {
      const { body } = await prepare(s);
      await complete(s.fx, body.request_id, randomId(), 0);
      await status(s, body.request_id);
    } finally {
      console.log = original;
    }
    const logged = lines.join('\n');
    expect(logged).not.toContain(SENTINEL_NAME);
    expect(logged).not.toContain(SENTINEL_VALUE);
  });
});
