/**
 * Human write requests (spec §3.10): `secrets_prepare_write` hands the AI a link,
 * never a value; the dashboard (a `browser` session) completes the request with a
 * sealed, signed record. The Worker stores neither the name nor the value.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { deriveSealKeyPair, openWriteIntent, randomId, type WriteIntentWire } from '@ak-vault/protocol';
import { LIMITS, REMOTE_ACCESS_LIMITS as L } from '../src/limits.js';
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

  it('caps the open requests of one client, so it cannot take every slot of the account', async () => {
    const s = await setup();
    const tokenFor = (n: number) => mintMcpToken({ sub: s.fx.owner.account, scope: 'vault-mcp:write', clientId: `client-${n}-${randomId()}`, grantId: s.grantId });
    for (let i = 0; i < L.write_requests_pending_per_client; i++) expect((await prepare(s, { name: `C${i}` })).body.status).toBe('pending_user');
    expect((await prepare(s, { name: 'one-more' })).body.code).toBe('too_many_requests');
    // Another client of the same account still gets a slot, up to the account's cap.
    let opened = L.write_requests_pending_per_client;
    for (let c = 0; opened < L.write_requests_pending_per_account; c++) {
      const other = await tokenFor(c);
      for (let i = 0; i < L.write_requests_pending_per_client && opened < L.write_requests_pending_per_account; i++, opened++) {
        expect((await prepare(s, { name: `O${c}-${i}` }, other)).body.status).toBe('pending_user');
      }
    }
    expect((await prepare(s, { name: 'over-account' }, await tokenFor(99))).body.code).toBe('too_many_requests');
    // Closing one frees that client's slot only while the account has room.
    const ids = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(s.fx.vaultId)), (_i: unknown, state: DurableObjectState) =>
      state.storage.sql.exec<{ request_id: string }>('SELECT request_id FROM write_requests WHERE client_id = ?', s.clientId).toArray().map((r) => r.request_id),
    );
    expect((await call(s.fx.owner, 'POST', requestPath(s.fx, ids[0]!, '/close'), { outcome: 'cancelled', reason: 'user_cancelled' }, BROWSER)).status).toBe(200);
    expect((await prepare(s, { name: 'after-close' })).body.status).toBe('pending_user');
  });

  it('rate-limits per client and caps open requests per account', async () => {
    const s = await setup();
    for (let i = 0; i < L.mcp_prepare_write_per_minute_per_client; i++) {
      const { body } = await prepare(s, { name: `N${i}` });
      expect(body.status).toBe('pending_user');
      // Cancel each one so the per-client open cap is not what refuses the overflow.
      expect((await call(s.fx.owner, 'POST', requestPath(s.fx, body.request_id, '/close'), { outcome: 'cancelled', reason: 'user_cancelled' }, BROWSER)).status).toBe(200);
    }
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

  it('refuses a deletion record as the completion and leaves the request open', async () => {
    const s = await setup();
    const existing = randomId();
    expect((await s.fx.write(s.fx.owner, existing, 0, { name: 'D', value: '1' })).status).toBe(200);
    const { body } = await prepare(s, { operation: 'replace', name: 'D' });
    const tombstone = s.fx.record(s.fx.owner, existing, 1, null);
    const res = await call(s.fx.owner, 'PUT', `/v1/vaults/${s.fx.vaultId}/items/${existing}?write_request=${body.request_id}`, tombstone, BROWSER);
    expect(res.status).toBe(400);
    const item = await s.fx.get(s.fx.owner, `/items/${existing}`);
    expect(item.json).toMatchObject({ revision: 1, tombstone: false });
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
    // The same request still completes with a value record.
    expect((await complete(s.fx, body.request_id, existing, 1)).status).toBe(200);
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

describe('write request concurrency and single use', () => {
  it('many concurrent completions of one request: exactly one wins', async () => {
    const s = await setup();
    const { body } = await prepare(s, { operation: 'create' });
    const itemIds = Array.from({ length: 6 }, () => randomId());
    const results = await Promise.all(itemIds.map((itemId) => complete(s.fx, body.request_id, itemId, 0)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 400)).toHaveLength(itemIds.length - 1);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'completed' });
    // Only the winner's item was written.
    const written = await Promise.all(itemIds.map(async (itemId) => (await s.fx.get(s.fx.owner, `/items/${itemId}`)).status));
    expect(written.filter((code) => code === 200)).toHaveLength(1);
  });

  it('a completion racing a cancel leaves exactly one outcome', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const itemId = randomId();
    const [done, cancel] = await Promise.all([
      complete(s.fx, body.request_id, itemId, 0),
      call(s.fx.owner, 'POST', requestPath(s.fx, body.request_id, '/close'), { outcome: 'cancelled', reason: 'user_cancelled' }, BROWSER),
    ]);
    expect([done.status, cancel.status].sort()).toEqual([200, 400]);
    const final = await status(s, body.request_id);
    expect(final.state).toBe(done.status === 200 ? 'completed' : 'cancelled');
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(done.status === 200 ? 200 : 404);
  });

  it('two requests for the same item and revision: one record settles one request, the other is a preserved conflict', async () => {
    const s = await setup();
    const itemId = randomId();
    expect((await s.fx.write(s.fx.owner, itemId, 0, { name: 'K', value: 'v1' })).status).toBe(200);
    const first = (await prepare(s, { operation: 'replace', name: 'K' })).body;
    const second = (await prepare(s, { operation: 'replace', name: 'K' })).body;

    // The winning record cannot be replayed to settle the second request too.
    const record = s.fx.record(s.fx.owner, itemId, 1, { name: 'K', value: 'v2' });
    const put = (id: string) => call(s.fx.owner, 'PUT', `/v1/vaults/${s.fx.vaultId}/items/${itemId}?write_request=${id}`, record, BROWSER);
    expect((await put(first.request_id)).status).toBe(200);
    expect((await put(second.request_id)).status).toBe(409);
    expect(await status(s, second.request_id)).toMatchObject({ state: 'pending_user' });

    // A different record at the same base revision loses compare-and-swap and closes the second request.
    const stale = await complete(s.fx, second.request_id, itemId, 1);
    expect(stale.status).toBe(409);
    expect(stale.json.error.code).toBe('conflict');
    expect(await status(s, first.request_id)).toMatchObject({ state: 'completed' });
    expect(await status(s, second.request_id)).toMatchObject({ state: 'conflict', reason: 'revision_conflict' });
    const item = await s.fx.get(s.fx.owner, `/items/${itemId}`);
    expect(item.json.revision).toBe(2);
    expect(item.json.conflicts).toHaveLength(1);
  });

  it('a device proof is single-use', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const first = await fetchIntent(s.fx, body.request_id);
    expect(first.status).toBe(200);
    const replay = await call(s.fx.owner, 'GET', requestPath(s.fx, body.request_id), undefined, { ...BROWSER, token: first.token, proof: first.proof });
    expect(replay.status).toBe(401);
  });
});

describe('write request device and route checks', () => {
  it('refuses a removed device', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const device = await s.fx.addDevice({ account: s.fx.owner.account });
    expect((await fetchIntent(s.fx, body.request_id, device)).status).toBe(200);
    expect((await s.fx.removeDevice(device)).status).toBe(201);
    expect((await fetchIntent(s.fx, body.request_id, device)).status).toBe(403);
    expect((await complete(s.fx, body.request_id, randomId(), 0, device)).status).toBe(403);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
  });

  it("refuses a device of the same account that is not in the request's vault", async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const outsider = s.fx.newDevice({ account: s.fx.owner.account });
    expect((await fetchIntent(s.fx, body.request_id, outsider)).status).toBe(403);
    expect((await complete(s.fx, body.request_id, randomId(), 0, outsider)).status).toBe(403);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
  });

  it('is a 404 while remote access is off, and the item PUT refuses the parameter', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const off: CallOptions = { ...BROWSER, env: { VAULT_REMOTE_ACCESS_ENABLED: 'false' } };
    expect((await fetchIntent(s.fx, body.request_id, s.fx.owner, off)).status).toBe(404);
    expect((await call(s.fx.owner, 'POST', requestPath(s.fx, body.request_id, '/close'), { outcome: 'cancelled', reason: 'user_cancelled' }, off)).status).toBe(404);
    const itemId = randomId();
    expect((await complete(s.fx, body.request_id, itemId, 0, s.fx.owner, off)).status).toBe(400);
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(404);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
  });

  it('spends the per-device request budget of the browser device', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    const did = s.fx.owner.keys.record.device_id;
    await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(s.fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
      const windowMs = LIMITS.rate_window_seconds * 1000;
      const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
      state.storage.sql.exec(
        'INSERT INTO rate_counters (did, window_start, count) VALUES (?, ?, ?) ON CONFLICT (did) DO UPDATE SET window_start = excluded.window_start, count = excluded.count',
        did,
        windowStart,
        LIMITS.rate_requests_per_window - 1,
      );
    });
    expect((await fetchIntent(s.fx, body.request_id)).status).toBe(200);
    const limited = await fetchIntent(s.fx, body.request_id);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('Retry-After'))).toBeGreaterThan(0);
  });

  it('answers 503 and changes nothing when the grant revocation lookup fails', async () => {
    const s = await setup();
    const { body } = await prepare(s);
    // Device revocation answers normally; only the requesting grant's lookup fails.
    const real = env.REVOCATIONS;
    const grantLookupDown = {
      idFromName: (name: string) => real.idFromName(name),
      get: (id: DurableObjectId) => {
        const stub = real.get(id);
        return {
          isRevoked: (q: Parameters<typeof stub.isRevoked>[0]) => stub.isRevoked(q),
          isGrantRevoked: () => Promise.reject(new Error('registry unavailable')),
        };
      },
    } as unknown as typeof env.REVOCATIONS;
    const down: CallOptions = { ...BROWSER, env: { REVOCATIONS: grantLookupDown } };
    const got = await fetchIntent(s.fx, body.request_id, s.fx.owner, down);
    expect(got.status).toBe(503);
    expect(JSON.stringify(got.json)).not.toContain('intent');
    const itemId = randomId();
    expect((await complete(s.fx, body.request_id, itemId, 0, s.fx.owner, down)).status).toBe(503);
    expect((await s.fx.get(s.fx.owner, `/items/${itemId}`)).status).toBe(404);
    expect(await status(s, body.request_id)).toMatchObject({ state: 'pending_user' });
  });
});
