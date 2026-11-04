/**
 * Access approvals (spec §3.13): a device publishes a signed, encrypted request; another
 * human device of the same account answers it with a signed decision; MCP may list and
 * deny only. The Worker never stores a secret name.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { openApprovalRequest, randomId, sealApprovalRequest, signApprovalDecision, verifyApprovalDecision, type ApprovalDecisionKind, type ApprovalRequestWire } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS as L } from '../src/limits.js';
import { call, type CallOptions, type TestDevice } from './helpers/api-client.js';
import { callTool, mintMcpToken, structured } from './helpers/mcp-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const SENTINEL_NAME = 'SENTINEL_APPROVAL_NAME_4d1e';
const BROWSER: CallOptions = { sessionKind: 'browser' };

function seal(fx: VaultFixture, device: TestDevice, opts: { ts?: number; life?: number; epoch?: number } = {}): ApprovalRequestWire {
  const ts = opts.ts ?? Date.now();
  const epoch = opts.epoch ?? fx.keyEpoch;
  return sealApprovalRequest(fx.vk.get(epoch)!, device.keys.signSecret, {
    vaultId: fx.vaultId,
    keyEpoch: epoch,
    requester: device.keys.record.device_id,
    ts,
    expiresAt: ts + (opts.life ?? 600_000),
    subject: { secret: SENTINEL_NAME, agent: 'claude', fingerprint: `sha256:${'a'.repeat(64)}`, purpose: 'publish blog', max_ttl_s: 86400 },
  });
}

const base = (fx: VaultFixture) => `/v1/vaults/${fx.vaultId}/approval-requests`;
const publish = (fx: VaultFixture, device: TestDevice, wire: unknown) => call(device, 'POST', base(fx), { request: wire });

function decide(fx: VaultFixture, approver: TestDevice, wire: ApprovalRequestWire, decision: ApprovalDecisionKind, opts: CallOptions = {}, ttlS?: number) {
  const signed = signApprovalDecision(approver.keys.signSecret, { request: wire, decision, ...(ttlS === undefined ? {} : { ttlS }), approver: approver.keys.record.device_id, ts: Date.now() });
  return call(approver, 'POST', `${base(fx)}/${wire.request_id}/decision`, { decision: signed }, opts);
}

async function twoDevices() {
  const fx = await VaultFixture.create();
  const job = await fx.addDevice({ kind: 'machine' });
  return { fx, job };
}

describe('approval requests', () => {
  it('round-trips a request and a signed allow, which the requester verifies', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    const posted = await publish(fx, job, wire);
    expect(posted.status).toBe(200);
    expect(posted.json.state).toBe('pending');

    // The owner's laptop lists it, opens the subject with VK, and allows it for an hour.
    const list = await call(fx.owner, 'GET', base(fx));
    expect(list.json.approvals).toHaveLength(1);
    const opened = openApprovalRequest(fx.vk.get(fx.keyEpoch)!, list.json.approvals[0].request, { vaultId: fx.vaultId, requesterSignPub: job.keys.record.sign_pub });
    expect(opened.subject.secret).toBe(SENTINEL_NAME);
    const res = await decide(fx, fx.owner, wire, 'allow_ttl', {}, 3600);
    expect(res.status).toBe(200);
    expect(res.json.state).toBe('allowed');

    // The requester fetches the decision and verifies it independently.
    const got = await call(job, 'GET', `${base(fx)}/${wire.request_id}`);
    expect(got.json.state).toBe('allowed');
    expect(got.json.source).toBe('device');
    const d = verifyApprovalDecision(got.json.decision, wire, { approverSignPub: fx.owner.keys.record.sign_pub, maxTtlS: 86400 });
    expect(d.ttl_s).toBe(3600);

    const dump = await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => JSON.stringify(state.storage.sql.exec('SELECT * FROM approval_requests').toArray()));
    expect(dump).not.toContain(SENTINEL_NAME);
    expect(dump).not.toContain('publish blog');
  });

  it('decides once: a replayed or second decision is refused', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    await publish(fx, job, wire);
    expect((await decide(fx, fx.owner, wire, 'allow_once')).status).toBe(200);
    expect((await decide(fx, fx.owner, wire, 'deny')).status).toBe(409);
    expect((await decide(fx, fx.owner, wire, 'allow_once')).status).toBe(409);
  });

  it('accepts a decision from a browser device and records the source', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    await publish(fx, job, wire);
    expect((await call(fx.owner, 'GET', base(fx), undefined, BROWSER)).json.approvals).toHaveLength(1);
    expect((await decide(fx, fx.owner, wire, 'deny', BROWSER)).json.state).toBe('denied');
    expect((await call(job, 'GET', `${base(fx)}/${wire.request_id}`)).json.source).toBe('browser');
  });

  it('refuses self-approval, machine approvers, other accounts and forged requesters', async () => {
    const fx = await VaultFixture.create('shared');
    const laptop = await fx.addDevice();
    const machine = await fx.addDevice({ kind: 'machine' });
    const stranger = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const wire = seal(fx, laptop);
    await publish(fx, laptop, wire);
    expect((await decide(fx, laptop, wire, 'allow_once')).status).toBe(403); // own request
    expect((await decide(fx, machine, wire, 'allow_once')).status).toBe(403); // not human
    expect((await decide(fx, stranger, wire, 'allow_once')).status).toBe(404); // another account sees nothing
    expect((await call(stranger, 'GET', base(fx))).json.approvals).toHaveLength(0);
    // A device cannot publish a request in another device's name.
    expect((await publish(fx, fx.owner, seal(fx, laptop))).status).toBe(403);
  });

  it('refuses a tampered signature, a stale ts, an over-long life and a past-expiry decision', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    expect((await publish(fx, job, { ...wire, expires_at: wire.expires_at + 1 })).status).toBe(400);
    expect((await publish(fx, job, seal(fx, job, { ts: Date.now() - 600_000 }))).status).toBe(400);
    expect((await publish(fx, job, seal(fx, job, { life: L.approval_request_ttl_s * 1000 + 1 }))).status).toBe(400);
    expect((await publish(fx, job, seal(fx, job, { life: 30_000 }))).status).toBe(400);
    // A decision signed for a different request body does not bind.
    const real = seal(fx, job);
    await publish(fx, job, real);
    const other = seal(fx, job);
    const signed = signApprovalDecision(fx.owner.keys.signSecret, { request: { ...other, request_id: real.request_id }, decision: 'allow_once', approver: fx.owner.keys.record.device_id, ts: Date.now() });
    expect((await call(fx.owner, 'POST', `${base(fx)}/${real.request_id}/decision`, { decision: signed })).status).toBe(400);
  });

  it('lets only the requester cancel, and refuses publishing from a browser session', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    expect((await publish(fx, fx.owner, seal(fx, fx.owner))).status).toBe(200);
    expect((await call(fx.owner, 'POST', base(fx), { request: seal(fx, fx.owner) }, BROWSER)).status).toBe(403);
    await publish(fx, job, wire);
    expect((await call(fx.owner, 'POST', `${base(fx)}/${wire.request_id}/cancel`, {})).status).toBe(403);
    expect((await call(job, 'POST', `${base(fx)}/${wire.request_id}/cancel`, {})).json.state).toBe('cancelled');
    expect((await decide(fx, fx.owner, wire, 'allow_once')).status).toBe(409);
  });

  it('caps pending requests per device', async () => {
    const { fx, job } = await twoDevices();
    for (let i = 0; i < L.approval_requests_pending_per_device; i++) expect((await publish(fx, job, seal(fx, job))).status).toBe(200);
    expect((await publish(fx, job, seal(fx, job))).status).toBe(429);
  });

  it('drops the oldest closed rows instead of refusing past the retained cap', async () => {
    const { fx, job } = await twoDevices();
    const first = seal(fx, job);
    await publish(fx, job, first);
    await call(job, 'POST', `${base(fx)}/${first.request_id}/cancel`, {});
    // Fill the rest of the history directly: the HTTP call budget is far below the cap.
    const now = Date.now();
    await runInDurableObject(env.VAULT.get(env.VAULT.idFromName(fx.vaultId)), (_i: unknown, state: DurableObjectState) => {
      const row = state.storage.sql.exec<Record<string, string | number>>('SELECT * FROM approval_requests WHERE request_id = ?', first.request_id).one();
      for (let i = 1; i < L.approval_requests_retained_per_account; i++) {
        state.storage.sql.exec(
          "INSERT INTO approval_requests (request_id, account, requester, key_epoch, wire, state, created_at, expires_at, decided_at) VALUES (?, ?, ?, ?, ?, 'cancelled', ?, ?, ?)",
          randomId(), row['account'], row['requester'], row['key_epoch'], row['wire'], now, now + 600_000, now + i,
        );
      }
    });
    expect((await publish(fx, job, seal(fx, job))).status).toBe(200);
    expect((await call(fx.owner, 'GET', `${base(fx)}/${first.request_id}`)).status).toBe(404);
  });

  it('refuses a decision once the vault key moved past the request', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    await publish(fx, job, wire);
    expect((await fx.rekey()).status).toBe(201);
    expect((await decide(fx, fx.owner, wire, 'allow_once')).status).toBe(409);
  });
});

describe('approval MCP tools', () => {
  it('lists metadata only and denies, but never allows', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    await publish(fx, job, wire);
    const clientId = `client-${randomId()}`;
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:read vault-mcp:write', clientId, grantId: `grant-${randomId()}` });

    const listed = await callTool(token, 'secrets_approvals_list', { vault_id: fx.vaultId });
    expect(listed.json.result.isError).toBe(false);
    const body = structured(listed);
    expect(body.approvals).toHaveLength(1);
    expect(body.approvals[0].request_id).toBe(wire.request_id);
    expect(listed.text).not.toContain(wire.ct);

    const allow = structured(await callTool(token, 'secrets_approvals_allow', { vault_id: fx.vaultId, request_id: wire.request_id }));
    expect(allow.status).toBe('pending');
    expect(allow.approve_url).toBe(`${env.VAULT_AUDIENCE}/app#approval=${wire.request_id}&vault=${fx.vaultId}`);
    expect((await call(job, 'GET', `${base(fx)}/${wire.request_id}`)).json.state).toBe('pending');

    const denied = structured(await callTool(token, 'secrets_approvals_deny', { vault_id: fx.vaultId, request_id: wire.request_id }));
    expect(denied.status).toBe('denied');
    const got = await call(job, 'GET', `${base(fx)}/${wire.request_id}`);
    expect(got.json).toMatchObject({ state: 'denied', source: 'mcp', mcp_client: clientId });
    expect(got.json.decision).toBeUndefined();
    expect(structured(await callTool(token, 'secrets_approvals_deny', { vault_id: fx.vaultId, request_id: wire.request_id })).code).toBe('not_found');
  });

  it('needs vault-mcp:write to deny', async () => {
    const { fx, job } = await twoDevices();
    const wire = seal(fx, job);
    await publish(fx, job, wire);
    const token = await mintMcpToken({ sub: fx.owner.account, scope: 'vault-mcp:read', clientId: `c-${randomId()}`, grantId: `g-${randomId()}` });
    const res = await callTool(token, 'secrets_approvals_deny', { vault_id: fx.vaultId, request_id: wire.request_id });
    expect(res.json.result?.isError ?? true).toBe(true);
  });
});
