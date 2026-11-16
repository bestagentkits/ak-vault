/**
 * Sandbox secret leases (spec §3.14, §9.6): a non-member sandbox posts a sealed request,
 * a human owner/editor device grants or denies it, and the sandbox fetches an allow once.
 * The Worker stores both wires opaque and never a secret reference or value.
 */
import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openLeaseGrant, randomId } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS as L } from '../src/limits.js';
import { VaultFixture } from './helpers/vault-fixture.js';
import { SUBJECT, VALUE, buildRequest, leasesPath, memberCall, newSandbox, postedLease, sandboxCall, sealPubFor, signGrant } from './helpers/lease-client.js';

const stubFor = (vaultId: string) => env.VAULT.get(env.VAULT.idFromName(vaultId));
const dumpLeases = (vaultId: string) =>
  runInDurableObject(stubFor(vaultId), (_i: unknown, state: DurableObjectState) =>
    JSON.stringify({ leases: state.storage.sql.exec('SELECT * FROM leases').toArray(), idem: state.storage.sql.exec('SELECT * FROM idempotency').toArray() }),
  );

afterEach(() => {
  vi.useRealTimers();
});

describe('sandbox leases: flow', () => {
  it('runs end to end: request, list, grant, status, single fetch that opens to the values', async () => {
    const fx = await VaultFixture.create();
    const { sb, wire } = await postedLease(fx);

    const list = await memberCall(fx.owner, 'GET', leasesPath(fx));
    expect(list.status).toBe(200);
    expect(list.json.leases).toHaveLength(1);
    expect(list.json.leases[0]).toMatchObject({ lease_id: wire.lease_id, requester: wire.requester, key_epoch: fx.keyEpoch, state: 'pending', expires_at: wire.expires_at });
    expect(list.json.leases[0].request).toEqual(wire);
    const got = await memberCall(fx.owner, 'GET', leasesPath(fx, `/${wire.lease_id}`));
    expect(got.json.request).toEqual(wire);

    expect((await sandboxCall(sb, 'GET', leasesPath(fx, `/${wire.lease_id}/status`))).json.state).toBe('pending');
    expect((await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {})).status).toBe(409);

    const grant = signGrant(fx.owner, wire, 'allow');
    const granted = await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant });
    expect(granted.status).toBe(200);
    expect(granted.json).toEqual({ lease_id: wire.lease_id, state: 'allowed' });

    const status = await sandboxCall(sb, 'GET', leasesPath(fx, `/${wire.lease_id}/status`));
    expect(status.json).toEqual({ lease_id: wire.lease_id, state: 'allowed', expires_at: grant.expires_at });
    const after = await memberCall(fx.owner, 'GET', leasesPath(fx, `/${wire.lease_id}`));
    expect(after.json).toMatchObject({ state: 'allowed', decision: 'allow', approver: fx.owner.keys.record.device_id });
    expect(after.json.grant).toBeUndefined();
    expect(JSON.stringify(after.json)).not.toContain(grant.ct!);

    const idem = randomId();
    const fetched = await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {}, { idempotencyKey: idem });
    expect(fetched.status).toBe(200);
    expect(fetched.json.state).toBe('fetched');
    const opened = openLeaseGrant(sb.leaseSecret, fetched.json.grant, wire, { now: Date.now(), requestedVars: SUBJECT.secrets.map((s) => s.var) });
    expect(opened.decision).toBe('allow');
    if (opened.decision === 'allow') expect(opened.payload.secrets).toEqual([{ var: 'SENTINEL_LEASE_VAR', value: VALUE }]);

    // Delivered once: a second fetch, even a same-key retry, is refused, and no ciphertext is kept.
    expect((await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {})).status).toBe(409);
    expect((await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {}, { idempotencyKey: idem })).status).toBe(409);
    expect((await sandboxCall(sb, 'GET', leasesPath(fx, `/${wire.lease_id}/status`))).json.state).toBe('fetched');
    const dump = await dumpLeases(fx.vaultId);
    expect(dump).not.toContain(grant.ct!);
    for (const leak of [SUBJECT.secrets[0]!.ref, SUBJECT.secrets[0]!.var, SUBJECT.purpose, VALUE]) expect(dump).not.toContain(leak);
  });

  it('deny: the sandbox fetches the signed deny, repeatedly, and the lease stays denied', async () => {
    const fx = await VaultFixture.create();
    const { sb, wire } = await postedLease(fx);
    const res = await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant: signGrant(fx.owner, wire, 'deny') });
    expect(res.json.state).toBe('denied');
    for (let i = 0; i < 2; i++) {
      const fetched = await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {});
      expect(fetched.status).toBe(200);
      expect(fetched.json.state).toBe('denied');
      expect(openLeaseGrant(sb.leaseSecret, fetched.json.grant, wire, { now: Date.now(), requestedVars: ['SENTINEL_LEASE_VAR'] }).decision).toBe('deny');
    }
  });

  it('decides once and only on a pending lease at the current key epoch', async () => {
    const fx = await VaultFixture.create();
    const { wire } = await postedLease(fx);
    const path = leasesPath(fx, `/${wire.lease_id}/grant`);
    expect((await memberCall(fx.owner, 'POST', path, { grant: signGrant(fx.owner, wire, 'deny') })).status).toBe(200);
    expect((await memberCall(fx.owner, 'POST', path, { grant: signGrant(fx.owner, wire, 'allow') })).status).toBe(409);

    const fx2 = await VaultFixture.create();
    const { wire: w2 } = await postedLease(fx2);
    expect((await fx2.rekey()).status).toBe(201);
    expect((await memberCall(fx2.owner, 'POST', leasesPath(fx2, `/${w2.lease_id}/grant`), { grant: signGrant(fx2.owner, w2, 'allow') })).status).toBe(409);
  });

  it('checks the approver: human owner/editor of the account, the token device, its current key', async () => {
    const fx = await VaultFixture.create('shared');
    const machine = await fx.addDevice({ kind: 'machine' });
    const reader = await fx.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    const laptop = await fx.addDevice();
    const { wire } = await postedLease(fx);
    const path = leasesPath(fx, `/${wire.lease_id}/grant`);
    const grantBy = (caller: typeof fx.owner, signer = caller) => memberCall(caller, 'POST', path, { grant: signGrant(signer, wire, 'allow') });

    expect((await grantBy(machine)).status).toBe(403); // machine device refused by role
    expect((await grantBy(reader)).status).toBe(403); // a reader is refused by role
    expect((await grantBy(laptop, fx.owner)).json.error.code).toBe('forbidden'); // approver is not the token device
    // approver_key other than the approver's key: `approver` = kid(`approver_key`) fails at parse.
    const forged = { ...signGrant(fx.owner, wire, 'allow'), approver_key: laptop.keys.record.sign_pub };
    expect((await memberCall(fx.owner, 'POST', path, { grant: forged })).json.error.code).toBe('bad_request');

    // A grant for another request of the same account does not verify against this one.
    const { wire: other } = await postedLease(fx);
    const mismatched = signGrant(fx.owner, other, 'allow');
    expect((await memberCall(fx.owner, 'POST', path, { grant: mismatched })).json.error.code).toBe('bad_request');

    const ok = await grantBy(laptop);
    expect(ok.status).toBe(200);
  });

  it('a browser owner device may list and grant; a reader member of the account may not list', async () => {
    const fx = await VaultFixture.create();
    const { wire } = await postedLease(fx);
    expect((await memberCall(fx.owner, 'GET', leasesPath(fx), undefined, { sessionKind: 'browser' })).status).toBe(200);
    const res = await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant: signGrant(fx.owner, wire, 'deny') }, { sessionKind: 'browser' });
    expect(res.status).toBe(200);

    const shared = await VaultFixture.create('shared');
    const reader = await shared.addDevice({ account: `acct-${randomId()}`, role: 'reader' });
    expect((await memberCall(reader, 'GET', leasesPath(shared))).status).toBe(403);
  });

  it('keeps leases to their account and their requester', async () => {
    const fx = await VaultFixture.create('shared');
    const other = await fx.addDevice({ account: `acct-${randomId()}`, role: 'editor' });
    const { sb, wire } = await postedLease(fx);
    const id = wire.lease_id;
    // Another account's member device sees nothing.
    expect((await memberCall(other, 'GET', leasesPath(fx, `/${id}`))).status).toBe(404);
    expect((await memberCall(other, 'GET', leasesPath(fx))).json.leases).toEqual([]);
    expect((await memberCall(other, 'POST', leasesPath(fx, `/${id}/grant`), { grant: signGrant(other, wire, 'allow') })).status).toBe(404);
    expect((await memberCall(other, 'POST', leasesPath(fx, `/${id}/revoke`), {})).status).toBe(404);
    // Another account's sandbox, and another sandbox of the same account, see nothing.
    const foreign = newSandbox(other.account);
    const sibling = newSandbox(fx.owner.account);
    for (const s of [foreign, sibling]) {
      expect((await sandboxCall(s, 'GET', leasesPath(fx, `/${id}/status`))).status).toBe(404);
      expect((await sandboxCall(s, 'POST', leasesPath(fx, `/${id}/fetch`), {})).status).toBe(404);
    }
    expect((await sandboxCall(sb, 'GET', leasesPath(fx, `/${randomId()}/status`))).status).toBe(404);
  });

  it('validates the request: binding, epoch, signature, clock window, lifetime, reuse, size', async () => {
    const fx = await VaultFixture.create();
    const sb = newSandbox(fx.owner.account);
    const sealPub = await sealPubFor(fx, sb);
    const post = (request: unknown, opts = {}) => sandboxCall(sb, 'POST', leasesPath(fx), { request }, opts);
    const code = async (request: unknown) => (await post(request)).json.error?.code;

    expect(await code(buildRequest(fx, sb, sealPub, { account: `acct-${randomId()}` }))).toBe('bad_request');
    expect(await code(buildRequest(fx, sb, sealPub, { vaultId: randomId() }))).toBe('bad_request');
    expect(await code(buildRequest(fx, sb, sealPub, { epoch: fx.keyEpoch + 1 }))).toBe('bad_request');
    expect(await code({ ...buildRequest(fx, sb, sealPub), ttl_s: 120 })).toBe('bad_request'); // signature no longer verifies
    expect(await code(buildRequest(fx, sb, sealPub, { ts: Date.now() - 600_000, life: 1_200_000 }))).toBe('bad_request');
    expect(await code(buildRequest(fx, sb, sealPub, { ts: Date.now() + 600_000 }))).toBe('bad_request');
    expect(await code(buildRequest(fx, sb, sealPub, { life: (L.lease_request_min_ttl_s - 1) * 1000 }))).toBe('bad_request');
    expect(await code(buildRequest(fx, sb, sealPub, { life: L.lease_request_ttl_s * 1000 + 1 }))).toBe('bad_request');
    // requester = token did: a request signed by another sandbox key is refused.
    const stranger = newSandbox(fx.owner.account);
    expect(await code(buildRequest(fx, stranger, sealPub))).toBe('bad_request');
    // Oversize ciphertext.
    expect(await code({ ...buildRequest(fx, sb, sealPub), ct: 'A'.repeat(40_000) })).toBe('bad_request');
    // Unknown body keys.
    expect((await sandboxCall(sb, 'POST', leasesPath(fx), { request: buildRequest(fx, sb, sealPub), extra: 1 })).json.error.code).toBe('bad_request');
    // A body over the request limit.
    expect((await sandboxCall(sb, 'POST', leasesPath(fx), undefined, { rawBody: new Uint8Array(300 * 1024) })).status).toBe(413);

    const wire = buildRequest(fx, sb, sealPub);
    expect((await post(wire)).status).toBe(200);
    expect((await post(wire)).status).toBe(409);
  });

  it('expires a pending lease at its approval window and an allowed one at its grant expiry', async () => {
    const fx = await VaultFixture.create();
    const t0 = Date.now();
    vi.useFakeTimers({ toFake: ['Date'], now: t0 });
    const { sb, wire } = await postedLease(fx, { life: 120_000 });
    const { sb: sb2, wire: w2 } = await postedLease(fx, { life: 600_000, ttlS: 60 });
    const grant = signGrant(fx.owner, w2, 'allow');
    expect((await memberCall(fx.owner, 'POST', leasesPath(fx, `/${w2.lease_id}/grant`), { grant })).status).toBe(200);

    vi.setSystemTime(t0 + 121_000);
    expect((await sandboxCall(sb, 'GET', leasesPath(fx, `/${wire.lease_id}/status`))).json.state).toBe('expired');
    expect((await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant: signGrant(fx.owner, wire, 'deny', { ts: t0 + 1000 }) })).status).toBe(409);
    expect((await sandboxCall(sb2, 'POST', leasesPath(fx, `/${w2.lease_id}/fetch`), {})).status).toBe(409);
    expect((await sandboxCall(sb2, 'GET', leasesPath(fx, `/${w2.lease_id}/status`))).json.state).toBe('expired');
    expect(await dumpLeases(fx.vaultId)).not.toContain(grant.ct!);
  });

  it('revoke closes a pending or allowed lease and deletes its grant; nothing else', async () => {
    const fx = await VaultFixture.create();
    const { sb, wire } = await postedLease(fx);
    const grant = signGrant(fx.owner, wire, 'allow');
    await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/grant`), { grant });
    const revoked = await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/revoke`), {});
    expect(revoked.json).toEqual({ lease_id: wire.lease_id, state: 'revoked' });
    expect((await sandboxCall(sb, 'POST', leasesPath(fx, `/${wire.lease_id}/fetch`), {})).status).toBe(409);
    expect((await memberCall(fx.owner, 'POST', leasesPath(fx, `/${wire.lease_id}/revoke`), {})).status).toBe(409);
    expect(await dumpLeases(fx.vaultId)).not.toContain(grant.ct!);

    const { wire: pending } = await postedLease(fx);
    expect((await memberCall(fx.owner, 'POST', leasesPath(fx, `/${pending.lease_id}/revoke`), {})).json.state).toBe('revoked');
    expect((await memberCall(fx.owner, 'POST', leasesPath(fx, `/${pending.lease_id}/revoke`), { x: 1 })).json.error.code).toBe('bad_request');
  });

  it('past the retained cap drops the oldest closed rows, never the new lease', async () => {
    const fx = await VaultFixture.create();
    const oldest = randomId();
    await runInDurableObject(stubFor(fx.vaultId), (_i: unknown, state: DurableObjectState) => {
      for (let i = 0; i < L.leases_retained_per_account; i++) {
        state.storage.sql.exec(
          "INSERT INTO leases (lease_id, account, requester, key_epoch, request, state, created_at, expires_at, closed_at) VALUES (?, ?, 'r', 1, '{}', 'fetched', ?, ?, ?)",
          i === 0 ? oldest : randomId(),
          fx.owner.account,
          Date.now() - 1000 + i,
          Date.now() + 600_000,
          Date.now() - 1000 + i,
        );
      }
    });
    const { wire } = await postedLease(fx);
    const ids = await runInDurableObject(stubFor(fx.vaultId), (_i: unknown, state: DurableObjectState) =>
      state.storage.sql.exec<{ lease_id: string }>('SELECT lease_id FROM leases').toArray().map((r) => r.lease_id),
    );
    expect(ids).toHaveLength(L.leases_retained_per_account);
    expect(ids).toContain(wire.lease_id);
    expect(ids).not.toContain(oldest);
  });

  it('caps pending leases per account and lists newest first with state and limit filters', async () => {
    const fx = await VaultFixture.create();
    await runInDurableObject(stubFor(fx.vaultId), (_i: unknown, state: DurableObjectState) => {
      for (let i = 0; i < L.leases_pending_per_account; i++) {
        state.storage.sql.exec(
          "INSERT INTO leases (lease_id, account, requester, key_epoch, request, state, created_at, expires_at) VALUES (?, ?, 'r', 1, '{}', 'pending', ?, ?)",
          randomId(),
          fx.owner.account,
          i,
          Date.now() + 600_000,
        );
      }
    });
    const sb = newSandbox(fx.owner.account);
    const sealPub = await sealPubFor(fx, sb);
    const res = await sandboxCall(sb, 'POST', leasesPath(fx), { request: buildRequest(fx, sb, sealPub) });
    expect(res.json.error.code).toBe('rate_limited');

    const page = await memberCall(fx.owner, 'GET', leasesPath(fx, '?state=all&limit=3'));
    expect(page.json.leases).toHaveLength(3);
    expect(page.json.leases[0].created_at).toBeGreaterThan(page.json.leases[1].created_at);
    expect((await memberCall(fx.owner, 'GET', leasesPath(fx, `?limit=${L.lease_page_max + 1}`))).status).toBe(400);
    expect((await memberCall(fx.owner, 'GET', leasesPath(fx, '?state=open'))).status).toBe(400);
  });
});
