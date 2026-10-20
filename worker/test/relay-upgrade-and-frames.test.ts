/** Device relay: upgrade checks, `hello`, frame rules, replacement and the per-account cap. */
import { env } from 'cloudflare:workers';
import { runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { cjson, randomId } from '@ak-vault/protocol';
import { REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { relayStub } from '../src/relay/relay-rpc.js';
import { createDevice } from './helpers/api-client.js';
import { openRelay, readyRelay, relayProof, relayToken, upgrade, RELAY_URL } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

async function errorOf(res: Response): Promise<{ status: number; code: string }> {
  const body = (await res.json()) as { error: { code: string } };
  return { status: res.status, code: body.error.code };
}

describe('relay upgrade', () => {
  it('accepts a human device with both scopes, its key and a proof, and answers hello with ready', async () => {
    const fx = await VaultFixture.create();
    const conn = await openRelay(fx.owner);
    const ready = await conn.hello([fx.vaultId]);
    expect(ready['type']).toBe('ready');
    expect(ready['v']).toBe(1);
    expect(typeof ready['exp']).toBe('number');
    expect(await relayStub(env, fx.owner.account).knownVaults()).toEqual([fx.vaultId]);
    conn.close();
  });

  it('refuses a missing or invalid token, a wrong device key, and a missing proof', async () => {
    const fx = await VaultFixture.create();
    expect(await errorOf(await upgrade(fx.owner, { token: null }))).toEqual({ status: 401, code: 'unauthorized' });
    expect(await errorOf(await upgrade(fx.owner, { token: 'not.a.jwt' }))).toEqual({ status: 401, code: 'unauthorized' });
    const other = createDevice(fx.owner.account);
    expect(await errorOf(await upgrade(fx.owner, { deviceKey: other.keys.record.sign_pub }))).toEqual({ status: 401, code: 'unauthorized' });
    expect(await errorOf(await upgrade(fx.owner, { deviceKey: null }))).toEqual({ status: 401, code: 'unauthorized' });
    expect(await errorOf(await upgrade(fx.owner, { proof: null }))).toEqual({ status: 401, code: 'unauthorized' });
  });

  it('refuses a proof signed by another key, for another URL, or replayed', async () => {
    const fx = await VaultFixture.create();
    const token = await relayToken(fx.owner);
    const stranger = createDevice(fx.owner.account);
    expect(await errorOf(await upgrade(fx.owner, { token, proof: relayProof(stranger, token) }))).toEqual({ status: 401, code: 'unauthorized' });
    const proof = relayProof(fx.owner, token);
    const first = await upgrade(fx.owner, { token, proof });
    expect(first.status).toBe(101);
    first.webSocket!.accept();
    expect(await errorOf(await upgrade(fx.owner, { token, proof }))).toEqual({ status: 401, code: 'unauthorized' });
    first.webSocket!.close(1000, 'done');
  });

  it('refuses machine and browser sessions and tokens without both vault scopes', async () => {
    const fx = await VaultFixture.create();
    expect(await errorOf(await upgrade(fx.owner, { sessionKind: 'browser' }))).toEqual({ status: 403, code: 'forbidden' });
    expect(await errorOf(await upgrade(fx.owner, { sessionKind: 'machine' }))).toEqual({ status: 403, code: 'forbidden' });
    expect(await errorOf(await upgrade(fx.owner, { scope: 'vault:read' }))).toEqual({ status: 403, code: 'forbidden' });
    expect(await errorOf(await upgrade(fx.owner, { scope: 'vault:write' }))).toEqual({ status: 403, code: 'forbidden' });
    expect((await upgrade(fx.owner, { sessionKind: 'api_key_device' })).status).toBe(101);
  });

  it('requires GET, a WebSocket upgrade and the exact URL', async () => {
    const fx = await VaultFixture.create();
    expect((await upgrade(fx.owner, { upgrade: false })).status).toBe(426);
    expect((await upgrade(fx.owner, { method: 'POST' })).status).toBe(404);
    expect((await upgrade(fx.owner, { url: `${RELAY_URL}?x=1` })).status).toBe(400);
  });

  it('answers sync_disabled while the kill switch is off', async () => {
    const fx = await VaultFixture.create();
    expect(await errorOf(await upgrade(fx.owner, { env: { VAULT_SYNC_ENABLED: 'false' } }))).toEqual({ status: 503, code: 'sync_disabled' });
  });

  it('a newer connection of the same device replaces the old one with 4409', async () => {
    const fx = await VaultFixture.create();
    const first = await readyRelay(fx.owner, [fx.vaultId]);
    const second = await readyRelay(fx.owner, [fx.vaultId]);
    expect((await first.closedWith()).code).toBe(4409);
    expect(second.closed).toBeNull();
    second.close();
  });

  it('caps open connections per account at relay_devices_per_account (429)', async () => {
    const account = `acct-${randomId()}`;
    const open = [];
    for (let i = 0; i < REMOTE_ACCESS_LIMITS.relay_devices_per_account; i++) open.push(await openRelay(createDevice(account)));
    const res = await upgrade(createDevice(account));
    expect(await errorOf(res)).toEqual({ status: 429, code: 'rate_limited' });
    // Another account is unaffected.
    const elsewhere = await openRelay(createDevice(`acct-${randomId()}`));
    // A device already connected may reconnect (it replaces itself).
    const again = await openRelay(open[0]!.device);
    expect((await open[0]!.closedWith()).code).toBe(4409);
    for (const c of [...open, elsewhere, again]) c.close();
  });
});

describe('relay hello', () => {
  it('closes 4403 when the device is not a current human device of every listed vault', async () => {
    const fx = await VaultFixture.create();
    const other = await VaultFixture.create();
    const conn = await openRelay(fx.owner);
    conn.send(conn.helloFrame([fx.vaultId, other.vaultId]));
    expect((await conn.closedWith()).code).toBe(4403);

    const unknown = await openRelay(fx.owner);
    unknown.send(unknown.helloFrame([randomId()]));
    expect((await unknown.closedWith()).code).toBe(4403);
  });

  it('closes 4403 for a device of the same account that is not enrolled with that key', async () => {
    const fx = await VaultFixture.create();
    const notEnrolled = createDevice(fx.owner.account);
    const conn = await openRelay(notEnrolled);
    conn.send(conn.helloFrame([fx.vaultId]));
    expect((await conn.closedWith()).code).toBe(4403);
  });

  it('closes 4403 when device_id is not the upgrade key and 4400 for a bad signature or stale ts', async () => {
    const fx = await VaultFixture.create();
    const a = await openRelay(fx.owner);
    a.send(a.helloFrame([fx.vaultId], undefined, { deviceId: createDevice(fx.owner.account).keys.record.device_id }));
    expect((await a.closedWith()).code).toBe(4403);

    const b = await openRelay(fx.owner);
    const frame = b.helloFrame([fx.vaultId]);
    b.send({ ...frame, ts: (frame['ts'] as number) + 1 });
    expect((await b.closedWith()).code).toBe(4400);

    const c = await openRelay(fx.owner);
    c.send(c.helloFrame([fx.vaultId], undefined, { ts: Date.now() - 10 * 60_000 }));
    expect((await c.closedWith()).code).toBe(4400);
  });

  it('closes 4400 on a non-canonical, unknown, binary, oversize or server-only frame, and a second hello', async () => {
    const fx = await VaultFixture.create();
    const cases: ((c: Awaited<ReturnType<typeof openRelay>>) => void)[] = [
      (c) => c.sendRaw('{"type":"hello", "v":1}'),
      (c) => c.send({ v: 1, type: 'nope' }),
      (c) => c.ws.send(new Uint8Array([1, 2, 3])),
      (c) => c.sendRaw(cjson({ v: 1, type: 'reauth', token: 'x'.repeat(REMOTE_ACCESS_LIMITS.relay_frame_max_bytes), proof: 'p' })),
      (c) => c.send({ v: 1, type: 'ready', exp: 1 }),
      (c) => c.send({ v: 1, type: 'reauth', token: 't', proof: 'p' }), // before hello
    ];
    for (const send of cases) {
      const conn = await openRelay(fx.owner);
      send(conn);
      expect((await conn.closedWith()).code).toBe(4400);
    }
    const twice = await readyRelay(fx.owner, [fx.vaultId]);
    twice.send(twice.helloFrame([fx.vaultId]));
    expect((await twice.closedWith()).code).toBe(4400);
  });

  it('the alarm closes a connection without hello after relay_hello_timeout_ms with 4400', async () => {
    const fx = await VaultFixture.create();
    const conn = await openRelay(fx.owner);
    const stub = relayStub(env, fx.owner.account);
    await runInDurableObject(stub, async (_instance, state) => {
      for (const ws of state.getWebSockets()) {
        const a = ws.deserializeAttachment() as { connectedAt: number };
        ws.serializeAttachment({ ...a, connectedAt: a.connectedAt - REMOTE_ACCESS_LIMITS.relay_hello_timeout_ms - 1 });
      }
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await conn.closedWith()).code).toBe(4400);
  });

  it('a hello after the timeout is refused even before the alarm runs', async () => {
    const fx = await VaultFixture.create();
    const conn = await openRelay(fx.owner);
    await runInDurableObject(relayStub(env, fx.owner.account), async (_instance, state) => {
      for (const ws of state.getWebSockets()) {
        const a = ws.deserializeAttachment() as { connectedAt: number };
        ws.serializeAttachment({ ...a, connectedAt: a.connectedAt - REMOTE_ACCESS_LIMITS.relay_hello_timeout_ms - 1 });
      }
    });
    conn.send(conn.helloFrame([fx.vaultId]));
    expect((await conn.closedWith()).code).toBe(4400);
  });
});
