/**
 * VAULT_REMOTE_ACCESS_ENABLED: off (anything but exactly "true") hides every
 * remote-access route as 404 and keeps /v1/meta at the sync limits; the deployed
 * configuration keeps it off in production.
 */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { b64encode, randomBytes, randomId } from '@ak-vault/protocol';
import { LIMITS, REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { call, fetchRaw } from './helpers/api-client.js';
import { upgrade } from './helpers/relay-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

declare global {
  namespace Cloudflare {
    interface Env {
      TEST_DEPLOYED_REMOTE_ACCESS: string;
    }
  }
}

const OFF = { VAULT_REMOTE_ACCESS_ENABLED: 'false' };

describe('remote access flag', () => {
  it('is off in production and on in staging as deployed', () => {
    expect(JSON.parse(env.TEST_DEPLOYED_REMOTE_ACCESS)).toEqual({ production: 'false', staging: 'true' });
  });

  for (const value of ['false', 'TRUE', '1', '', ' true']) {
    it(`"${value}" hides /v1/relay, /mcp, protected-resource metadata and /app`, async () => {
      const off = { VAULT_REMOTE_ACCESS_ENABLED: value };
      const fx = await VaultFixture.create();
      const relay = await upgrade(fx.owner, { env: off });
      expect(relay.status).toBe(404);
      expect(await relay.json()).toEqual({ error: { code: 'not_found', message: 'not found' } });
      for (const path of ['/mcp', '/.well-known/oauth-protected-resource/mcp', '/app', '/app/', '/app/index.html', '/app/assets/x.js']) {
        const res = await fetchRaw(path, {}, off);
        expect(res.status, path).toBe(404);
        expect(((await res.json()) as { error: { code: string } }).error.code).toBe('not_found');
      }
      // The root metadata path is no remote-access route at all: the landing site's 404.
      expect((await fetchRaw('/.well-known/oauth-protected-resource', {}, off)).status).toBe(404);
      const health = (await (await fetchRaw('/healthz', {}, off)).json()) as { remote_access: boolean };
      expect(health.remote_access).toBe(false);
    });
  }

  it('off hides the lookup, seal-key and sealed routes and refuses the name_tag wrapper', async () => {
    const fx = await VaultFixture.create();
    const opts = { env: OFF };
    expect((await fx.get(fx.owner, `/lookup?tag=${'A'.repeat(22)}&key_epoch=1`, opts)).status).toBe(404);
    expect((await fx.get(fx.owner, '/seal-key', opts)).status).toBe(404);
    expect((await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/seal-key`, { seal_key: {} }, opts)).status).toBe(404);
    expect((await fx.get(fx.owner, '/sealed', opts)).status).toBe(404);
    expect((await fx.post(fx.owner, `/sealed/${randomId()}/ack`, { outcome: 'applied' }, opts)).status).toBe(404);

    const id = randomId();
    const record = fx.record(fx.owner, id, 0, { name: 'A', value: '1' });
    const wrapped = await call(fx.owner, 'PUT', `/v1/vaults/${fx.vaultId}/items/${id}`, { record, name_tag: { key_epoch: 1, tag: b64encode(randomBytes(16)) } }, opts);
    expect(wrapped.status).toBe(400);
    expect((await fx.put(fx.owner, record, opts)).status).toBe(200);
  });

  it('off publishes only the sync limits in /v1/meta; on adds the remote-access limits', async () => {
    const off = (await (await fetchRaw('/v1/meta', {}, OFF)).json()) as { limits: unknown; remote_access: boolean };
    expect(off.limits).toEqual(LIMITS);
    expect(off.remote_access).toBe(false);
    const on = (await (await fetchRaw('/v1/meta')).json()) as { limits: unknown; remote_access: boolean };
    expect(on.limits).toEqual({ ...LIMITS, ...REMOTE_ACCESS_LIMITS });
    expect(on.remote_access).toBe(true);
  });

  it('on routes /app to its handler (not yet served: 404 JSON) and never to the landing site', async () => {
    for (const path of ['/app', '/app/x']) {
      const res = await fetchRaw(path);
      expect(res.status, path).toBe(404);
      expect(res.headers.get('Content-Type')).toContain('application/json');
    }
  });

  it('on serves /mcp (401 challenge) and protected-resource metadata, never the landing site', async () => {
    const mcp = await fetchRaw('/mcp', { method: 'POST' });
    expect(mcp.status).toBe(401);
    expect(mcp.headers.get('WWW-Authenticate')).toContain('resource_metadata=');
    const prm = await fetchRaw('/.well-known/oauth-protected-resource/mcp');
    expect(prm.status).toBe(200);
    expect(prm.headers.get('Content-Type')).toContain('application/json');
  });

  it('on still answers 404 for the root /.well-known/oauth-protected-resource', async () => {
    const res = await fetchRaw('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(404);
    expect(res.headers.get('Content-Type') ?? '').not.toContain('application/json');
  });
});
