/** Public surface: /healthz, /v1/meta, kill switch, landing site and its headers. */
import { describe, expect, it } from 'vitest';
import { LIMITS, REMOTE_ACCESS_LIMITS } from '../src/limits.js';
import { fetchRaw } from './helpers/api-client.js';
import { VaultFixture } from './helpers/vault-fixture.js';

const OFF = { VAULT_SYNC_ENABLED: 'false' };

describe('health and meta', () => {
  it('GET /healthz reports version, protocol and sync state', async () => {
    const res = await fetchRaw('/healthz');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, version: expect.any(String), protocol: 'akv1', sync_enabled: true, remote_access: true });
  });

  it('GET /v1/meta publishes the limits owner verbatim', async () => {
    const res = await fetchRaw('/v1/meta');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { limits: unknown; protocol_versions: string[]; sync_enabled: boolean; remote_access: boolean };
    expect(body.limits).toEqual({ ...LIMITS, ...REMOTE_ACCESS_LIMITS });
    expect(body.remote_access).toBe(true);
    expect(body.protocol_versions).toEqual(['akv1']);
    expect(body.sync_enabled).toBe(true);
  });

  it('unknown /v1 routes are 404 JSON', async () => {
    const res = await fetchRaw('/v1/nope');
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: { code: 'not_found', message: 'not found' } });
    expect((await fetchRaw('/internal/v1/other', { method: 'POST' })).status).toBe(404);
  });
});

describe('kill switch', () => {
  it('sync routes return 503 sync_disabled while health and meta keep working', async () => {
    const fx = VaultFixture.local();
    const res = await fx.putGenesis({ env: OFF });
    expect(res.status).toBe(503);
    expect(res.json.error.code).toBe('sync_disabled');
    expect((await fetchRaw('/v1/anything', {}, OFF)).status).toBe(503);

    const health = await fetchRaw('/healthz', {}, OFF);
    expect(health.status).toBe(200);
    expect(((await health.json()) as { sync_enabled: boolean }).sync_enabled).toBe(false);
    const meta = await fetchRaw('/v1/meta', {}, OFF);
    expect(meta.status).toBe(200);
    expect(((await meta.json()) as { sync_enabled: boolean }).sync_enabled).toBe(false);
    expect((await fetchRaw('/', {}, OFF)).status).toBe(200);
  });

  it('any value other than exactly "true" disables sync', async () => {
    for (const value of ['TRUE', '1', 'yes', '']) {
      expect((await fetchRaw('/v1/vaults/x', { method: 'PUT' }, { VAULT_SYNC_ENABLED: value })).status).toBe(503);
    }
  });
});

describe('landing site', () => {
  it('serves HTML with security headers', async () => {
    const res = await fetchRaw('/');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/html');
    expect(await res.text()).toContain('ak-vault');
    const csp = res.headers.get('Content-Security-Policy') ?? '';
    for (const directive of ["default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "img-src 'self' data:"]) {
      expect(csp).toContain(directive);
    }
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(res.headers.get('Strict-Transport-Security')).toMatch(/max-age=\d+/);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Referrer-Policy')).toBeTruthy();
    expect(res.headers.get('Permissions-Policy')).toBeTruthy();
  });

  it('marks HTML pages no-transform so the proxy cannot inject scripts, keeping other cache directives', async () => {
    for (const path of ['/', '/how-it-works/', '/security/', '/guide/', '/faq/', '/does-not-exist']) {
      const directives = ((await fetchRaw(path)).headers.get('Cache-Control') ?? '').split(',').map((d) => d.trim());
      expect(directives, path).toContain('no-transform');
      expect(directives.filter((d) => d === 'no-transform'), path).toHaveLength(1);
      expect(directives.length, path).toBeGreaterThan(1);
    }
  });

  it('leaves non-HTML assets transformable so the edge can compress them', async () => {
    for (const path of ['/styles.css', '/site.js', '/index.md', '/llms.txt']) {
      expect((await fetchRaw(path)).headers.get('Cache-Control') ?? '', path).not.toContain('no-transform');
    }
  });

  it('serves Markdown twins as UTF-8 text/markdown', async () => {
    for (const path of ['/index.md', '/how-it-works/index.md', '/security/index.md', '/guide/index.md', '/faq/index.md']) {
      const res = await fetchRaw(path);
      expect(res.status).toBe(200);
      expect(res.headers.get('Content-Type')).toBe('text/markdown; charset=utf-8');
    }
  });

  it('redirects /security to /security/', async () => {
    const res = await fetchRaw('/security', { redirect: 'manual' });
    expect([301, 307, 308]).toContain(res.status);
    expect(new URL(res.headers.get('Location')!, 'https://vault.agentkit.best').pathname).toBe('/security/');
    expect((await fetchRaw('/security/')).status).toBe(200);
  });

  it('unknown pages get the 404 page with security headers', async () => {
    const res = await fetchRaw('/does-not-exist');
    expect(res.status).toBe(404);
    expect(await res.text()).toContain('This page does not exist');
    expect(res.headers.get('Content-Security-Policy')).toBeTruthy();
  });

  it('API responses carry security headers and no-store', async () => {
    const res = await fetchRaw('/healthz');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
  });
});
