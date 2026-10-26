/**
 * The vault dashboard at /app: its Client ID Metadata Document, its public
 * configuration and the committed static bundle. No response sets a cookie,
 * reveals anything beyond deployed public vars, or falls back to the landing site.
 */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { appContentSecurityPolicy } from '../src/http/responses.js';
import { BASE, fetchRaw } from './helpers/api-client.js';

const CLIENT_ID = `${BASE}/app/client.json`;

/** The checks ak-web applies before it accepts a metadata document (CIMD). */
function expectValidClientMetadata(doc: Record<string, unknown>, url: string): void {
  expect(doc['client_id']).toBe(url);
  const redirects = doc['redirect_uris'] as string[];
  expect(Array.isArray(redirects) && redirects.length >= 1 && redirects.length <= 10).toBe(true);
  for (const r of redirects) {
    const u = new URL(r);
    expect(u.protocol).toBe('https:');
    expect(u.origin).toBe(new URL(url).origin);
    expect(u.pathname.startsWith('/app')).toBe(true);
    expect(u.hash).toBe('');
  }
  expect(doc['token_endpoint_auth_methods_supported']).toContain('none');
  expect(doc['token_endpoint_auth_method']).toBe('none');
  expect(doc['response_types']).toEqual(['code']);
  expect(doc['grant_types']).toContain('authorization_code');
  expect(doc).not.toHaveProperty('client_secret');
  expect(doc).not.toHaveProperty('jwks');
}

describe('dashboard entry', () => {
  it('serves a valid Client ID Metadata Document at its own URL', async () => {
    const res = await fetchRaw('/app/client.json');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toMatch(/^application\/json/);
    expect(res.headers.get('Cache-Control')).toBe('public, max-age=300');
    expect(res.headers.get('Set-Cookie')).toBeNull();
    const text = await res.text();
    expect(new TextEncoder().encode(text).length).toBeLessThanOrEqual(16 * 1024);
    const doc = JSON.parse(text) as Record<string, unknown>;
    expectValidClientMetadata(doc, CLIENT_ID);
    expect(doc['redirect_uris']).toEqual([`${BASE}/app/`]);
    expect(doc['scope']).toBe('vault-app:session');
  });

  it('serves the public configuration derived from deployed vars only', async () => {
    const res = await fetchRaw('/app/config.json');
    expect(res.status).toBe(200);
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    expect(await res.json()).toEqual({
      v: 1,
      issuer: env.VAULT_ISSUER,
      client_id: CLIENT_ID,
      redirect_uri: `${BASE}/app/`,
      resource: `${BASE}/app`,
      scope: 'vault-app:session',
    });
  });

  it('serves the committed bundle with strict headers and no inline code', async () => {
    const res = await fetchRaw('/app/');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toMatch(/^text\/html/);
    expect(res.headers.get('Content-Security-Policy')).toBe(appContentSecurityPolicy(env));
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(res.headers.get('Cache-Control')).toBe('no-store, no-transform');
    expect(res.headers.get('Set-Cookie')).toBeNull();
    const html = await res.text();
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
    expect(scripts.length).toBe(1);
    for (const [, attrs, body] of scripts) {
      expect(body).toBe('');
      expect(attrs).toMatch(/src="\/app\/assets\/app\.[0-9a-f]{8}\.js"/);
      expect(attrs).toMatch(/integrity="sha384-[A-Za-z0-9+/=]+"/);
      expect(attrs).toContain('crossorigin="anonymous"');
    }
    expect(html).not.toMatch(/<style\b/);
    expect(html).not.toMatch(/\son[a-z]+=/i);
    expect(html).not.toMatch(/https?:\/\//);

    const src = /src="([^"]+)"/.exec(scripts[0]![1]!)![1]!;
    const asset = await fetchRaw(src);
    expect(asset.status).toBe(200);
    expect(asset.headers.get('Content-Security-Policy')).toBe(appContentSecurityPolicy(env));
    expect(asset.headers.get('Set-Cookie')).toBeNull();
    const body = new Uint8Array(await asset.arrayBuffer());
    const integrity = /integrity="(sha384-[^"]+)"/.exec(scripts[0]![1]!)![1]!;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-384', body));
    expect(`sha384-${btoa(String.fromCharCode(...digest))}`).toBe(integrity);
  });

  it('answers a matching revalidation of a bundle asset with 304, not not_found', async () => {
    const html = await (await fetchRaw('/app/')).text();
    const src = /<script\b[^>]*\bsrc="([^"]+)"/.exec(html)![1]!;
    const first = await fetchRaw(src);
    const etag = first.headers.get('ETag');
    expect(etag).toBeTruthy();
    await first.arrayBuffer();
    const again = await fetchRaw(src, { headers: { 'If-None-Match': etag! } });
    expect(again.status).toBe(304);
    expect(again.headers.get('Set-Cookie')).toBeNull();
    expect(again.headers.get('Content-Security-Policy')).toBe(appContentSecurityPolicy(env));
  });

  it('answers unknown dashboard paths and other methods with JSON not_found, never the landing site', async () => {
    for (const path of ['/app/x', '/app/assets/missing.js', '/app/404.html', '/app/robots.txt']) {
      const res = await fetchRaw(path);
      expect(res.status, path).toBe(404);
      expect(res.headers.get('Content-Type'), path).toContain('application/json');
    }
    for (const method of ['POST', 'PUT', 'DELETE']) {
      const res = await fetchRaw('/app/config.json', { method });
      expect(res.status, method).toBe(404);
    }
  });

  it('is hidden when remote access is off', async () => {
    for (const path of ['/app/', '/app/client.json', '/app/config.json']) {
      const res = await fetchRaw(path, {}, { VAULT_REMOTE_ACCESS_ENABLED: 'false' });
      expect(res.status, path).toBe(404);
    }
  });
});
