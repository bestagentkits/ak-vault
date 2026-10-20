/** Dashboard paths get their own CSP, cross-origin isolation and an uncached document; other paths keep the default. */
import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY, appContentSecurityPolicy } from '../src/http/responses.js';
import { fetchRaw } from './helpers/api-client.js';

describe('dashboard security headers', () => {
  it('the dashboard CSP denies by default, uses Trusted Types and connects only to itself and the issuer', () => {
    const csp = appContentSecurityPolicy(env);
    const directives = csp.split('; ');
    expect(directives).toContain("default-src 'none'");
    expect(directives).toContain("script-src 'self'");
    expect(directives).toContain("frame-ancestors 'none'");
    expect(directives).toContain("require-trusted-types-for 'script'");
    expect(directives).toContain(`connect-src 'self' ${new URL(env.VAULT_ISSUER).origin}`);
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
  });

  for (const path of ['/app', '/app/', '/app/index.html', '/app/assets/main.js']) {
    it(`${path} carries the dashboard CSP, COOP and CORP`, async () => {
      const res = await fetchRaw(path);
      expect(res.headers.get('Content-Security-Policy')).toBe(appContentSecurityPolicy(env));
      expect(res.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
      expect(res.headers.get('Cross-Origin-Resource-Policy')).toBe('same-origin');
      expect(res.headers.get('X-Frame-Options')).toBe('DENY');
      expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    });
  }

  it('the dashboard document is never cached', async () => {
    for (const path of ['/app', '/app/', '/app/index.html']) expect((await fetchRaw(path)).headers.get('Cache-Control')).toBe('no-store');
  });

  it('other paths keep the default CSP and no cross-origin isolation headers', async () => {
    for (const path of ['/', '/v1/meta', '/healthz', '/mcp', '/application']) {
      const res = await fetchRaw(path);
      expect(res.headers.get('Content-Security-Policy'), path).toBe(CONTENT_SECURITY_POLICY);
      expect(res.headers.get('Cross-Origin-Opener-Policy'), path).toBeNull();
    }
  });

  it('a refused relay upgrade carries the default security headers', async () => {
    const res = await fetchRaw('/v1/relay', { headers: { Upgrade: 'websocket' } });
    expect(res.status).toBe(401);
    expect(res.headers.get('Content-Security-Policy')).toBe(CONTENT_SECURITY_POLICY);
  });
});
