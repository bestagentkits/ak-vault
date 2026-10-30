/**
 * `GET /input` (spec §3.11): the input form link redirects to the dashboard bundle,
 * which reads the fragment the browser keeps across the redirect. It serves only
 * where remote access and input requests are both on; otherwise, and for any other
 * method, it is a JSON 404 like every gated route.
 */
import { describe, expect, it, vi } from 'vitest';
import type { Env } from '../src/env.js';
import { CONTENT_SECURITY_POLICY } from '../src/http/responses.js';
import { fetchRaw } from './helpers/api-client.js';

const ON: Partial<Env> = { VAULT_REMOTE_ACCESS_ENABLED: 'true', VAULT_INPUT_REQUESTS_ENABLED: 'true' };

async function expectNotFound(res: Response): Promise<void> {
  expect(res.status).toBe(404);
  expect(res.headers.get('Location')).toBeNull();
  expect(res.headers.get('Content-Type')).toContain('application/json');
  expect(((await res.json()) as { error: { code: string } }).error.code).toBe('not_found');
}

describe('input form redirect', () => {
  for (const method of ['GET', 'HEAD']) {
    it(`${method} /input redirects to /app/ uncached, with the security headers, when both flags are on`, async () => {
      const res = await fetchRaw('/input', { method, redirect: 'manual' }, ON);
      expect(res.status).toBe(302);
      expect(res.headers.get('Location')).toBe('/app/');
      expect(res.headers.get('Cache-Control')).toBe('no-store');
      expect(res.headers.get('Content-Security-Policy')).toBe(CONTENT_SECURITY_POLICY);
      expect(res.headers.get('X-Frame-Options')).toBe('DENY');
      expect(res.headers.get('Set-Cookie')).toBeNull();
    });
  }

  it('the query is not carried over, and the redirect never depends on it', async () => {
    const res = await fetchRaw('/input?x=1', { redirect: 'manual' }, ON);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/app/');
  });

  for (const value of [undefined, 'false', 'TRUE', '1', '']) {
    it(`is a 404 while VAULT_INPUT_REQUESTS_ENABLED is ${JSON.stringify(value)}`, async () => {
      await expectNotFound(await fetchRaw('/input', { redirect: 'manual' }, { VAULT_REMOTE_ACCESS_ENABLED: 'true', VAULT_INPUT_REQUESTS_ENABLED: value as string }));
    });
  }

  it('is a 404 while remote access is off, even with the input flag on', async () => {
    await expectNotFound(await fetchRaw('/input', { redirect: 'manual' }, { VAULT_REMOTE_ACCESS_ENABLED: 'false', VAULT_INPUT_REQUESTS_ENABLED: 'true' }));
  });

  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
    it(`refuses ${method} with a 404`, async () => {
      await expectNotFound(await fetchRaw('/input', { method, redirect: 'manual' }, ON));
    });
  }

  it('logs the route under the request method', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      await fetchRaw('/input', { redirect: 'manual' }, ON);
      await fetchRaw('/input', { method: 'POST', redirect: 'manual' }, ON);
      const lines = spy.mock.calls.map((c) => JSON.parse(String(c[0])) as { route: string; status: number });
      expect(lines).toEqual([expect.objectContaining({ route: 'GET /input', status: 302 }), expect.objectContaining({ route: 'POST /input', status: 404 })]);
    } finally {
      spy.mockRestore();
    }
  });

  it('only the exact path redirects', async () => {
    for (const path of ['/input/', '/input/x', '/inputs']) {
      const res = await fetchRaw(path, { redirect: 'manual' }, ON);
      expect(res.status, path).not.toBe(302);
    }
  });
});
