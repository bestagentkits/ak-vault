/**
 * Landing site delivery through the assets binding. The Worker runs first for
 * every request (`run_worker_first: true`) so static responses get the same
 * security headers as the API, and Markdown twins get an explicit UTF-8
 * `text/markdown` type. `no-transform` keeps the Cloudflare proxy from rewriting
 * pages, e.g. a zone-wide Web Analytics beacon the CSP would block anyway.
 */
import type { Env } from '../env.js';
import { withSecurityHeaders } from './responses.js';

export async function serveAsset(request: Request, env: Pick<Env, 'ASSETS'>): Promise<Response> {
  const response = await env.ASSETS.fetch(request);
  const out = withSecurityHeaders(response);
  const { pathname } = new URL(request.url);
  out.headers.set('Cache-Control', withNoTransform(response.headers.get('Cache-Control')));
  if (pathname.endsWith('.md') && response.ok) out.headers.set('Content-Type', 'text/markdown; charset=utf-8');
  if (pathname === '/llms.txt' && response.ok) out.headers.set('Content-Type', 'text/plain; charset=utf-8');
  return out;
}

function withNoTransform(cacheControl: string | null): string {
  if (!cacheControl) return 'no-transform';
  return /(^|,)\s*no-transform\s*(,|$)/i.test(cacheControl) ? cacheControl : `${cacheControl}, no-transform`;
}
