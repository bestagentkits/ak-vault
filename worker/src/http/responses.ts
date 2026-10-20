/** Response builders: JSON API responses and the security headers applied to every response. */
import { issuerOrigin, type Env } from '../env.js';
import type { ApiResult } from './errors.js';

/** Content-Security-Policy for the landing site and API: same-origin only, no inline script or style. */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'none'",
].join('; ');

/**
 * CSP of the dashboard at `/app` (ADR 0002 D1): nothing by default, same-origin
 * scripts and styles only, Trusted Types for script sinks, and `connect-src`
 * widened only to the authorization server it signs in with.
 */
export function appContentSecurityPolicy(env: Pick<Env, 'VAULT_ISSUER'>): string {
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${issuerOrigin(env)}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "require-trusted-types-for 'script'",
    // The bundle writes text only (`textContent`), so no Trusted Types policy may exist at all.
    "trusted-types 'none'",
  ].join('; ');
}

/** Whether `pathname` is the dashboard (`/app` or below). */
export function isAppPath(pathname: string): boolean {
  return pathname === '/app' || pathname.startsWith('/app/');
}

/** The CSP for a path: the dashboard's for `/app*`, the default everywhere else. */
export function cspFor(pathname: string, env: Pick<Env, 'VAULT_ISSUER'>): string {
  return isAppPath(pathname) ? appContentSecurityPolicy(env) : CONTENT_SECURITY_POLICY;
}

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  'X-Frame-Options': 'DENY',
};

/** Dashboard documents are never cached, so a fixed asset set always matches its SRI hashes. */
function isAppDocument(pathname: string): boolean {
  return pathname === '/app' || pathname === '/app/' || pathname === '/app/index.html';
}

/**
 * Return a copy of `response` with the security headers set. With `path`, a
 * dashboard path also gets its CSP, cross-origin isolation of the window and
 * resources, and `no-store` on its document.
 */
export function withSecurityHeaders(response: Response, path?: { pathname: string; env: Pick<Env, 'VAULT_ISSUER'> }): Response {
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value);
  if (path && isAppPath(path.pathname)) {
    out.headers.set('Content-Security-Policy', cspFor(path.pathname, path.env));
    out.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
    out.headers.set('Cross-Origin-Resource-Policy', 'same-origin');
    // The OAuth callback URL carries a code and state; no request from the dashboard sends a referrer.
    out.headers.set('Referrer-Policy', 'no-referrer');
    // `no-transform` also keeps the proxy from injecting a beacon script into the document.
    if (isAppDocument(path.pathname)) out.headers.set('Cache-Control', 'no-store, no-transform');
  }
  return out;
}

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

export function resultResponse(result: ApiResult): Response {
  return jsonResponse(result.body, result.status, result.headers ?? {});
}
