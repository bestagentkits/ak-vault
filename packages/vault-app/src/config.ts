/**
 * Dashboard configuration: what the Worker serves at `/app/config.json`, checked
 * against the page's own origin. Every URL the dashboard signs in with is derived
 * from the origin (ADR 0002 D6); only the issuer comes from the server.
 */
import { AppError } from './app-error.js';

export interface AppConfig {
  /** Vault origin: the sync tokens' audience and the API base. */
  origin: string;
  /** ak-web authorization server issuer (exact string, RFC 8414). */
  issuer: string;
  /** `<origin>/app/client.json`, the Client ID Metadata Document URL. */
  clientId: string;
  /** `<origin>/app/`, the one registered redirect URI. */
  redirectUri: string;
  /** `<origin>/app`, the OAuth resource (RFC 8707). */
  resource: string;
  scope: 'vault-app:session';
}

export const APP_SCOPE = 'vault-app:session';

function isHttpsOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
    return url.origin === value.replace(/\/$/, '') && (url.protocol === 'https:' || (url.protocol === 'http:' && loopback));
  } catch {
    return false;
  }
}

/** Validate the served config for a page at `origin` (fail closed: anything unexpected is `config_invalid`). */
export function parseAppConfig(value: unknown, origin: string): AppConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new AppError('config_invalid');
  const obj = value as Record<string, unknown>;
  const expected = {
    client_id: `${origin}/app/client.json`,
    redirect_uri: `${origin}/app/`,
    resource: `${origin}/app`,
    scope: APP_SCOPE,
  };
  if (obj['v'] !== 1) throw new AppError('config_invalid');
  for (const [key, want] of Object.entries(expected)) if (obj[key] !== want) throw new AppError('config_invalid');
  const issuer = obj['issuer'];
  if (typeof issuer !== 'string' || !isHttpsOrigin(issuer) || !isHttpsOrigin(origin)) throw new AppError('config_invalid');
  return { origin, issuer, clientId: expected.client_id, redirectUri: expected.redirect_uri, resource: expected.resource, scope: APP_SCOPE };
}

export async function loadAppConfig(fetchFn: typeof fetch, origin: string): Promise<AppConfig> {
  let res: Response;
  try {
    res = await fetchFn(`${origin}/app/config.json`, { credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new AppError('network');
  }
  if (!res.ok) throw new AppError('config_invalid');
  return parseAppConfig(await res.json().catch(() => null), origin);
}
