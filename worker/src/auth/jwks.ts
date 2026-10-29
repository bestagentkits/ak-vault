/**
 * Issuer public keys (JWKS). Source: `VAULT_JWKS_JSON` (inline, tests) or
 * `VAULT_JWKS_URL` (deployed environments, fetched and cached for 5 minutes). Only P-256
 * signing keys with a `kid` are imported; anything else is ignored. Every load
 * failure is fail-closed: the caller gets an error and the request is refused.
 * A failed load is remembered for 30 s (negative cache) so an issuer outage does
 * not cost every request another outbound fetch; during that window requests are
 * refused immediately. Stale keys are never served after their TTL.
 * Redirects are never followed: the configured URL alone pins the key source, so a
 * 3xx (or an opaque redirect) is a load failure like any other, whatever its target.
 */
import { ApiError } from '../http/errors.js';

const CACHE_TTL_MS = 5 * 60_000;
/** An unknown `kid` triggers a refetch at most this often (key rotation). */
const MISS_REFETCH_MS = 30_000;
const FETCH_TIMEOUT_MS = 5_000;
/** After a failed load, refuse without refetching for this long. */
const FAILURE_BACKOFF_MS = 30_000;
const MAX_JWKS_BYTES = 64 * 1024;

export type KeySet = Map<string, CryptoKey>;

interface CacheEntry {
  source: string;
  keys: KeySet;
  loadedAt: number;
}

// Module-level cache: shared by requests in one isolate, rebuilt after eviction.
let cache: CacheEntry | undefined;
let lastFailure: { source: string; at: number } | undefined;

function unavailable(): ApiError {
  return new ApiError('unauthorized', { status: 503, message: 'token keys unavailable', headers: { 'Retry-After': '5' } });
}

async function importKeys(jwks: unknown): Promise<KeySet> {
  const keys: KeySet = new Map();
  const list = (jwks as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(list)) throw unavailable();
  for (const raw of list.slice(0, 32)) {
    if (typeof raw !== 'object' || raw === null) continue;
    const jwk = raw as Record<string, unknown>;
    if (jwk['kty'] !== 'EC' || jwk['crv'] !== 'P-256' || typeof jwk['kid'] !== 'string' || jwk['kid'].length === 0) continue;
    if (jwk['alg'] !== undefined && jwk['alg'] !== 'ES256') continue;
    if (jwk['use'] !== undefined && jwk['use'] !== 'sig') continue;
    if (typeof jwk['x'] !== 'string' || typeof jwk['y'] !== 'string' || jwk['d'] !== undefined) continue;
    try {
      const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk['x'], y: jwk['y'], ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      keys.set(jwk['kid'], key);
    } catch {
      // Malformed key material: skip it; a token naming this kid is then refused.
    }
  }
  return keys;
}

async function load(env: { VAULT_JWKS_JSON?: string; VAULT_JWKS_URL?: string }): Promise<{ source: string; keys: KeySet }> {
  if (env.VAULT_JWKS_JSON) {
    try {
      return { source: `inline:${env.VAULT_JWKS_JSON}`, keys: await importKeys(JSON.parse(env.VAULT_JWKS_JSON)) };
    } catch {
      throw unavailable();
    }
  }
  const url = env.VAULT_JWKS_URL;
  if (!url || !url.startsWith('https://')) throw unavailable();
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json' }, redirect: 'manual', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    // With `manual`, workerd returns a 3xx as is and a WHATWG fetch returns an opaque
    // redirect (status 0): only a direct 200 is accepted, so both are refused.
    if (res.status !== 200 || res.redirected) {
      await res.body?.cancel(); // release the refused response instead of leaving it stalled
      throw unavailable();
    }
    const text = await res.text();
    if (text.length > MAX_JWKS_BYTES) throw unavailable();
    return { source: `url:${url}`, keys: await importKeys(JSON.parse(text)) };
  } catch {
    throw unavailable();
  }
}

/** Resolve the verification key for `kid`, or `undefined` if the current JWKS lacks it. */
export async function getIssuerKey(env: { VAULT_JWKS_JSON?: string; VAULT_JWKS_URL?: string }, kid: string, now = Date.now()): Promise<CryptoKey | undefined> {
  const source = env.VAULT_JWKS_JSON ? `inline:${env.VAULT_JWKS_JSON}` : `url:${env.VAULT_JWKS_URL ?? ''}`;
  const fresh = cache && cache.source === source && now - cache.loadedAt < CACHE_TTL_MS;
  if (!fresh) await refresh(env, source, now);
  const hit = cache!.keys.get(kid);
  if (hit || source.startsWith('inline:') || now - cache!.loadedAt < MISS_REFETCH_MS) return hit;
  await refresh(env, source, now);
  return cache!.keys.get(kid);
}

/**
 * Load the key set, honouring the failure backoff. A failure leaves `cache` as is:
 * an expired entry is never consulted (the TTL check gates it), and a still-fresh
 * entry stays valid when only an unknown-kid refetch failed.
 */
async function refresh(env: { VAULT_JWKS_JSON?: string; VAULT_JWKS_URL?: string }, source: string, now: number): Promise<void> {
  if (lastFailure && lastFailure.source === source && now - lastFailure.at < FAILURE_BACKOFF_MS) throw unavailable();
  try {
    cache = { ...(await load(env)), loadedAt: now };
    lastFailure = undefined;
  } catch (err) {
    lastFailure = { source, at: now };
    throw err;
  }
}

/** Test hook: drop the cached key set and any remembered load failure. */
export function clearJwksCache(): void {
  cache = undefined;
  lastFailure = undefined;
}
