/**
 * Issuer public keys (JWKS). Source: `VAULT_JWKS_JSON` (inline, staging/tests) or
 * `VAULT_JWKS_URL` (production, fetched and cached for 5 minutes). Only P-256
 * signing keys with a `kid` are imported; anything else is ignored. Every load
 * failure is fail-closed: the caller gets an error and the request is refused.
 */
import { ApiError } from '../http/errors.js';

const CACHE_TTL_MS = 5 * 60_000;
/** An unknown `kid` triggers a refetch at most this often (key rotation). */
const MISS_REFETCH_MS = 30_000;
const FETCH_TIMEOUT_MS = 5_000;
const MAX_JWKS_BYTES = 64 * 1024;

export type KeySet = Map<string, CryptoKey>;

interface CacheEntry {
  source: string;
  keys: KeySet;
  loadedAt: number;
}

// Module-level cache: shared by requests in one isolate, rebuilt after eviction.
let cache: CacheEntry | undefined;

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
    const res = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) throw unavailable();
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
  if (!fresh) {
    const loaded = await load(env);
    cache = { ...loaded, loadedAt: now };
  }
  const hit = cache!.keys.get(kid);
  if (hit || source.startsWith('inline:') || now - cache!.loadedAt < MISS_REFETCH_MS) return hit;
  const loaded = await load(env);
  cache = { ...loaded, loadedAt: now };
  return cache.keys.get(kid);
}

/** Test hook: drop the cached key set. */
export function clearJwksCache(): void {
  cache = undefined;
}
