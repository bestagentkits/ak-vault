/**
 * Minimal same-origin client for the vault API (spec §9): a sync token as
 * bearer, a fresh `AKV-Proof` per attempt (single-use `jti`), and an
 * `Idempotency-Key` on writes that stays the same across a retry. A 401 gets
 * one retry with a freshly exchanged token. Errors carry only the status and the
 * server's stable code, never the response text.
 */
import { buildProofAsync, randomBytes, utf8Encode, b64encode, type DeviceSigner } from '@ak-vault/protocol';
import { AppError } from '../app-error.js';
import type { SyncToken } from '../vault/token-exchange.js';

export class VaultApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(`vault api ${status} ${code}`);
    this.name = 'VaultApiError';
  }
}

export function isVaultApiError(err: unknown, code?: string): err is VaultApiError {
  return err instanceof VaultApiError && (code === undefined || err.code === code);
}

export interface AkvClient {
  get(path: string): Promise<unknown>;
  put(path: string, body: unknown): Promise<unknown>;
  /** POST with an optional JSON body and no idempotency key (write-request actions are CAS transitions). */
  post(path: string, body?: unknown): Promise<unknown>;
}

export interface AkvClientDeps {
  origin: string;
  /** Return the sync token in force; `fresh` forces a new exchange. */
  getToken(fresh: boolean): Promise<SyncToken>;
  signer: DeviceSigner;
  fetchFn: typeof fetch;
  now?: () => number;
}

const STABLE_CODE = /^[a-z_]{1,64}$/;

async function errorCode(res: Response): Promise<string> {
  const body = (await res.json().catch(() => null)) as unknown;
  const err = typeof body === 'object' && body !== null ? (body as Record<string, unknown>)['error'] : undefined;
  const code = typeof err === 'object' && err !== null ? (err as Record<string, unknown>)['code'] : undefined;
  return typeof code === 'string' && STABLE_CODE.test(code) ? code : 'unknown';
}

export function newIdempotencyKey(): string {
  return b64encode(randomBytes(16));
}

export function createAkvClient(deps: AkvClientDeps): AkvClient {
  const now = deps.now ?? Date.now;

  async function send(method: 'GET' | 'PUT' | 'POST', path: string, body: unknown, idempotencyKey: string | null): Promise<unknown> {
    if (!path.startsWith('/v1/')) throw new AppError('server');
    const url = `${deps.origin}${path}`;
    const text = body === undefined ? '' : JSON.stringify(body);
    const bytes = utf8Encode(text);
    for (let attempt = 0; attempt < 2; attempt++) {
      const token = await deps.getToken(attempt > 0);
      const proof = await buildProofAsync({ htm: method, htu: url, ts: now(), token: token.token, body: bytes }, deps.signer);
      const headers: Record<string, string> = { Authorization: `Bearer ${token.token}`, 'AKV-Proof': proof };
      if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      let res: Response;
      try {
        res = await deps.fetchFn(url, { method, headers, credentials: 'omit', cache: 'no-store', ...(body !== undefined ? { body: text } : {}) });
      } catch {
        throw new AppError('network');
      }
      if (res.status === 401 && attempt === 0) continue;
      if (!res.ok) throw new VaultApiError(res.status, await errorCode(res));
      const json = (await res.json().catch(() => undefined)) as unknown;
      if (json === undefined) throw new AppError('server');
      return json;
    }
    throw new VaultApiError(401, 'unauthorized');
  }

  return {
    get: (path) => send('GET', path, undefined, null),
    put: (path, body) => send('PUT', path, body, newIdempotencyKey()),
    post: (path, body) => send('POST', path, body, null),
  };
}
