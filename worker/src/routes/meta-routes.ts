/** Public, unauthenticated endpoints: `/healthz` and `/v1/meta`. Both work with the kill switch on. */
import { remoteAccessEnabled, type Env } from '../env.js';
import { okResult, type ApiResult } from '../http/errors.js';
import { LIMITS, PROTOCOL_VERSIONS, REMOTE_ACCESS_LIMITS, WORKER_VERSION } from '../limits.js';

export function syncEnabled(env: Pick<Env, 'VAULT_SYNC_ENABLED'>): boolean {
  return env.VAULT_SYNC_ENABLED === 'true';
}

export function healthz(env: Env): ApiResult {
  return okResult({ ok: true, version: WORKER_VERSION, protocol: PROTOCOL_VERSIONS[0], sync_enabled: syncEnabled(env), remote_access: remoteAccessEnabled(env) });
}

export function meta(env: Env): ApiResult {
  const remote = remoteAccessEnabled(env);
  return okResult({
    version: WORKER_VERSION,
    protocol_versions: PROTOCOL_VERSIONS,
    sync_enabled: syncEnabled(env),
    remote_access: remote,
    // Remote-access limits appear only where the routes serve (spec §3.7: writers key off `lookup_tags_max`).
    limits: remote ? { ...LIMITS, ...REMOTE_ACCESS_LIMITS } : LIMITS,
    auth: {
      token_alg: 'ES256',
      issuer: env.VAULT_ISSUER,
      audience: env.VAULT_AUDIENCE,
      scopes: ['vault:read', 'vault:write'],
      proof_header: 'AKV-Proof',
      idempotency_header: 'Idempotency-Key',
    },
  });
}
