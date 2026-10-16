/** Worker bindings. Names and values are owned by `wrangler.jsonc`. */
import type { RevocationRegistry } from './revocation/revocation-registry.js';
import type { VaultDurableObject } from './vault/vault-durable-object.js';

export interface Env {
  ASSETS: Fetcher;
  VAULT: DurableObjectNamespace<VaultDurableObject>;
  REVOCATIONS: DurableObjectNamespace<RevocationRegistry>;
  /** Kill switch: the sync API serves only when exactly "true". */
  VAULT_SYNC_ENABLED: string;
  VAULT_ISSUER: string;
  VAULT_AUDIENCE: string;
  /** JWKS endpoint; used when `VAULT_JWKS_JSON` is unset. */
  VAULT_JWKS_URL?: string;
  /** Inline public JWKS (integration tests only). Takes precedence over the URL. */
  VAULT_JWKS_JSON?: string;
  /** HMAC key for the revocation webhook (secret, never in config). */
  REVOCATION_WEBHOOK_SECRET?: string;
  /** Previous HMAC key, accepted only during a rotation overlap (secret). */
  REVOCATION_WEBHOOK_SECRET_PREVIOUS?: string;
  /**
   * HMAC key for the operator restore route (secret, never in config). Unset by
   * default: the route then answers 404. Set only for a restore, then delete.
   */
  VAULT_OPERATOR_SECRET?: string;
}

type WorkerEnv = Env;

declare global {
  namespace Cloudflare {
    // Types `env` from `cloudflare:workers` / `cloudflare:test` in tests.
    interface Env extends WorkerEnv {}
  }
}
