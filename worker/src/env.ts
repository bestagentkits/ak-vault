/** Worker bindings. Names and values are owned by `wrangler.jsonc`. */
import type { AccountRelay } from './relay/account-relay-durable-object.js';
import type { RevocationRegistry } from './revocation/revocation-registry.js';
import type { VaultDurableObject } from './vault/vault-durable-object.js';

export interface Env {
  ASSETS: Fetcher;
  VAULT: DurableObjectNamespace<VaultDurableObject>;
  REVOCATIONS: DurableObjectNamespace<RevocationRegistry>;
  /** One relay object per account (`acct:<sub>`), spec §9.7. */
  RELAY: DurableObjectNamespace<AccountRelay>;
  /** Kill switch: the sync API serves only when exactly "true". */
  VAULT_SYNC_ENABLED: string;
  /**
   * Remote access (ADR 0002): `/app`, `/mcp`, protected-resource metadata, `/v1/relay`
   * and the lookup, seal-key and sealed-queue routes serve only when exactly "true".
   */
  VAULT_REMOTE_ACCESS_ENABLED?: string;
  /**
   * Device-sealed input requests (ADR 0004): the `/v1/vaults/:vid/input-requests/:rid`
   * routes, the item PUT `?input_request=` parameter and the device flow of
   * `secrets_request_input` serve only when exactly "true" and remote access is on.
   * Unset in every deployed environment until ak-web mints `input` session tokens.
   */
  VAULT_INPUT_REQUESTS_ENABLED?: string;
  /**
   * Refuse a new `role_set` without a signed log fence (spec §5). "false" in every
   * environment until the CLIs that sign the fence have replaced older ones; any
   * other value, or none, refuses (fail closed).
   */
  VAULT_REFUSE_LEGACY_ROLE_SET?: string;
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

/** Whether the remote-access routes serve (fail closed: anything but "true" is off). */
export function remoteAccessEnabled(env: Pick<Env, 'VAULT_REMOTE_ACCESS_ENABLED'>): boolean {
  return env.VAULT_REMOTE_ACCESS_ENABLED === 'true';
}

/** Whether the device-sealed input requests serve: remote access on and the input flag exactly "true" (fail closed). */
export function inputRequestsEnabled(env: Pick<Env, 'VAULT_REMOTE_ACCESS_ENABLED' | 'VAULT_INPUT_REQUESTS_ENABLED'>): boolean {
  return remoteAccessEnabled(env) && env.VAULT_INPUT_REQUESTS_ENABLED === 'true';
}

/** Whether a new unfenced `role_set` is refused (fail closed: anything but exactly "false" refuses). */
export function refuseLegacyRoleSet(env: Pick<Env, 'VAULT_REFUSE_LEGACY_ROLE_SET'>): boolean {
  return env.VAULT_REFUSE_LEGACY_ROLE_SET !== 'false';
}

/** The remote MCP resource, `<origin>/mcp` (spec §9.8). */
export function mcpResource(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `${env.VAULT_AUDIENCE}/mcp`;
}

/** The dashboard sign-in resource, `<origin>/app` (ADR 0002 D6). */
export function appResource(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `${env.VAULT_AUDIENCE}/app`;
}

/** The input-form session resource, `<origin>/input` (ADR 0004 D3): the audience of `input` session tokens. */
export function inputResource(env: Pick<Env, 'VAULT_AUDIENCE'>): string {
  return `${env.VAULT_AUDIENCE}/input`;
}

/** Origin of the token issuer (the authorization server the dashboard talks to). */
export function issuerOrigin(env: Pick<Env, 'VAULT_ISSUER'>): string {
  return new URL(env.VAULT_ISSUER).origin;
}

type WorkerEnv = Env;

declare global {
  namespace Cloudflare {
    // Types `env` from `cloudflare:workers` / `cloudflare:test` in tests.
    interface Env extends WorkerEnv {}
  }
}
