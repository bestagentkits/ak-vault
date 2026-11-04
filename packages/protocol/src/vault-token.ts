/**
 * Vault token lifetime classes (spec §9 item 3). A short-lived token (lifetime at most
 * {@link VAULT_TOKEN_SHORT_MAX_SECONDS}) had device revocation checked when it was
 * issued, so a server may accept it without a per-request revocation lookup, and only
 * while `now < exp` (no clock skew), so a revocation takes effect within the lifetime.
 * Any other token keeps the per-request revocation check.
 */

/** Longest lifetime (`exp - iat`, seconds) of a token served without a per-request revocation lookup. */
export const VAULT_TOKEN_SHORT_MAX_SECONDS = 120;

/** True when `exp - iat` is positive and at most {@link VAULT_TOKEN_SHORT_MAX_SECONDS}. */
export function isShortLivedVaultToken(iat: number, exp: number): boolean {
  return Number.isSafeInteger(iat) && Number.isSafeInteger(exp) && exp > iat && exp - iat <= VAULT_TOKEN_SHORT_MAX_SECONDS;
}

/**
 * True when a short-lived token may be served at `nowSeconds` without a revocation lookup:
 * `now < exp` and `exp - now` at most the short lifetime, so an issuer clock running fast
 * cannot stretch the time since its revocation check past {@link VAULT_TOKEN_SHORT_MAX_SECONDS}.
 */
export function shortLivedVaultTokenUsable(iat: number, exp: number, nowSeconds: number): boolean {
  return isShortLivedVaultToken(iat, exp) && nowSeconds >= iat - 60 && nowSeconds < exp && exp - nowSeconds <= VAULT_TOKEN_SHORT_MAX_SECONDS;
}
