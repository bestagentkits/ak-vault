/** vault-token-lifetime.json */
import { isShortLivedVaultToken, shortLivedVaultTokenUsable, VAULT_TOKEN_SHORT_MAX_SECONDS } from '../../src/index.js';

const IAT = 1_800_000_000;

export function vaultTokenLifetimeVectors(): Record<string, unknown> {
  const lifetimes: [number, number][] = [
    [IAT, IAT + 1],
    [IAT, IAT + 60],
    [IAT, IAT + VAULT_TOKEN_SHORT_MAX_SECONDS],
    [IAT, IAT + VAULT_TOKEN_SHORT_MAX_SECONDS + 1],
    [IAT, IAT + 300],
    [IAT, IAT],
    [IAT, IAT - 1],
  ];
  const usableAt: [number, number, number][] = [
    [IAT, IAT + 120, IAT],
    [IAT, IAT + 120, IAT + 119],
    [IAT, IAT + 120, IAT + 120],
    [IAT, IAT + 120, IAT + 150],
    [IAT, IAT + 120, IAT - 60],
    [IAT, IAT + 120, IAT - 61],
    [IAT, IAT + 300, IAT + 10],
  ];
  return {
    version: 1,
    description: 'Vault token lifetime classes (spec §9.3): short-lived tokens are served without a per-request revocation lookup only while now < exp.',
    short_max_seconds: VAULT_TOKEN_SHORT_MAX_SECONDS,
    lifetime: lifetimes.map(([iat, exp]) => ({ iat, exp, short: isShortLivedVaultToken(iat, exp) })),
    usable: usableAt.map(([iat, exp, now]) => ({ iat, exp, now, usable: shortLivedVaultTokenUsable(iat, exp, now) })),
  };
}
