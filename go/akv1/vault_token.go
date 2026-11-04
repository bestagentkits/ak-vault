package akv1

// VaultTokenShortMaxSeconds is the longest lifetime (exp - iat, seconds) of a vault
// token served without a per-request revocation lookup (spec §9.3).
const VaultTokenShortMaxSeconds = 120

// IsShortLivedVaultToken reports whether exp - iat is positive and at most
// VaultTokenShortMaxSeconds.
func IsShortLivedVaultToken(iat, exp int64) bool {
	return exp > iat && exp-iat <= VaultTokenShortMaxSeconds
}

// ShortLivedVaultTokenUsable reports whether a short-lived token may be served at
// nowSeconds without a revocation lookup: only while now < exp, with no clock skew.
func ShortLivedVaultTokenUsable(iat, exp, nowSeconds int64) bool {
	return IsShortLivedVaultToken(iat, exp) && nowSeconds >= iat-60 && nowSeconds < exp
}
