package main

// The vault token route (spec §9.1, the client side is agentkit's
// akvhttp/vault_token_source.go). The CLI posts its CLI session as the
// bearer and a body signed with its device key; the token is bound to the
// session ID (sid), the device key (did = kid(sign_pub)) and the requested
// scope. Ported from agentkit's in-process e2e fake registry.

import (
	"net/http"
	"strings"
	"time"

	"github.com/bestagentkits/ak-vault/go/akv1"
)

const (
	tokenRoute          = "/api/agentkit/vault/token" //nolint:gosec // a route path, not a credential
	tokenRequestContext = "akv1/vault-token-request"  //nolint:gosec // a signing context label
	maxTokenRequestSkew = 60 * time.Second
)

// vaultTokenRequest is the signed body the CLI posts.
type vaultTokenRequest struct {
	SignPub string   `json:"sign_pub"`
	Scope   []string `json:"scope"`
	TS      int64    `json:"ts"`
	Sig     string   `json:"sig"`
}

func (s *server) handleVaultToken(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	now := s.now()
	sess, err := s.accounts.authenticate(bearer, now)
	if err != nil {
		// The CLI renews its session on not_authenticated and retries once.
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	var tr vaultTokenRequest
	if err := decodeStrict(r, &tr); err != nil || tr.SignPub == "" || tr.Sig == "" || len(tr.Scope) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !validScope(tr.Scope) {
		writeError(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	if d := now.Sub(time.Unix(tr.TS, 0)); d > maxTokenRequestSkew || d < -maxTokenRequestSkew {
		writeError(w, http.StatusBadRequest, "stale_request")
		return
	}
	pub, err := akv1.B64Decode(tr.SignPub)
	signed := map[string]any{"aud": s.issuer.audience, "scope": tr.Scope, "sid": sess.sid, "sign_pub": tr.SignPub, "ts": tr.TS}
	if err != nil || len(pub) != 32 || !akv1.VerifyDetached(tokenRequestContext, signed, tr.Sig, pub) {
		writeError(w, http.StatusUnauthorized, "invalid_signature")
		return
	}
	did := akv1.Kid(pub)
	if s.accounts.deviceRevoked(did) {
		writeError(w, http.StatusForbidden, "device_revoked")
		return
	}
	token, err := s.issuer.mint(tokenClaims{account: sess.account, sid: sess.sid, did: did, scope: tr.Scope}, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "vault_unavailable")
		return
	}
	s.accounts.countMint()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": int64(vaultTokenLifetime / time.Second), "did": did,
	})
}

// validScope accepts a non-empty set of vault scopes without duplicates.
func validScope(scope []string) bool {
	seen := map[string]bool{}
	for _, sc := range scope {
		if sc != "vault:read" && sc != "vault:write" || seen[sc] {
			return false
		}
		seen[sc] = true
	}
	return len(seen) > 0
}
