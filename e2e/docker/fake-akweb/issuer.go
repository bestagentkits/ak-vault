package main

// The ephemeral ES256 issuer: its public half is the JWKS the Worker
// trusts (VAULT_JWKS_JSON), and it signs every vault token.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/bestagentkits/ak-vault/go/akv1"
)

// vaultTokenLifetime matches ak-web: 300 s tokens.
const vaultTokenLifetime = 300 * time.Second

type issuer struct {
	key      *ecdsa.PrivateKey
	kid      string
	origin   string // iss
	audience string // aud
}

func newIssuer(origin, audience string) (*issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("issuer key: %w", err)
	}
	return &issuer{key: key, kid: "e2e-" + akv1.RandomID(), origin: origin, audience: audience}, nil
}

// jwks is the public key set.
func (i *issuer) jwks() map[string]any {
	pub := i.key.PublicKey
	return map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": i.kid,
		"x": b64url(pad32(pub.X)), "y": b64url(pad32(pub.Y)),
	}}}
}

// tokenClaims are the identity a vault token is bound to.
type tokenClaims struct {
	account string
	sid     string
	did     string
	scope   []string
}

// mint signs an ES256 at+jwt with the claims spec §9.1 requires.
func (i *issuer) mint(c tokenClaims, now time.Time) (string, error) {
	iat := now.Unix()
	header := map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": i.kid}
	claims := map[string]any{
		"iss": i.origin, "aud": i.audience, "sub": c.account, "sid": c.sid, "did": c.did,
		"scope": strings.Join(c.scope, " "), "jti": akv1.RandomID(),
		"iat": iat, "nbf": iat, "exp": iat + int64(vaultTokenLifetime/time.Second),
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64url(h) + "." + b64url(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64url(append(pad32(r), pad32(s)...)), nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 is n as a 32-byte big-endian integer (a P-256 coordinate or scalar).
func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	return n.FillBytes(out)
}
