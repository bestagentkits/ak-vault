package akv1

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"strings"
)

// Signing contexts used by protocol v1 (closed set).
const (
	ContextMembership      = "akv1/membership"
	ContextRecord          = "akv1/record"
	ContextCheckpoint      = "akv1/checkpoint"
	ContextAuditCheckpoint = "akv1/audit-checkpoint"
	ContextProof           = "akv1/proof"
)

// KeyBytes is the size of Ed25519 seeds, X25519 secrets and all public keys.
const KeyBytes = 32

// SigningInput builds `utf8(context) || 0x0A || cjson(obj minus top-level "sig")`
// (spec §2). obj must be a map[string]any or a Valuer producing one.
func SigningInput(context string, obj any) ([]byte, error) {
	if context == "" || strings.Contains(context, "\n") {
		return nil, badRequest("invalid signing context")
	}
	m, err := asObject(obj, "signed value")
	if err != nil {
		return nil, badRequest("signed value must be an object")
	}
	rest := make(map[string]any, len(m))
	for k, v := range m {
		if k != "sig" {
			rest[k] = v
		}
	}
	body, err := CJSON(rest)
	if err != nil {
		return nil, err
	}
	return concatBytes([]byte(context), []byte{'\n'}, body), nil
}

// Kid returns `b64(SHA-256(utf8("akv1/kid") || 0x0A || pubkey)[0:16])`.
func Kid(publicKey []byte) string {
	return B64Encode(SHA256(concatBytes([]byte("akv1/kid\n"), publicKey))[:16])
}

// DeviceIDFromSignPub returns the device ID (kid) of a 32-byte Ed25519 public key.
func DeviceIDFromSignPub(signPub []byte) (string, error) {
	if len(signPub) != KeyBytes {
		return "", badRequest("sign_pub must be 32 bytes")
	}
	return Kid(signPub), nil
}

// DeviceIDFromSignPubB64 is DeviceIDFromSignPub for a b64 public key.
func DeviceIDFromSignPubB64(signPub string) (string, error) {
	b, err := B64Decode(signPub)
	if err != nil {
		return "", err
	}
	return DeviceIDFromSignPub(b)
}

// SignPublicKey derives the Ed25519 public key from a 32-byte seed.
func SignPublicKey(seed []byte) ([]byte, error) {
	if len(seed) != KeyBytes {
		return nil, badRequest("secret key must be 32 bytes")
	}
	return []byte(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), nil
}

// KxPublicKey derives the X25519 public key from a 32-byte secret (RFC 7748).
func KxPublicKey(secret []byte) ([]byte, error) {
	if len(secret) != KeyBytes {
		return nil, badRequest("secret key must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		return nil, badRequest("invalid X25519 secret")
	}
	return priv.PublicKey().Bytes(), nil
}

// SignDetached signs obj (minus "sig") under context with an Ed25519 seed and
// returns the b64 signature.
func SignDetached(context string, obj any, seed []byte) (string, error) {
	if len(seed) != KeyBytes {
		return "", badRequest("secret key must be 32 bytes")
	}
	msg, err := SigningInput(context, obj)
	if err != nil {
		return "", err
	}
	return B64Encode(ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)), nil
}

// VerifyDetached reports whether sig (b64) is a valid Ed25519 signature of
// obj under context by publicKey (raw 32 bytes), using the strict rules of
// verifyEd25519Strict. Malformed input returns false.
func VerifyDetached(context string, obj any, sig string, publicKey []byte) bool {
	sigBytes, err := B64Decode(sig)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	msg, err := SigningInput(context, obj)
	if err != nil {
		return false
	}
	return verifyEd25519Strict(publicKey, msg, sigBytes)
}

// VerifyObject verifies obj["sig"] with a b64 public key; failure is CodeInvalidSignature.
func VerifyObject(context string, obj any, publicKeyB64 string) error {
	m, err := asObject(obj, "signed value")
	if err != nil {
		return newErr(CodeInvalidSignature, "%s: signature verification failed", context)
	}
	sig, ok := m["sig"].(string)
	pub, decErr := B64Decode(publicKeyB64)
	if !ok || decErr != nil || !VerifyDetached(context, m, sig, pub) {
		return newErr(CodeInvalidSignature, "%s: signature verification failed", context)
	}
	return nil
}
