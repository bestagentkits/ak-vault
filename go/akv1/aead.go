package akv1

import (
	"crypto/rand"
	"regexp"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD envelope limits (spec §3.1).
const (
	MaxPlaintextBytes = 65536
	NonceBytes        = chacha20poly1305.NonceSizeX // 24
	TagBytes          = chacha20poly1305.Overhead   // 16
)

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Envelope is the XChaCha20-Poly1305 envelope
// {"v":1,"alg":"xc20p","kid","n","ct"} (spec §3.1). N and Ct are b64.
type Envelope struct {
	Kid string
	N   string
	Ct  string
}

// JSONValue returns the wire object.
func (e Envelope) JSONValue() any {
	return map[string]any{"v": int64(1), "alg": "xc20p", "kid": e.Kid, "n": e.N, "ct": e.Ct}
}

// SealOptions configures SealEnvelope. Nonce is nil in production (24 random
// bytes are drawn); tests inject a fixed nonce to reproduce vectors.
type SealOptions struct {
	Kid   string
	Nonce []byte
}

// EpochTag returns the envelope kid for vault-key-derived keys: "e<key_epoch>".
func EpochTag(keyEpoch int64) (string, error) {
	if keyEpoch < 1 || keyEpoch > MaxSafeInteger {
		return "", badRequest("key_epoch must be a positive integer")
	}
	return "e" + strconv.FormatInt(keyEpoch, 10), nil
}

var epochTagPattern = regexp.MustCompile(`^e([1-9][0-9]{0,15})$`)

// ParseEpochTag is the inverse of EpochTag: the key epoch named by an
// "e<key_epoch>" kid (bad_request otherwise).
func ParseEpochTag(kid string) (int64, error) {
	m := epochTagPattern.FindStringSubmatch(kid)
	if m == nil {
		return 0, badRequest("envelope kid is not an epoch tag")
	}
	epoch, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || epoch > MaxSafeInteger {
		return 0, badRequest("envelope kid is not an epoch tag")
	}
	return epoch, nil
}

// randomBytes returns n bytes from crypto/rand. Since Go 1.24 crypto/rand.Read
// never returns an error (it aborts the program if the OS source fails).
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// RandomID returns a fresh opaque ID: b64 of 16 random bytes.
func RandomID() string { return B64Encode(randomBytes(IDBytes)) }

func checkAEADKey(key []byte) error {
	if len(key) != chacha20poly1305.KeySize {
		return badRequest("AEAD key must be 32 bytes")
	}
	return nil
}

// XC20PSeal encrypts plaintext (ct||tag) with AAD = cjson(aad).
func XC20PSeal(key, nonce, plaintext []byte, aad any) ([]byte, error) {
	if err := checkAEADKey(key); err != nil {
		return nil, err
	}
	if len(nonce) != NonceBytes {
		return nil, badRequest("nonce must be 24 bytes")
	}
	if len(plaintext) > MaxPlaintextBytes {
		return nil, badRequest("plaintext exceeds 65536 bytes")
	}
	aadBytes, err := CJSON(aad)
	if err != nil {
		return nil, err
	}
	aeadCipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, badRequest("AEAD key must be 32 bytes")
	}
	return aeadCipher.Seal(nil, nonce, plaintext, aadBytes), nil
}

// XC20POpen decrypts ct||tag with AAD = cjson(aad). Authentication failure is
// CodeDecryptFailed.
func XC20POpen(key, nonce, ciphertext []byte, aad any) ([]byte, error) {
	if err := checkAEADKey(key); err != nil {
		return nil, err
	}
	if len(nonce) != NonceBytes {
		return nil, badRequest("nonce must be 24 bytes")
	}
	if len(ciphertext) < TagBytes || len(ciphertext) > MaxPlaintextBytes+TagBytes {
		return nil, badRequest("ciphertext length out of range")
	}
	aadBytes, err := CJSON(aad)
	if err != nil {
		return nil, err
	}
	aeadCipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, badRequest("AEAD key must be 32 bytes")
	}
	pt, err := aeadCipher.Open(nil, nonce, ciphertext, aadBytes)
	if err != nil {
		return nil, newErr(CodeDecryptFailed, "AEAD authentication failed")
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}

// ParseEnvelope validates an untrusted envelope (version and alg fail closed).
func ParseEnvelope(v any) (Envelope, error) { return parseEnvelopeAs(v, "envelope") }

func parseEnvelopeAs(v any, what string) (Envelope, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return Envelope{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return Envelope{}, err
	}
	if obj["alg"] != "xc20p" {
		return Envelope{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "kid", "n", "ct"}, what); err != nil {
		return Envelope{}, err
	}
	kid, ok := obj["kid"].(string)
	if !ok || !kidPattern.MatchString(kid) {
		return Envelope{}, badRequest("%s.kid is invalid", what)
	}
	n, err := asB64(obj["n"], what+".n", NonceBytes)
	if err != nil {
		return Envelope{}, err
	}
	ct, err := asB64(obj["ct"], what+".ct", -1)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Kid: kid, N: n, Ct: ct}, nil
}

// SealEnvelope encrypts plaintext under key with AAD cjson(aad).
func SealEnvelope(key, plaintext []byte, aad any, opts SealOptions) (Envelope, error) {
	if !kidPattern.MatchString(opts.Kid) {
		return Envelope{}, badRequest("envelope kid is invalid")
	}
	nonce := opts.Nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	ct, err := XC20PSeal(key, nonce, plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Kid: opts.Kid, N: B64Encode(nonce), Ct: B64Encode(ct)}, nil
}

// OpenEnvelope parses an untrusted envelope and decrypts it. When expectedKid
// is non-empty the envelope kid must equal it (CodeBadRequest otherwise).
func OpenEnvelope(key []byte, envelope any, aad any, expectedKid string) ([]byte, error) {
	env, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if expectedKid != "" && env.Kid != expectedKid {
		return nil, badRequest("envelope kid mismatch")
	}
	return openParsedEnvelope(key, env, aad)
}

func openParsedEnvelope(key []byte, env Envelope, aad any) ([]byte, error) {
	nonce, err := B64Decode(env.N)
	if err != nil {
		return nil, err
	}
	ct, err := B64Decode(env.Ct)
	if err != nil {
		return nil, err
	}
	return XC20POpen(key, nonce, ct, aad)
}

// AssertUniqueNonces rejects (CodeBadRequest) a batch of envelopes produced
// under the same key that reuses a nonce.
func AssertUniqueNonces(envelopes []Envelope) error {
	seen := make(map[string]bool, len(envelopes))
	for _, e := range envelopes {
		if seen[e.N] {
			return badRequest("duplicate nonce under the same key")
		}
		seen[e.N] = true
	}
	return nil
}
