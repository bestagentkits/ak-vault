package akv1

import (
	"crypto/sha256"
	"encoding/base64"
)

// b64 is unpadded base64url with strict decoding: Go's Strict mode rejects
// non-zero trailing bits, and NoPadding rejects "=", so every byte string has
// exactly one accepted encoding (spec §2).
var b64 = base64.RawURLEncoding.Strict()

// B64Encode encodes bytes as base64url without padding.
func B64Encode(data []byte) string {
	return b64.EncodeToString(data)
}

// B64Decode strictly decodes base64url without padding. Padding, characters
// outside the URL-safe alphabet (including CR/LF, which the standard library
// would otherwise skip), impossible lengths and non-canonical trailing bits
// are all CodeBadRequest.
func B64Decode(text string) ([]byte, error) {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, badRequest("invalid base64url character")
		}
	}
	if len(text)%4 == 1 {
		return nil, badRequest("invalid base64url length")
	}
	out, err := b64.DecodeString(text)
	if err != nil {
		return nil, badRequest("non-canonical base64url trailing bits")
	}
	return out, nil
}

// B64DecodeLength decodes text and requires exactly length bytes.
func B64DecodeLength(text string, length int, what string) ([]byte, error) {
	out, err := B64Decode(text)
	if err != nil {
		return nil, err
	}
	if len(out) != length {
		return nil, badRequest("%s must be %d bytes", what, length)
	}
	return out, nil
}

// SHA256 returns the SHA-256 digest of data.
func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// SHA256B64 returns b64(SHA-256(data)), the digest form used throughout the protocol.
func SHA256B64(data []byte) string {
	return B64Encode(SHA256(data))
}

func concatBytes(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func isAllZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
