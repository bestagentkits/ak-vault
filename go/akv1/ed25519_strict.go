package akv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
)

// Strict RFC 8032 Ed25519 verification shared by every akv1 implementation
// (spec §11). crypto/ed25519 already rejects S >= L and uses the cofactorless
// equation with a byte comparison of R (so a non-canonical R never verifies),
// but it decodes non-canonical public key encodings and accepts small-order
// public keys, for which signatures can be forged without a secret key. These
// encoding checks close that gap; they are input validation, not new
// cryptography.

// ed25519L is the group order L in little-endian bytes.
var ed25519L = mustHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

// ed25519PMinus1 is p - 1 = 2^255 - 20 in little-endian bytes.
var ed25519PMinus1 = mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

// smallOrderEncodings are the canonical encodings of the eight points of the
// Ed25519 torsion subgroup (orders 1, 2, 4 and 8).
var smallOrderEncodings = [][]byte{
	mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("0000000000000000000000000000000000000000000000000000000000000000"),
	mustHex("0000000000000000000000000000000000000000000000000000000000000080"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// lessLE reports a < b for equal-length little-endian integers.
func lessLE(a, b []byte) bool {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// canonicalPointEncoding reports whether a 32-byte point encoding is the
// unique RFC 8032 §5.1.2 encoding: y < p, and the sign bit is clear when
// x = 0 (y = 1 or y = p-1). Whether the point is on the curve is left to
// crypto/ed25519.
func canonicalPointEncoding(enc []byte) bool {
	y := bytes.Clone(enc)
	sign := y[31] >> 7
	y[31] &= 0x7f
	if !lessLE(y, ed25519PMinus1) && !bytes.Equal(y, ed25519PMinus1) {
		return false // y >= p
	}
	if sign == 1 {
		one := make([]byte, 32)
		one[0] = 1
		if bytes.Equal(y, one) || bytes.Equal(y, ed25519PMinus1) {
			return false // x = 0 with the sign bit set ("negative zero")
		}
	}
	return true
}

func isSmallOrderEncoding(enc []byte) bool {
	for _, s := range smallOrderEncodings {
		if bytes.Equal(enc, s) {
			return true
		}
	}
	return false
}

// verifyEd25519Strict verifies an Ed25519 signature with the akv1 strict
// rules: canonical S < L, canonical A and R, A not of small order, and the
// cofactorless equation (crypto/ed25519).
func verifyEd25519Strict(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if !lessLE(sig[32:], ed25519L) {
		return false
	}
	if !canonicalPointEncoding(pub) || isSmallOrderEncoding(pub) || !canonicalPointEncoding(sig[:32]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
