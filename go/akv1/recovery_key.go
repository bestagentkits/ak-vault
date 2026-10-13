package akv1

import (
	"strings"
)

// RecoveryKeyBytes is the size of a recovery key.
const RecoveryKeyBytes = 32

const (
	crockford        = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	recoverySymbols  = (RecoveryKeyBytes*8 + 4) / 5 // 52
	maxDisplayLength = 128
)

// RecoveryWrap is {"v":1,"alg":"rk-xc20p","key_epoch","n","ct"} (spec §3.4).
type RecoveryWrap struct {
	KeyEpoch int64
	N        string
	Ct       string
}

// JSONValue returns the wire object.
func (w RecoveryWrap) JSONValue() any {
	return map[string]any{"v": int64(1), "alg": "rk-xc20p", "key_epoch": w.KeyEpoch, "n": w.N, "ct": w.Ct}
}

// GenerateRecoveryKey returns 32 random bytes.
func GenerateRecoveryKey() []byte { return randomBytes(RecoveryKeyBytes) }

// EncodeRecoveryKey returns the display form: MSB-first Crockford base32,
// uppercase, 52 symbols in 13 groups of 4 joined by "-".
func EncodeRecoveryKey(rk []byte) (string, error) {
	if len(rk) != RecoveryKeyBytes {
		return "", badRequest("recovery key must be 32 bytes")
	}
	symbols := make([]byte, 0, recoverySymbols)
	var acc uint32
	bits := 0
	for _, b := range rk {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			symbols = append(symbols, crockford[(acc>>(bits-5))&31])
			bits -= 5
		}
		acc &= 1<<bits - 1
	}
	if bits > 0 {
		symbols = append(symbols, crockford[(acc<<(5-bits))&31])
	}
	var sb strings.Builder
	for i := 0; i < len(symbols); i += 4 {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.Write(symbols[i:min(i+4, len(symbols))])
	}
	return sb.String(), nil
}

// isASCIIWhitespace matches the JavaScript RegExp `\s` class restricted to
// ASCII (tab, LF, VT, FF, CR, space); non-ASCII input is rejected earlier.
func isASCIIWhitespace(b byte) bool {
	switch b {
	case '\t', '\n', '\v', '\f', '\r', ' ':
		return true
	}
	return false
}

// DecodeRecoveryKey parses a user-entered recovery key. Input MUST be ASCII
// (any other byte is CodeBadRequest, so look-alikes such as U+0131 or
// fullwidth digits never fold into valid symbols). It is ASCII
// case-insensitive, ignores "-" and ASCII whitespace, maps I/L to 1 and O to
// 0, and rejects (CodeBadRequest) any other symbol, a wrong length or
// non-zero padding bits.
func DecodeRecoveryKey(display string) ([]byte, error) {
	if utf16Len(display) > maxDisplayLength {
		return nil, badRequest("recovery key must be a string")
	}
	for i := 0; i < len(display); i++ {
		if display[i] >= 0x80 {
			return nil, badRequest("recovery key must be ASCII")
		}
	}
	values := make([]byte, 0, recoverySymbols)
	for i := 0; i < len(display); i++ {
		c := display[i]
		if c == '-' || isASCIIWhitespace(c) {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		idx := strings.IndexByte(crockford, c)
		if idx < 0 {
			values = append(values, 0xff) // reported after the length check, as in the reference
			continue
		}
		values = append(values, byte(idx))
	}
	if len(values) != recoverySymbols {
		return nil, badRequest("recovery key has the wrong length")
	}
	out := make([]byte, 0, RecoveryKeyBytes)
	var acc uint32
	bits := 0
	for _, v := range values {
		if v == 0xff {
			return nil, badRequest("recovery key contains an invalid symbol")
		}
		acc = (acc<<5 | uint32(v)) & 0xfff
		bits += 5
		if bits >= 8 {
			out = append(out, byte(acc>>(bits-8)))
			bits -= 8
		}
	}
	if acc&(1<<bits-1) != 0 {
		return nil, badRequest("recovery key has non-zero padding bits")
	}
	return out, nil
}

// DeriveRecoveryKEK computes HKDF(ikm=rk, salt=utf8("akv1"), info="akv1/recovery-kek", L=32).
func DeriveRecoveryKEK(rk []byte) ([]byte, error) {
	if len(rk) != RecoveryKeyBytes {
		return nil, badRequest("recovery key must be 32 bytes")
	}
	return hkdf32(rk, []byte("akv1"), []byte("akv1/recovery-kek")), nil
}

func rkAAD(vaultID string, keyEpoch int64) map[string]any {
	return map[string]any{"ctx": "akv1/rk-wrap", "vault_id": vaultID, "key_epoch": keyEpoch}
}

// ParseRecoveryWrap validates an untrusted recovery wrap.
func ParseRecoveryWrap(v any) (RecoveryWrap, error) {
	const what = "recovery wrap"
	obj, err := asObject(v, what)
	if err != nil {
		return RecoveryWrap{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return RecoveryWrap{}, err
	}
	if obj["alg"] != "rk-xc20p" {
		return RecoveryWrap{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "key_epoch", "n", "ct"}, what); err != nil {
		return RecoveryWrap{}, err
	}
	var w RecoveryWrap
	if w.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return RecoveryWrap{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return RecoveryWrap{}, err
	}
	if w.Ct, err = asB64(obj["ct"], what+".ct", wrappedKeyCtBytes); err != nil {
		return RecoveryWrap{}, err
	}
	return w, nil
}

// WrapWithRecoveryKey wraps VK[e] under the recovery KEK (rk-xc20p). nonce is
// nil in production (random).
func WrapWithRecoveryKey(vk []byte, vaultID string, keyEpoch int64, rk []byte, nonce []byte) (RecoveryWrap, error) {
	if len(vk) != KeyBytes {
		return RecoveryWrap{}, badRequest("vault key must be 32 bytes")
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return RecoveryWrap{}, err
	}
	if _, err := asInt(keyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return RecoveryWrap{}, err
	}
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	kek, err := DeriveRecoveryKEK(rk)
	if err != nil {
		return RecoveryWrap{}, err
	}
	ct, err := XC20PSeal(kek, nonce, vk, rkAAD(vaultID, keyEpoch))
	if err != nil {
		return RecoveryWrap{}, err
	}
	return RecoveryWrap{KeyEpoch: keyEpoch, N: B64Encode(nonce), Ct: B64Encode(ct)}, nil
}

// UnwrapWithRecoveryKey recovers VK[e]; a wrong key is CodeDecryptFailed.
func UnwrapWithRecoveryKey(wrap any, vaultID string, rk []byte) ([]byte, error) {
	w, err := ParseRecoveryWrap(wrap)
	if err != nil {
		return nil, err
	}
	kek, err := DeriveRecoveryKEK(rk)
	if err != nil {
		return nil, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return nil, err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	return XC20POpen(kek, nonce, ct, rkAAD(vaultID, w.KeyEpoch))
}
