package akv1

import (
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// ArgonParams are Argon2id parameters: T iterations, M memory in KiB, P lanes.
type ArgonParams struct {
	T int64
	M int64
	P int64
}

// Argon2id defaults and accepted bounds (spec §3.4, §11). Bounds are checked
// before any KDF work so a malicious server can neither downgrade nor exhaust
// the client.
var (
	ArgonDefaults = ArgonParams{T: 3, M: 65536, P: 1}
	ArgonMin      = ArgonParams{T: 2, M: 19456, P: 1}
	ArgonMax      = ArgonParams{T: 10, M: 1048576, P: 16}
)

// SaltBytes is the password wrap salt size.
const SaltBytes = 16

// PasswordWrap is {"v":1,"alg":"argon2id-xc20p","key_epoch","s","t","m","p","n","ct"}.
type PasswordWrap struct {
	KeyEpoch int64
	S        string
	Params   ArgonParams
	N        string
	Ct       string
}

// JSONValue returns the wire object.
func (w PasswordWrap) JSONValue() any {
	return map[string]any{
		"v": int64(1), "alg": "argon2id-xc20p", "key_epoch": w.KeyEpoch, "s": w.S,
		"t": w.Params.T, "m": w.Params.M, "p": w.Params.P, "n": w.N, "ct": w.Ct,
	}
}

// ValidateArgonParams returns CodeBadRequest when params are outside the bounds.
func ValidateArgonParams(p ArgonParams) error {
	return validateArgonValues(p.T, p.M, p.P)
}

func validateArgonValues(t, m, p any) error {
	if _, err := asInt(t, "argon2 t", ArgonMin.T, ArgonMax.T); err != nil {
		return err
	}
	if _, err := asInt(m, "argon2 m", ArgonMin.M, ArgonMax.M); err != nil {
		return err
	}
	_, err := asInt(p, "argon2 p", ArgonMin.P, ArgonMax.P)
	return err
}

// ArgonNeedsUpgrade reports whether params are weaker than ArgonDefaults, in
// which case a client re-wraps with the defaults after a successful unlock.
func ArgonNeedsUpgrade(p ArgonParams) bool {
	return p.T < ArgonDefaults.T || p.M < ArgonDefaults.M || p.P < ArgonDefaults.P
}

// DerivePasswordKEK computes Argon2id v1.3(utf8(NFC(password)), salt, t, m, p, 32).
//
// The password is normalized to Unicode NFC here, exactly like the TypeScript
// reference (String.prototype.normalize("NFC")), so callers pass the raw
// user input. A password that is not valid UTF-8 is CodeBadRequest: it has no
// JavaScript string equivalent, so it could never derive a portable key.
func DerivePasswordKEK(password string, salt []byte, params ArgonParams) ([]byte, error) {
	if password == "" || !utf8.ValidString(password) {
		return nil, badRequest("password must be a non-empty UTF-8 string")
	}
	if len(salt) != SaltBytes {
		return nil, badRequest("salt must be 16 bytes")
	}
	if err := ValidateArgonParams(params); err != nil {
		return nil, err
	}
	return argon2.IDKey([]byte(norm.NFC.String(password)), salt, uint32(params.T), uint32(params.M), uint8(params.P), 32), nil
}

func pwAAD(vaultID string, keyEpoch int64, p ArgonParams) map[string]any {
	return map[string]any{"ctx": "akv1/pw-wrap", "vault_id": vaultID, "key_epoch": keyEpoch, "t": p.T, "m": p.M, "p": p.P}
}

// ParsePasswordWrap validates an untrusted password wrap, including the
// Argon2id bounds, before any KDF work.
func ParsePasswordWrap(v any) (PasswordWrap, error) {
	const what = "password wrap"
	obj, err := asObject(v, what)
	if err != nil {
		return PasswordWrap{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return PasswordWrap{}, err
	}
	if obj["alg"] != "argon2id-xc20p" {
		return PasswordWrap{}, newErr(CodeUnsupportedVersion, "%s: unsupported alg", what)
	}
	if err := exactKeys(obj, []string{"v", "alg", "key_epoch", "s", "t", "m", "p", "n", "ct"}, what); err != nil {
		return PasswordWrap{}, err
	}
	if err := validateArgonValues(obj["t"], obj["m"], obj["p"]); err != nil {
		return PasswordWrap{}, err
	}
	var w PasswordWrap
	w.Params.T, _ = toInt(obj["t"])
	w.Params.M, _ = toInt(obj["m"])
	w.Params.P, _ = toInt(obj["p"])
	if w.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return PasswordWrap{}, err
	}
	if w.S, err = asB64(obj["s"], what+".s", SaltBytes); err != nil {
		return PasswordWrap{}, err
	}
	if w.N, err = asB64(obj["n"], what+".n", NonceBytes); err != nil {
		return PasswordWrap{}, err
	}
	if w.Ct, err = asB64(obj["ct"], what+".ct", wrappedKeyCtBytes); err != nil {
		return PasswordWrap{}, err
	}
	return w, nil
}

// WrapWithPasswordArgs configures WrapWithPassword. A zero Params means
// ArgonDefaults. Salt and Nonce are nil in production (random); tests inject them.
type WrapWithPasswordArgs struct {
	VK       []byte
	VaultID  string
	KeyEpoch int64
	Password string // raw user input; NFC-normalized by DerivePasswordKEK
	Params   ArgonParams
	Salt     []byte
	Nonce    []byte
}

// WrapWithPassword wraps VK[e] under an Argon2id password KEK (argon2id-xc20p).
func WrapWithPassword(args WrapWithPasswordArgs) (PasswordWrap, error) {
	if len(args.VK) != KeyBytes {
		return PasswordWrap{}, badRequest("vault key must be 32 bytes")
	}
	params := args.Params
	if params == (ArgonParams{}) {
		params = ArgonDefaults
	}
	if err := ValidateArgonParams(params); err != nil {
		return PasswordWrap{}, err
	}
	if _, err := asID(args.VaultID, "vault_id"); err != nil {
		return PasswordWrap{}, err
	}
	if _, err := asInt(args.KeyEpoch, "key_epoch", 1, MaxSafeInteger); err != nil {
		return PasswordWrap{}, err
	}
	salt := args.Salt
	if salt == nil {
		salt = randomBytes(SaltBytes)
	}
	nonce := args.Nonce
	if nonce == nil {
		nonce = randomBytes(NonceBytes)
	}
	kek, err := DerivePasswordKEK(args.Password, salt, params)
	if err != nil {
		return PasswordWrap{}, err
	}
	ct, err := XC20PSeal(kek, nonce, args.VK, pwAAD(args.VaultID, args.KeyEpoch, params))
	if err != nil {
		return PasswordWrap{}, err
	}
	return PasswordWrap{KeyEpoch: args.KeyEpoch, S: B64Encode(salt), Params: params, N: B64Encode(nonce), Ct: B64Encode(ct)}, nil
}

// UnwrapWithPassword recovers VK[e]. needsUpgrade reports parameters weaker
// than ArgonDefaults (the client should re-wrap). Wrong password is CodeDecryptFailed.
func UnwrapWithPassword(wrap any, vaultID, password string) (vk []byte, needsUpgrade bool, err error) {
	w, err := ParsePasswordWrap(wrap)
	if err != nil {
		return nil, false, err
	}
	salt, _ := B64Decode(w.S)
	kek, err := DerivePasswordKEK(password, salt, w.Params)
	if err != nil {
		return nil, false, err
	}
	if _, err := asID(vaultID, "vault_id"); err != nil {
		return nil, false, err
	}
	nonce, _ := B64Decode(w.N)
	ct, _ := B64Decode(w.Ct)
	vk, err = XC20POpen(kek, nonce, ct, pwAAD(vaultID, w.KeyEpoch, w.Params))
	if err != nil {
		return nil, false, err
	}
	return vk, ArgonNeedsUpgrade(w.Params), nil
}
